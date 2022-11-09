// This file is part of Substrate.

// Copyright (C) 2020-2022 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Procedural macroses used in the contracts module.
//!
//! Most likely you should use the [`#[define_env]`][`macro@define_env`] attribute macro which hides
//! boilerplate of defining external environment for a wasm module.

#![no_std]

extern crate alloc;

use alloc::{
	format,
	string::{String, ToString},
	vec::Vec,
};
use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{quote, quote_spanned, ToTokens};
use syn::{parse_macro_input, spanned::Spanned, Data, DeriveInput, FnArg, Ident};

/// This derives `Debug` for a struct where each field must be of some numeric type.
/// It interprets each field as its represents some weight and formats it as times so that
/// it is readable by humans.
#[proc_macro_derive(WeightDebug)]
pub fn derive_weight_debug(input: TokenStream) -> TokenStream {
	derive_debug(input, format_weight)
}

/// This is basically identical to the std libs Debug derive but without adding any
/// bounds to existing generics.
#[proc_macro_derive(ScheduleDebug)]
pub fn derive_schedule_debug(input: TokenStream) -> TokenStream {
	derive_debug(input, format_default)
}

fn derive_debug(input: TokenStream, fmt: impl Fn(&Ident) -> TokenStream2) -> TokenStream {
	let input = parse_macro_input!(input as DeriveInput);
	let name = &input.ident;
	let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
	let data = if let Data::Struct(data) = &input.data {
		data
	} else {
		return quote_spanned! {
			name.span() =>
			compile_error!("WeightDebug is only supported for structs.");
		}
		.into()
	};

	#[cfg(feature = "full")]
	let fields = iterate_fields(data, fmt);

	#[cfg(not(feature = "full"))]
	let fields = {
		drop(fmt);
		drop(data);
		TokenStream2::new()
	};

	let tokens = quote! {
		impl #impl_generics core::fmt::Debug for #name #ty_generics #where_clause {
			fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
				use ::sp_runtime::{FixedPointNumber, FixedU128 as Fixed};
				let mut formatter = formatter.debug_struct(stringify!(#name));
				#fields
				formatter.finish()
			}
		}
	};

	tokens.into()
}

/// This is only used then the `full` feature is activated.
#[cfg(feature = "full")]
fn iterate_fields(data: &syn::DataStruct, fmt: impl Fn(&Ident) -> TokenStream2) -> TokenStream2 {
	use syn::Fields;

	match &data.fields {
		Fields::Named(fields) => {
			let recurse = fields.named.iter().filter_map(|f| {
				let name = f.ident.as_ref()?;
				if name.to_string().starts_with('_') {
					return None
				}
				let value = fmt(name);
				let ret = quote_spanned! { f.span() =>
					formatter.field(stringify!(#name), #value);
				};
				Some(ret)
			});
			quote! {
				#( #recurse )*
			}
		},
		Fields::Unnamed(fields) => quote_spanned! {
			fields.span() =>
			compile_error!("Unnamed fields are not supported")
		},
		Fields::Unit => quote!(),
	}
}

fn format_weight(field: &Ident) -> TokenStream2 {
	quote_spanned! { field.span() =>
		&if self.#field > 1_000_000_000 {
			format!(
				"{:.1?} ms",
				Fixed::saturating_from_rational(self.#field, 1_000_000_000).to_float()
			)
		} else if self.#field > 1_000_000 {
			format!(
				"{:.1?} µs",
				Fixed::saturating_from_rational(self.#field, 1_000_000).to_float()
			)
		} else if self.#field > 1_000 {
			format!(
				"{:.1?} ns",
				Fixed::saturating_from_rational(self.#field, 1_000).to_float()
			)
		} else {
			format!("{} ps", self.#field)
		}
	}
}

fn format_default(field: &Ident) -> TokenStream2 {
	quote_spanned! { field.span() =>
		&self.#field
	}
}

/// Parsed environment definition.
struct EnvDef {
	host_funcs: Vec<HostFn>,
}

/// Parsed host function definition.
struct HostFn {
	item: syn::ItemFn,
	module: String,
	name: String,
	returns: HostFnReturn,
}

enum HostFnReturn {
	Unit,
	U32,
	ReturnCode,
}

impl ToTokens for HostFn {
	fn to_tokens(&self, tokens: &mut TokenStream2) {
		self.item.to_tokens(tokens);
	}
}

impl HostFn {
	pub fn try_from(item: syn::ItemFn) -> syn::Result<Self> {
		let err = |span, msg| {
			let msg = format!("Invalid host function definition. {}", msg);
			syn::Error::new(span, msg)
		};

		// process attributes
		let msg = "only #[version(<u8>)] or #[unstable] attribute is allowed.";
		let span = item.span();
		let mut attrs = item.attrs.clone();
		attrs.retain(|a| !(a.path.is_ident("doc") || a.path.is_ident("prefixed_alias")));
		let name = item.sig.ident.to_string();
		let module = match attrs.len() {
			0 => Ok("seal0".to_string()),
			1 => {
				let attr = &attrs[0];
				let ident = attr.path.get_ident().ok_or(err(span, msg))?.to_string();
				match ident.as_str() {
					"version" => {
						let ver: syn::LitInt = attr.parse_args()?;
						Ok(format!("seal{}", ver.base10_parse::<u8>().map_err(|_| err(span, msg))?))
					},
					"unstable" => Ok("__unstable__".to_string()),
					_ => Err(err(span, msg)),
				}
			},
			_ => Err(err(span, msg)),
		}?;

		// process return type
		let msg = r#"Should return one of the following:
				- Result<(), TrapReason>,
				- Result<ReturnCode, TrapReason>,
				- Result<u32, TrapReason>"#;
		let ret_ty = match item.clone().sig.output {
			syn::ReturnType::Type(_, ty) => Ok(ty.clone()),
			_ => Err(err(span, &msg)),
		}?;
		match *ret_ty {
			syn::Type::Path(tp) => {
				let result = &tp.path.segments.last().ok_or(err(span, &msg))?;
				let (id, span) = (result.ident.to_string(), result.ident.span());
				id.eq(&"Result".to_string()).then_some(()).ok_or(err(span, &msg))?;

				match &result.arguments {
					syn::PathArguments::AngleBracketed(group) => {
						if group.args.len() != 2 {
							return Err(err(span, &msg))
						};

						let arg2 = group.args.last().ok_or(err(span, &msg))?;

						let err_ty = match arg2 {
							syn::GenericArgument::Type(ty) => Ok(ty.clone()),
							_ => Err(err(arg2.span(), &msg)),
						}?;

						match err_ty {
							syn::Type::Path(tp) => Ok(tp
								.path
								.segments
								.first()
								.ok_or(err(arg2.span(), &msg))?
								.ident
								.to_string()),
							_ => Err(err(tp.span(), &msg)),
						}?
						.eq("TrapReason")
						.then_some(())
						.ok_or(err(span, &msg))?;

						let arg1 = group.args.first().ok_or(err(span, &msg))?;
						let ok_ty = match arg1 {
							syn::GenericArgument::Type(ty) => Ok(ty.clone()),
							_ => Err(err(arg1.span(), &msg)),
						}?;
						let ok_ty_str = match ok_ty {
							syn::Type::Path(tp) => Ok(tp
								.path
								.segments
								.first()
								.ok_or(err(arg1.span(), &msg))?
								.ident
								.to_string()),
							syn::Type::Tuple(tt) => {
								if !tt.elems.is_empty() {
									return Err(err(arg1.span(), &msg))
								};
								Ok("()".to_string())
							},
							_ => Err(err(ok_ty.span(), &msg)),
						}?;
						let returns = match ok_ty_str.as_str() {
							"()" => Ok(HostFnReturn::Unit),
							"u32" => Ok(HostFnReturn::U32),
							"ReturnCode" => Ok(HostFnReturn::ReturnCode),
							_ => Err(err(arg1.span(), &msg)),
						}?;

						Ok(Self { item, module, name, returns })
					},
					_ => Err(err(span, &msg)),
				}
			},
			_ => Err(err(span, &msg)),
		}
	}
}

impl EnvDef {
	pub fn try_from(item: syn::ItemMod) -> syn::Result<Self> {
		let span = item.span();
		let err = |msg| syn::Error::new(span, msg);
		let items = &item
			.content
			.as_ref()
			.ok_or(err("Invalid environment definition, expected `mod` to be inlined."))?
			.1;

		let extract_fn = |i: &syn::Item| match i {
			syn::Item::Fn(i_fn) => Some(i_fn.clone()),
			_ => None,
		};

		let host_funcs = items
			.iter()
			.filter_map(extract_fn)
			.map(|i| HostFn::try_from(i))
			.collect::<Result<Vec<_>, _>>()?;

		Ok(Self { host_funcs })
	}
}

/// Expands environment definiton.
/// Should generate source code for:
///  - wasm import satisfy checks (see `expand_can_satisfy()`);
///  - implementations of the host functions to be added to the wasm runtime environment (see
///    `expand_impls()`).
fn expand_env(def: &mut EnvDef) -> TokenStream2 {
	let impls = expand_functions(def);

	quote! {
		pub extern "C" fn dispatch_thunk<E>(state_object: *mut StateObject, r1: u64, r2: u64, r3: u64, _r4: u64, _r5: u64) -> u64
		where
			E: Ext,
			<E::T as frame_system::Config>::AccountId: UncheckedFrom<<E::T as frame_system::Config>::Hash> + AsRef<[u8]>
		{
			let (ctx, __gas_left__) = unsafe {
				(
					&mut *((*state_object).runtime_ptr as *mut Runtime<E>),
					&mut (*state_object).gas_left,
				)
			};
			ctx.ext.gas_meter().set_ref_time(*__gas_left__);
			let result: Result<(), ()> = match r1 {
				#impls
				_ => {
					ctx.set_trap_reason(crate::Error::<E::T>::UnknownSyscall.into());
					Err(())
				},
			};
			*__gas_left__ = ctx.ext.gas_meter().gas_left().ref_time();
			result.map(|_| 0).unwrap_or(1)
		}
	}
}

fn expand_functions(def: &mut EnvDef) -> TokenStream2 {
	let impls = def.host_funcs.iter().enumerate().map(|(idx, f)| {
		// skip the context arg
		let params = f.item.sig.inputs.iter().skip(1);
		let param_names = params.clone().filter_map(|arg| {
			let FnArg::Typed(arg) = arg else {
				return None;
			};
			Some(&arg.pat)
		});
		let param_types = params.clone().filter_map(|arg| {
			let FnArg::Typed(arg) = arg else {
				return None;
			};
			Some(&arg.ty)
		});
		let idx = idx as u64;
		let (module, name, body, output) = (&f.module, &f.name, &f.item.block, &f.item.sig.output);
		let unstable_feat = match module.as_str() {
			"__unstable__" => quote! { #[cfg(feature = "unstable-interface")] },
			_ => quote! {},
		};

		let map_output = match &f.returns {
			HostFnReturn::Unit => quote! { |_| Ok(()) },
			HostFnReturn::U32 | HostFnReturn::ReturnCode => quote! {
				|val| {
					let val: u32 = (val as u32).into();
					ctx.write_sandbox_memory(r3, &val.to_le_bytes())?;
					Ok(())
				}
			},
		};

		quote! {
			#unstable_feat
			#idx => {
				let _module = #module;
				let _name = #name;
				let mut func = || #output {
					let (#( #param_names, )*): (#( #param_types, )*) = ctx.read_sandbox_memory_as(r2)?;
					#body
				};
				func()
					.and_then(#map_output)
					.map_err(|trap_reason| ctx.set_trap_reason(trap_reason))
			}
		}
	});
	quote! {
		#( #impls )*
	}
}

/// Defines a host functions set that can be imported by contract wasm code.
///
/// **NB**: Be advised that all functions defined by this macro
/// will panic if called with unexpected arguments.
///
/// It's up to you as the user of this macro to check signatures of wasm code to be executed
/// and reject the code if any imported function has a mismatched signature.
///
/// ## Example
///
/// ```nocompile
/// #[define_env]
/// pub mod some_env {
/// 	fn some_host_fn(ctx: _, memory: _, key_ptr: u32, value_ptr: u32, value_len: u32) -> Result<(), TrapReason> {
/// 		ctx.some_host_fn(KeyType::Fix, key_ptr, value_ptr, value_len).map(|_| ())
/// 	}
/// }
/// ```
/// This example will expand to the `some_host_fn()` defined in the wasm module named `seal0`.
/// To define a host function in `seal1` and `__unstable__` modules, it should be annotated with the
/// appropriate attribute as follows:
///
/// ## Example
///
/// ```nocompile
/// #[define_env]
/// pub mod some_env {
/// 	#[version(1)]
/// 	fn some_host_fn(ctx: _, memory: _, key_ptr: u32, value_ptr: u32, value_len: u32) -> Result<ReturnCode, TrapReason> {
/// 		ctx.some_host_fn(KeyType::Fix, key_ptr, value_ptr, value_len).map(|_| ())
/// 	}
///
/// 	#[unstable]
/// 	fn some_host_fn(ctx: _, memory: _, key_ptr: u32, value_ptr: u32, value_len: u32) -> Result<u32, TrapReason> {
/// 		ctx.some_host_fn(KeyType::Fix, key_ptr, value_ptr, value_len).map(|_| ())
/// 	}
/// }
/// ```
///
/// In legacy versions of pallet_contracts, it was a naming convention that all host functions had
/// to be named with the `seal_` prefix. For the sake of backwards compatibility, each host function
/// now can get a such prefix-named alias function generated by marking it by the
/// `#[prefixed_alias]` attribute:
///
/// ## Example
///
/// ```nocompile
/// #[define_env]
/// pub mod some_env {
/// 	#[version(1)]
/// 	#[prefixed_alias]
/// 	fn some_host_fn(ctx: _, memory: _, key_ptr: u32, value_ptr: u32, value_len: u32) -> Result<ReturnCode, TrapReason> {
/// 		ctx.some_host_fn(KeyType::Fix, key_ptr, value_ptr, value_len).map(|_| ())
/// 	}
///
/// 	#[unstable]
/// 	fn some_host_fn(ctx: _, memory: _, key_ptr: u32, value_ptr: u32, value_len: u32) -> Result<u32, TrapReason> {
/// 		ctx.some_host_fn(KeyType::Fix, key_ptr, value_ptr, value_len).map(|_| ())
/// 	}
/// }
/// ```
///
/// In this example, the following host functions will be generated by the macro:
/// - `some_host_fn()` in module `seal1`,
/// - `seal_some_host_fn()` in module `seal1`,
/// - `some_host_fn()` in module `__unstable__`.
///
/// Only following return types are allowed for the host functions defined with the macro:
/// - `Result<(), TrapReason>`,
/// - `Result<ReturnCode, TrapReason>`,
/// - `Result<u32, TrapReason>`.
///
/// The macro expands to `pub struct Env` declaration, with the following traits implementations:
/// - `pallet_contracts::wasm::Environment<Runtime<E>> where E: Ext`
/// - `pallet_contracts::wasm::Environment<()>`
///
/// The implementation on `()` can be used in places where no `Ext` exists, yet. This is useful
/// when only checking whether a code can be instantiated without actually executing any code.
#[proc_macro_attribute]
pub fn define_env(attr: TokenStream, item: TokenStream) -> TokenStream {
	if !attr.is_empty() {
		let msg = "Invalid `define_env` attribute macro: expected no attributes: `#[define_env]`.";
		let span = TokenStream2::from(attr).span();
		return syn::Error::new(span, msg).to_compile_error().into()
	}

	let item = syn::parse_macro_input!(item as syn::ItemMod);

	match EnvDef::try_from(item) {
		Ok(mut def) => expand_env(&mut def).into(),
		Err(e) => e.to_compile_error().into(),
	}
}
