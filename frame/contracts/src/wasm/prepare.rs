// This file is part of Substrate.

// Copyright (C) 2018-2022 Parity Technologies (UK) Ltd.
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

//! This module takes care of loading, checking and preprocessing of a
//! wasm module before execution. It also extracts some essential information
//! from a module.

use crate::{
	storage::meter::Diff,
	wasm::{Determinism, OwnerInfo, PrefabWasmModule},
	AccountIdOf, CodeVec, Config, Error, Schedule,
};
use codec::{Encode, MaxEncodedLen};
use sp_runtime::{traits::Hash, DispatchError};
use sp_std::prelude::*;

fn do_preparation<T: Config>(
	original_code: CodeVec<T>,
	schedule: &Schedule<T>,
	owner: AccountIdOf<T>,
	determinism: Determinism,
) -> Result<PrefabWasmModule<T>, (DispatchError, &'static str)> {
	let original_code_len = original_code.len();

	let mut module = PrefabWasmModule {
		instruction_weights_version: schedule.instruction_weights.version,
		initial: 0,
		maximum: 0,
		code: original_code
			.clone()
			.into_inner()
			.try_into()
			.map_err(|_| (<Error<T>>::CodeTooLarge.into(), ""))?,
		determinism,
		code_hash: T::Hashing::hash(&original_code),
		original_code: Some(original_code),
		owner_info: None,
	};

	// We need to add the sizes of the `#[codec(skip)]` fields which are stored in different
	// storage items. This is also why we have `3` items added and not only one.
	let bytes_added = module
		.encoded_size()
		.saturating_add(original_code_len)
		.saturating_add(<OwnerInfo<T>>::max_encoded_len()) as u32;
	let deposit = Diff { bytes_added, items_added: 3, ..Default::default() }
		.update_contract::<T>(None)
		.charge_or_zero();

	module.owner_info = Some(OwnerInfo { owner, deposit, refcount: 0 });

	Ok(module)
}

/// Loads the given module given in `original_code`, performs some checks on it and
/// does some preprocessing.
///
/// The checks are:
///
/// - provided code is a valid wasm module.
/// - the module doesn't define an internal memory instance,
/// - imported memory (if any) doesn't reserve more memory than permitted by the `schedule`,
/// - all imported functions from the external environment matches defined by `env` module,
///
/// The preprocessing includes injecting code for gas metering and metering the height of stack.
pub fn prepare_contract<T: Config>(
	original_code: CodeVec<T>,
	schedule: &Schedule<T>,
	owner: AccountIdOf<T>,
	determinism: Determinism,
) -> Result<PrefabWasmModule<T>, (DispatchError, &'static str)> {
	do_preparation::<T>(original_code, schedule, owner, determinism)
}

/// The same as [`prepare_contract`] but without constructing a new [`PrefabWasmModule`]
///
/// # Note
///
/// Use this when an existing contract should be re-instrumented with a newer schedule version.
pub fn reinstrument_contract<T: Config>(
	original_code: &[u8],
	_schedule: &Schedule<T>,
	_determinism: Determinism,
) -> Result<Vec<u8>, &'static str> {
	Ok(original_code.to_vec())
}

/// Alternate (possibly unsafe) preparation functions used only for benchmarking.
///
/// For benchmarking we need to construct special contracts that might not pass our
/// sanity checks or need to skip instrumentation for correct results. We hide functions
/// allowing this behind a feature that is only set during benchmarking to prevent usage
/// in production code.
#[cfg(feature = "runtime-benchmarks")]
pub mod benchmarking {
	use super::{elements::FunctionType, *};

	impl ImportSatisfyCheck for () {
		fn can_satisfy(_module: &[u8], _name: &[u8], _func_type: &FunctionType) -> bool {
			true
		}
	}

	/// Prepare function that neither checks nor instruments the passed in code.
	pub fn prepare_contract<T: Config>(
		original_code: Vec<u8>,
		schedule: &Schedule<T>,
		owner: AccountIdOf<T>,
	) -> Result<PrefabWasmModule<T>, &'static str> {
		let contract_module = ContractModule::new(&original_code, schedule)?;
		let memory_limits = get_memory_limits(contract_module.scan_imports::<()>(&[])?, schedule)?;
		Ok(PrefabWasmModule {
			instruction_weights_version: schedule.instruction_weights.version,
			initial: memory_limits.0,
			maximum: memory_limits.1,
			code_hash: T::Hashing::hash(&original_code),
			original_code: Some(original_code.try_into().map_err(|_| "Original code too large")?),
			determinism: Determinism::Deterministic,
			code: contract_module
				.into_wasm_code()?
				.try_into()
				.map_err(|_| "Instrumented code too large")?,
			owner_info: Some(OwnerInfo {
				owner,
				// this is a helper function for benchmarking which skips deposit collection
				deposit: Default::default(),
				refcount: 0,
			}),
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		exec::Ext,
		schedule::Limits,
		tests::{Test, ALICE},
	};
	use pallet_contracts_proc_macro::define_env;
	use std::fmt;

	impl fmt::Debug for PrefabWasmModule<Test> {
		fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
			write!(f, "PreparedContract {{ .. }}")
		}
	}

	/// Using unreachable statements triggers unreachable warnings in the generated code
	#[allow(unreachable_code)]
	mod env {
		use super::*;

		// Define test environment for tests. We need ImportSatisfyCheck
		// implementation from it. So actual implementations doesn't matter.
		#[define_env]
		pub mod test_env {
			fn panic(_ctx: crate::wasm::Runtime<E>) -> Result<(), TrapReason> {
				Ok(())
			}

			// gas is an implementation defined function and a contract can't import it.
			fn gas(_ctx: crate::wasm::Runtime<E>, _amount: u32) -> Result<(), TrapReason> {
				Ok(())
			}

			fn nop(_ctx: crate::wasm::Runtime<E>, _unused: u64) -> Result<(), TrapReason> {
				Ok(())
			}

			// new version of nop with other data type for argumebt
			#[version(1)]
			fn nop(_ctx: crate::wasm::Runtime<E>, _unused: i32) -> Result<(), TrapReason> {
				Ok(())
			}
		}
	}

	macro_rules! prepare_test {
		($name:ident, $wat:expr, $($expected:tt)*) => {
			#[test]
			fn $name() {
				let wasm = wat::parse_str($wat).unwrap().try_into().unwrap();
				let schedule = Schedule {
					limits: Limits {
						globals: 3,
						parameters: 3,
						memory_pages: 16,
						table_size: 3,
						br_table_size: 3,
						.. Default::default()
					},
					.. Default::default()
				};
				let r = do_preparation::<Test>(wasm, &schedule, ALICE, Determinism::Deterministic);
				assert_matches::assert_matches!(r.map_err(|(_, msg)| msg), $($expected)*);
			}
		};
	}

	prepare_test!(
		no_floats,
		r#"
		(module
			(func (export "call")
				(drop
					(f32.add
						(f32.const 0)
						(f32.const 1)
					)
				)
			)
			(func (export "deploy"))
		)"#,
		Err("gas instrumentation failed")
	);

	mod functions {
		use super::*;

		prepare_test!(
			param_number_valid,
			r#"
			(module
				(func (export "call"))
				(func (export "deploy"))
				(func (param i32 i32 i32))
			)
			"#,
			Ok(_)
		);

		prepare_test!(
			param_number_invalid,
			r#"
			(module
				(func (export "call"))
				(func (export "deploy"))
				(func (param i32 i32 i32 i32))
				(func (param i32))
			)
			"#,
			Err("Use of a function type with too many parameters.")
		);
	}

	mod globals {
		use super::*;

		prepare_test!(
			global_number_valid,
			r#"
			(module
				(global i64 (i64.const 0))
				(global i64 (i64.const 0))
				(global i64 (i64.const 0))
				(func (export "call"))
				(func (export "deploy"))
			)
			"#,
			Ok(_)
		);

		prepare_test!(
			global_number_too_high,
			r#"
			(module
				(global i64 (i64.const 0))
				(global i64 (i64.const 0))
				(global i64 (i64.const 0))
				(global i64 (i64.const 0))
				(func (export "call"))
				(func (export "deploy"))
			)
			"#,
			Err("module declares too many globals")
		);
	}

	mod memories {
		use super::*;

		prepare_test!(
			memory_with_one_page,
			r#"
			(module
				(import "env" "memory" (memory 1 1))

				(func (export "call"))
				(func (export "deploy"))
			)
			"#,
			Ok(_)
		);

		prepare_test!(
			internal_memory_declaration,
			r#"
			(module
				(memory 1 1)

				(func (export "call"))
				(func (export "deploy"))
			)
			"#,
			Err("module declares internal memory")
		);

		prepare_test!(
			no_memory_import,
			r#"
			(module
				;; no memory imported

				(func (export "call"))
				(func (export "deploy"))
			)"#,
			Ok(_)
		);

		prepare_test!(
			initial_exceeds_maximum,
			r#"
			(module
				(import "env" "memory" (memory 16 1))

				(func (export "call"))
				(func (export "deploy"))
			)
			"#,
			Err("Module is not valid")
		);

		prepare_test!(
			no_maximum,
			r#"
			(module
				(import "env" "memory" (memory 1))

				(func (export "call"))
				(func (export "deploy"))
			)
			"#,
			Err("Maximum number of pages should be always declared.")
		);

		prepare_test!(
			requested_maximum_valid,
			r#"
			(module
				(import "env" "memory" (memory 1 16))

				(func (export "call"))
				(func (export "deploy"))
			)
			"#,
			Ok(_)
		);

		prepare_test!(
			requested_maximum_exceeds_configured_maximum,
			r#"
			(module
				(import "env" "memory" (memory 1 17))

				(func (export "call"))
				(func (export "deploy"))
			)
			"#,
			Err("Maximum number of pages should not exceed the configured maximum.")
		);

		prepare_test!(
			field_name_not_memory,
			r#"
			(module
				(import "env" "forgetit" (memory 1 1))

				(func (export "call"))
				(func (export "deploy"))
			)
			"#,
			Err("Memory import must have the field name 'memory'")
		);

		prepare_test!(
			multiple_memory_imports,
			r#"
			(module
				(import "env" "memory" (memory 1 1))
				(import "env" "memory" (memory 1 1))

				(func (export "call"))
				(func (export "deploy"))
			)
			"#,
			Err("Module is not valid")
		);

		prepare_test!(
			table_import,
			r#"
			(module
				(import "seal0" "table" (table 1 anyfunc))

				(func (export "call"))
				(func (export "deploy"))
			)
			"#,
			Err("Cannot import tables")
		);

		prepare_test!(
			global_import,
			r#"
			(module
				(global $g (import "seal0" "global") i32)
				(func (export "call"))
				(func (export "deploy"))
			)
			"#,
			Err("Cannot import globals")
		);
	}

	mod tables {
		use super::*;

		prepare_test!(
			no_tables,
			r#"
			(module
				(func (export "call"))
				(func (export "deploy"))
			)
			"#,
			Ok(_)
		);

		prepare_test!(
			table_valid_size,
			r#"
			(module
				(table 3 funcref)

				(func (export "call"))
				(func (export "deploy"))
			)
			"#,
			Ok(_)
		);

		prepare_test!(
			table_too_big,
			r#"
			(module
				(table 4 funcref)

				(func (export "call"))
				(func (export "deploy"))
			)"#,
			Err("table exceeds maximum size allowed")
		);

		prepare_test!(
			br_table_valid_size,
			r#"
			(module
				(func (export "call"))
				(func (export "deploy"))
				(func
					i32.const 0
					br_table 0 0 0 0
				)
			)
			"#,
			Ok(_)
		);

		prepare_test!(
			br_table_too_big,
			r#"
			(module
				(func (export "call"))
				(func (export "deploy"))
				(func
					i32.const 0
					br_table 0 0 0 0 0
				)
			)"#,
			Err("BrTable's immediate value is too big.")
		);
	}

	mod imports {
		use super::*;

		prepare_test!(
			can_import_legit_function,
			r#"
			(module
				(import "seal0" "nop" (func (param i64)))

				(func (export "call"))
				(func (export "deploy"))
			)
			"#,
			Ok(_)
		);

		// even though gas is defined the contract can't import it since
		// it is an implementation defined.
		prepare_test!(
			can_not_import_gas_function,
			r#"
			(module
				(import "seal0" "gas" (func (param i32)))

				(func (export "call"))
				(func (export "deploy"))
			)
			"#,
			Err("module imports a non-existent function")
		);

		// memory is in "env" and not in "seal0"
		prepare_test!(
			memory_not_in_seal0,
			r#"
			(module
				(import "seal0" "memory" (memory 1 1))

				(func (export "call"))
				(func (export "deploy"))
			)
			"#,
			Err("Invalid module for imported memory")
		);

		// memory is in "env" and not in some arbitrary module
		prepare_test!(
			memory_not_in_arbitrary_module,
			r#"
			(module
				(import "any_module" "memory" (memory 1 1))

				(func (export "call"))
				(func (export "deploy"))
			)
			"#,
			Err("Invalid module for imported memory")
		);

		prepare_test!(
			function_in_other_module_works,
			r#"
			(module
				(import "seal1" "nop" (func (param i32)))

				(func (export "call"))
				(func (export "deploy"))
			)
			"#,
			Ok(_)
		);

		// wrong signature
		prepare_test!(
			wrong_signature,
			r#"
			(module
				(import "seal0" "gas" (func (param i64)))

				(func (export "call"))
				(func (export "deploy"))
			)
			"#,
			Err("module imports a non-existent function")
		);

		prepare_test!(
			unknown_func_name,
			r#"
			(module
				(import "seal0" "unknown_func" (func))

				(func (export "call"))
				(func (export "deploy"))
			)
			"#,
			Err("module imports a non-existent function")
		);
	}

	mod entrypoints {
		use super::*;

		prepare_test!(
			it_works,
			r#"
			(module
				(func (export "call"))
				(func (export "deploy"))
			)
			"#,
			Ok(_)
		);

		prepare_test!(
			omit_deploy,
			r#"
			(module
				(func (export "call"))
			)
			"#,
			Err("deploy function isn't exported")
		);

		prepare_test!(
			omit_call,
			r#"
			(module
				(func (export "deploy"))
			)
			"#,
			Err("call function isn't exported")
		);

		// Try to use imported function as an entry point.
		prepare_test!(
			try_sneak_export_as_entrypoint,
			r#"
			(module
				(import "seal0" "panic" (func))

				(func (export "deploy"))

				(export "call" (func 0))
			)
			"#,
			Err("entry point points to an imported function")
		);

		// Try to use imported function as an entry point.
		prepare_test!(
			try_sneak_export_as_global,
			r#"
			(module
				(func (export "deploy"))
				(global (export "call") i32 (i32.const 0))
			)
			"#,
			Err("expected a function")
		);

		prepare_test!(
			wrong_signature,
			r#"
			(module
				(func (export "deploy"))
				(func (export "call") (param i32))
			)
			"#,
			Err("entry point has wrong signature")
		);

		prepare_test!(
			unknown_exports,
			r#"
			(module
				(func (export "call"))
				(func (export "deploy"))
				(func (export "whatevs"))
			)
			"#,
			Err("unknown export: expecting only deploy and call functions")
		);

		prepare_test!(
			global_float,
			r#"
			(module
				(global $x f32 (f32.const 0))
				(func (export "call"))
				(func (export "deploy"))
			)
			"#,
			Err("use of floating point type in globals is forbidden")
		);

		prepare_test!(
			local_float,
			r#"
			(module
				(func $foo (local f32))
				(func (export "call"))
				(func (export "deploy"))
			)
			"#,
			Err("use of floating point type in locals is forbidden")
		);

		prepare_test!(
			param_float,
			r#"
			(module
				(func $foo (param f32))
				(func (export "call"))
				(func (export "deploy"))
			)
			"#,
			Err("use of floating point type in function types is forbidden")
		);

		prepare_test!(
			result_float,
			r#"
			(module
				(func $foo (result f32) (f32.const 0))
				(func (export "call"))
				(func (export "deploy"))
			)
			"#,
			Err("use of floating point type in function types is forbidden")
		);
	}
}
