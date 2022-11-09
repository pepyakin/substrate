use solana_rbpf::{
	error::EbpfError,
	memory_region::MemoryMapping,
	vm::{InstructionMeter, SyscallRegistry},
};

use super::{MemoryRef, ProcessData};

#[derive(thiserror::Error, Debug)]
#[error("abort")]
pub struct AbortError;

#[derive(thiserror::Error, Debug)]
#[error("panic")]
pub struct PanicError {
	file: u64,
	len: u64,
	line: u64,
	column: u64,
}

#[derive(thiserror::Error, Debug)]
#[error("custom panic")]
pub struct CustomPanic;

#[derive(thiserror::Error, Debug)]
#[error("supervisor returned non-zero error code")]
pub struct SupervisorError;

#[derive(thiserror::Error, Debug)]
#[error("supervisor trapped")]
pub struct SupervisorTrapped;

macro_rules! register_syscall {
	($registry:ident, $name:expr, $handler:ident) => {{
		fn handle(
			process_data: &mut ProcessData,
			arg1: u64,
			arg2: u64,
			arg3: u64,
			arg4: u64,
			arg5: u64,
			memory_mapping: &mut MemoryMapping,
			result: &mut solana_rbpf::vm::ProgramResult,
		) {
			let f: fn(
				&mut ProcessData,
				u64,
				u64,
				u64,
				u64,
				u64,
				&mut MemoryMapping,
			) -> Result<u64, EbpfError> = $handler;
			match f(process_data, arg1, arg2, arg3, arg4, arg5, memory_mapping) {
				Ok(r0) => *result = solana_rbpf::vm::ProgramResult::Ok(r0),
				Err(err) => *result = solana_rbpf::vm::ProgramResult::Err(err),
			}
		}
		$registry
			.register_syscall_by_name($name, handle)
			.expect("duplicate syscall handler");
	}};
}

fn abort_syscall(
	_process_data: &mut ProcessData,
	_arg1: u64,
	_arg2: u64,
	_arg3: u64,
	_arg4: u64,
	_arg5: u64,
	_memory_mapping: &mut MemoryMapping,
) -> Result<u64, EbpfError> {
	Err(EbpfError::UserError(Box::new(AbortError)))
}

fn ext_syscall(
	process_data: &mut ProcessData,
	arg1: u64,
	arg2: u64,
	arg3: u64,
	arg4: u64,
	arg5: u64,
	memory_mapping: &mut MemoryMapping,
) -> Result<u64, EbpfError> {
	let mut gas_left = process_data.meter.get_remaining();
	let err_code = process_data.context.supervisor_call(
		arg1,
		arg2,
		arg3,
		arg4,
		arg5,
		&mut gas_left,
		MemoryRef { mapping: memory_mapping },
	);
	process_data.meter.set_gas_left(gas_left);

	match err_code {
		Ok(0) => Ok(0),
		Ok(_) => Err(EbpfError::UserError(Box::new(SupervisorError))),
		Err(_) => Err(EbpfError::UserError(Box::new(SupervisorTrapped))),
	}
}

// pub fn sol_memcpy_(dest: *mut u8, src: *const u8, n: u64);
fn sol_memcpy_(
	_process_data: &mut ProcessData,
	dest: u64,
	src: u64,
	n: u64,
	_arg4: u64,
	_arg5: u64,
	memory_mapping: &mut MemoryMapping,
) -> Result<u64, EbpfError> {
	let mut buf = vec![0u8; n as usize];
	let mut memory_ref = MemoryRef { mapping: memory_mapping };
	memory_ref.read(src, &mut buf)?;
	memory_ref.write(dest, &buf)?;
	Ok(0)
}

// pub fn sol_memmove_(dest: *mut u8, src: *const u8, n: u64);
fn sol_memmove_(
	_process_data: &mut ProcessData,
	dest: u64,
	src: u64,
	n: u64,
	_arg4: u64,
	_arg5: u64,
	memory_mapping: &mut MemoryMapping,
) -> Result<u64, EbpfError> {
	let mut buf = vec![0u8; n as usize];
	let mut memory_ref = MemoryRef { mapping: memory_mapping };
	memory_ref.read(src, &mut buf)?;
	memory_ref.write(dest, &buf)?;
	Ok(0)
}

// pub fn sol_memset_(s: *mut u8, c: u8, n: u64);
fn sol_memset_(
	_process_data: &mut ProcessData,
	s: u64,
	c: u64,
	n: u64,
	_arg4: u64,
	_arg5: u64,
	memory_mapping: &mut MemoryMapping,
) -> Result<u64, EbpfError> {
	let buf = vec![c as u8; n as usize];
	let mut memory_ref = MemoryRef { mapping: memory_mapping };
	memory_ref.write(s, &buf)?;
	Ok(0)
}

// pub fn sol_memcmp_(s1: *const u8, s2: *const u8, n: u64, result: *mut i32);
fn sol_memcmp_(
	_process_data: &mut ProcessData,
	s1: u64,
	s2: u64,
	n: u64,
	result_ptr: u64,
	_arg5: u64,
	memory_mapping: &mut MemoryMapping,
) -> Result<u64, EbpfError> {
	use std::cmp::Ordering;
	let mut buf1 = vec![0u8; n as usize];
	let mut buf2 = vec![0u8; n as usize];
	let mut memory_ref = MemoryRef { mapping: memory_mapping };
	memory_ref.read(s1, &mut buf1)?;
	memory_ref.read(s2, &mut buf2)?;
	match buf1.cmp(&buf2) {
		Ordering::Less => memory_ref.write(result_ptr, &(-1i32).to_le_bytes())?,
		Ordering::Equal => memory_ref.write(result_ptr, &(0i32).to_le_bytes())?,
		Ordering::Greater => memory_ref.write(result_ptr, &(1i32).to_le_bytes())?,
	};
	Ok(0)
}

fn sol_alloc_free_syscall(
	process_data: &mut ProcessData,
	size: u64,
	free_addr: u64,
	_arg3: u64,
	_arg4: u64,
	_arg5: u64,
	_memory_mapping: &mut MemoryMapping,
) -> Result<u64, EbpfError> {
	if free_addr == 0 {
		let addr = process_data.bumper_next;
		process_data.bumper_next += size;
		Ok(addr as u64)
	} else {
		// do nothing
		Ok(0)
	}
}

fn sol_panic_syscall(
	_process_data: &mut ProcessData,
	file: u64,
	len: u64,
	line: u64,
	column: u64,
	_arg5: u64,
	_memory_mapping: &mut MemoryMapping,
) -> Result<u64, EbpfError> {
	let err =
		solana_rbpf::error::EbpfError::UserError(Box::new(PanicError { file, len, line, column }));
	Err(err)
}

fn sol_log_syscall(
	_process_data: &mut ProcessData,
	data: u64,
	len: u64,
	_arg3: u64,
	_arg4: u64,
	_arg5: u64,
	memory_mapping: &mut MemoryMapping,
) -> Result<u64, EbpfError> {
	let mut buf = vec![0u8; len as usize];
	let memory_ref = MemoryRef { mapping: memory_mapping };
	memory_ref.read(data, &mut buf)?;
	println!("{}", String::from_utf8(buf).unwrap());
	Ok(0)
}

fn custom_panic_syscall(
	_process_data: &mut ProcessData,
	_arg1: u64,
	_arg2: u64,
	_arg3: u64,
	_arg4: u64,
	_arg5: u64,
	_memory_mapping: &mut MemoryMapping,
) -> Result<u64, EbpfError> {
	let err = solana_rbpf::error::EbpfError::UserError(Box::new(CustomPanic));
	Err(err)
}

/// Registers the syscalls that are available to the program.
pub fn register(syscall_registry: &mut SyscallRegistry) {
	// LLVM emits calls as for unreachable
	register_syscall!(syscall_registry, b"abort", abort_syscall);

	// Main interface to the supervisor.
	register_syscall!(syscall_registry, b"ext_syscall", ext_syscall);

	// memcpy and friends
	register_syscall!(syscall_registry, b"sol_memcpy_", sol_memcpy_);
	register_syscall!(syscall_registry, b"sol_memmove_", sol_memmove_);
	register_syscall!(syscall_registry, b"sol_memset_", sol_memset_);
	register_syscall!(syscall_registry, b"sol_memcmp_", sol_memcmp_);

	// allocation
	register_syscall!(syscall_registry, b"sol_alloc_free_", sol_alloc_free_syscall);

	// panics and logs
	register_syscall!(syscall_registry, b"sol_panic_", sol_panic_syscall);
	register_syscall!(syscall_registry, b"sol_log_", sol_log_syscall);
	register_syscall!(syscall_registry, b"custom_panic", custom_panic_syscall);
}
