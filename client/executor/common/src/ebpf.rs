// This file is part of Substrate.

// Copyright (C) 2019-2022 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use solana_rbpf::{
	aligned_memory::AlignedMemory,
	ebpf::{self, HOST_ALIGN},
	elf::Executable,
	error::EbpfError,
	memory_region::{AccessType, MemoryMapping, MemoryRegion},
	verifier::RequisiteVerifier,
	vm::{Config, EbpfVm, InstructionMeter, StableResult, SyscallRegistry, VerifiedExecutable},
};

mod meter;
mod syscall;

use meter::MeterRef;

/// An error that can happen during [`execute`].
pub enum ExecError {
	/// The eBPF program has run out of gas (OOG).
	OutOfGas,
	/// The eBPF program has trapped during the execution.
	///
	/// There are numerous ways to trap, e.g. access violation, division by zero. Calling a syscall
	/// such as `abort`, `custom_panic`, etc will also cause a trap.
	///
	/// Be careful though since this error is a catch all it might actually be not a trap.
	Trap,
	/// The eBPF ELF image is invalid in some way.
	InvalidImage,
}

const HEAP_SIZE: usize = 16 * 65536;

pub struct MemoryRef<'a, 'b> {
	mapping: &'a mut MemoryMapping<'b>,
}

impl<'a, 'b> MemoryRef<'a, 'b> {
	pub fn erase(self) -> *mut () {
		self.mapping as *mut _ as *mut ()
	}

	pub unsafe fn recover(ptr: *mut ()) -> Self {
		MemoryRef { mapping: std::mem::transmute(ptr) }
	}

	/// Reads the memory at the given address into the given buffer.
	///
	/// Returns `false` is the memory is not accessible.
	pub fn read(&self, offset: u64, buf: &mut [u8]) -> Result<(), EbpfError> {
		let host_addr = Result::from(self.mapping.map(AccessType::Load, offset, buf.len() as u64))?;
		buf.copy_from_slice(unsafe {
			std::slice::from_raw_parts(host_addr as usize as *mut u8, buf.len())
		});
		Ok(())
	}

	/// Writes the given buffer to the memory at the given offset.
	///
	/// Returns `false` if the write would go out of bounds.
	pub fn write(&mut self, offset: u64, buf: &[u8]) -> Result<(), EbpfError> {
		let host_addr =
			Result::from(self.mapping.map(AccessType::Store, offset, buf.len() as u64))?;
		unsafe {
			std::ptr::copy_nonoverlapping(buf.as_ptr(), host_addr as usize as *mut u8, buf.len())
		}
		Ok(())
	}
}

struct ProcessData<'a> {
	/// The bridge to the supervisor.
	context: &'a mut dyn SupervisorContext,
	/// The next available address in the heap. Used by the bumper allocator.
	bumper_next: u64,
	meter: MeterRef,
}

/// This trait is used as a bridge between the eBPF program and the supervisor.
///
/// Specifically, it will be invoked every time when the eBPF program invokes the `ext_syscall`
/// syscall (via `call ext_syscall` in eBPF code).
pub trait SupervisorContext {
	/// Returns an `Ok(error code)`. If it's non-zero then the eBPF program will trap. `gas_left`
	/// can be changed to any value. If it's zero then the eBPF program will run out of gas
	/// immediatelly.
	///
	/// Returns `Err` if the supervisor trapped.
	fn supervisor_call(
		&mut self,
		r1: u64,
		r2: u64,
		r3: u64,
		r4: u64,
		r5: u64,
		gas_left: &mut u64,
		memory_ref: MemoryRef<'_, '_>,
	) -> Result<u64, ()>;
}

/// Executes the given eBPF program.
///
/// The program will receive the given `input`.
///
/// This function also expects a gas limit. If the gas is exhausted before the program terminates
/// then the execution is conclused with the OOG error.
pub fn execute(
	program: &[u8],
	input: &mut [u8],
	context: &mut dyn SupervisorContext,
	gas_left: &mut u64,
) -> Result<(), ExecError> {
	let config = Config::default();

	let mut syscall_registry = SyscallRegistry::default();
	syscall::register(&mut syscall_registry);

	let executable = Executable::<MeterRef>::from_elf(program, config, syscall_registry)
		.map_err(|_| ExecError::InvalidImage)?;
	let region_input = MemoryRegion::new_writable(input, ebpf::MM_INPUT_START);

	let verified_executable =
		VerifiedExecutable::<RequisiteVerifier, MeterRef>::from_executable(executable)
			.map_err(|_| ExecError::InvalidImage)?;

	// Beware! This is not technically sound.
	//
	// The API of `solana_rbpf` allows us just to create EbpfVm with the given process data and
	// but there is nothing that constraints EbpfVm to the lifetime of the process data.
	let mut meter = MeterRef::new(*gas_left);
	let mut process_data =
		ProcessData { context, bumper_next: ebpf::MM_HEAP_START, meter: meter.clone() };

	let mut heap = AlignedMemory::<{ HOST_ALIGN }>::zero_filled(HEAP_SIZE);
	let mut vm = EbpfVm::new(
		&verified_executable,
		&mut process_data,
		heap.as_slice_mut(),
		vec![region_input],
	)
	.map_err(|_| ExecError::InvalidImage)?;

	let result = vm.execute_program_interpreted(&mut meter);
	*gas_left = meter.get_remaining();
	match result {
		StableResult::Ok(_ret_code) => Ok(()),
		StableResult::Err(err) => match err {
			EbpfError::ExceededMaxInstructions(_pc, _limit) => Err(ExecError::OutOfGas),
			_ => Err(ExecError::Trap),
		},
	}
}
