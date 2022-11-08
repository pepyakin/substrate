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
    ebpf,
    elf::{register_bpf_function, Executable},
    memory_region::{MemoryMapping, MemoryRegion},
    verifier::RequisiteVerifier,
    vm::{Config, EbpfVm, SyscallRegistry, TestInstructionMeter, VerifiedExecutable},
};


pub struct MemoryRef<'a, 'b> {
	mapping: &'a mut MemoryMapping<'b>,
}

/// This context is used for calling back into the supervisor.
pub trait SupervisorContext {
	fn supervisor_call(&mut self, memory_ref: MemoryRef<'_, '_>);
}

pub fn execute(program: &[u8], input: &mut [u8], context: &mut impl SupervisorContext) {
	let config = Config::default();
	let mut syscall_registry = SyscallRegistry::default();
	syscall_registry
		.register_syscall_by_name(b"abort", abort_syscall)
		.unwrap();
	syscall_registry
		.register_syscall_by_name(b"ext_syscall", ext_syscall)
		.unwrap();
	let mut executable =
		Executable::<TestInstructionMeter>::from_elf(program, config, syscall_registry).unwrap();
	let mem_region = MemoryRegion::new_writable(input, ebpf::MM_INPUT_START);
	let verified_executable =
		VerifiedExecutable::<RequisiteVerifier, TestInstructionMeter>::from_executable(executable)
			.unwrap();
	let mut vm = EbpfVm::new(&verified_executable, &mut (), &mut [], vec![mem_region]).unwrap();
	let res = vm
		.execute_program_interpreted(&mut TestInstructionMeter { remaining: 1 })
		.unwrap();
}

struct ProcessData<'a> {
	meter: TestInstructionMeter,
	context: &'a mut dyn SupervisorContext,
}

impl<'a> solana_rbpf::vm::InstructionMeter for ProcessData<'a> {
	fn consume(&mut self, amount: u64) {
		self.meter.consume(amount)
	}
	fn get_remaining(&self) -> u64 {
		self.meter.get_remaining()
	}
}

fn abort_syscall(
    _invoke_context: &mut ProcessData,
    _arg1: u64,
    _arg2: u64,
    _arg3: u64,
    _arg4: u64,
    _arg5: u64,
    _memory_mapping: &mut MemoryMapping,
    result: &mut solana_rbpf::vm::ProgramResult,
) {
    let err = solana_rbpf::error::EbpfError::UserError(Box::new(
        AbortError
    ));
    *result = solana_rbpf::vm::StableResult::Err(err);
}

#[derive(thiserror::Error, Debug)]
#[error("abort")]
struct AbortError;

fn ext_syscall(
    process_data: &mut ProcessData,
    _arg1: u64,
    _arg2: u64,
    _arg3: u64,
    _arg4: u64,
    _arg5: u64,
    _memory_mapping: &mut MemoryMapping,
    result: &mut solana_rbpf::vm::ProgramResult,
) {
    *result = solana_rbpf::vm::StableResult::Ok(0);
}
