use std::{cell::RefCell, rc::Rc};

struct Meter {
	gas_left: u64,
}

#[derive(Clone)]
pub struct MeterRef(Rc<RefCell<Meter>>);

impl MeterRef {
	/// Creates a new instance with the given gas left.
	pub fn new(gas_left: u64) -> Self {
		Self(Rc::new(RefCell::new(Meter { gas_left })))
	}

	/// Sets the new gas left value.
	pub fn set_gas_left(&self, gas_left: u64) {
		self.0.borrow_mut().gas_left = gas_left;
	}
}

impl solana_rbpf::vm::InstructionMeter for MeterRef {
	fn consume(&mut self, amount: u64) {
		self.0.borrow_mut().gas_left -= amount;
	}

	fn get_remaining(&self) -> u64 {
		self.0.borrow().gas_left
	}
}
