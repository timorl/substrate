//! The Randomness Beacon runtime primitives related to inherents.

use codec::{Decode, Encode};
use sp_inherents::{InherentIdentifier, IsFatalError};
pub const INHERENT_IDENTIFIER: InherentIdentifier = *b"randbecn";

/// Errors that can occur while checking the inherent
#[derive(Encode, sp_runtime::RuntimeDebug)]
#[cfg_attr(feature = "std", derive(Decode))]
pub enum InherentError {
	WrongHeight,
	InvalidRandomBytes,
	VerifyKeyNotSet,
}

impl InherentError {
	/// Tries to create an instance out of the given identifier and data.
	#[cfg(feature = "std")]
	pub fn try_from(id: &InherentIdentifier, data: &[u8]) -> Option<Self> {
		if id == &INHERENT_IDENTIFIER {
			<InherentError as codec::Decode>::decode(&mut &data[..]).ok()
		} else {
			None
		}
	}
}
impl IsFatalError for InherentError {
	fn is_fatal_error(&self) -> bool {
		match self {
			InherentError::WrongHeight => true,
			InherentError::InvalidRandomBytes => true,
			InherentError::VerifyKeyNotSet => true,
		}
	}
}
