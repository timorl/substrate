#![cfg_attr(not(feature = "std"), no_std)]

use codec::Encode;
use sp_std::vec::Vec;

#[cfg(feature = "std")]
use log::info;
#[cfg(feature = "std")]
use sp_std::sync::Arc;
#[cfg(feature = "std")]
use parking_lot::Mutex;

#[cfg(feature = "std")]
use codec::Decode;
#[cfg(feature = "std")]
use sp_inherents::{ProvideInherentData, InherentDataProviders, InherentData};
use sp_inherents::{InherentIdentifier, IsFatalError};

pub const INHERENT_IDENTIFIER: InherentIdentifier = *b"randbecn";
pub type InherentType = Vec<(Vec<u8>, Vec<u8>)>;

#[cfg(feature = "std")]
pub struct InherentDataProvider {
    random_bytes: Arc<Mutex<InherentType>>,
}

/// Errors that can occur while checking the timestamp inherent.
#[derive(Encode, sp_runtime::RuntimeDebug)]
#[cfg_attr(feature = "std", derive(Decode))]
pub enum InherentError {
	WrongHeight,
        InvalidRandomBytes,
}

impl IsFatalError for InherentError {
	fn is_fatal_error(&self) -> bool {
		match self {
			InherentError::WrongHeight => true,
			InherentError::InvalidRandomBytes => true,
		}
	}
}

#[cfg(feature = "std")]
impl ProvideInherentData for InherentDataProvider {
    fn inherent_identifier(&self) -> &'static InherentIdentifier {
        &INHERENT_IDENTIFIER
    }

    fn provide_inherent_data(
        &self,
        inherent_data: &mut InherentData,
    ) -> Result<(), sp_inherents::Error> {
        let id = (*self.random_bytes.lock()).clone();
        info!(target: "inherents", "created inherents {:?}", id);
        inherent_data.put_data(INHERENT_IDENTIFIER, &id)
    }

    fn error_to_string(&self, error: &[u8]) -> Option<String> {
        sp_inherents::Error::decode(&mut &error[..])
            .map(|e| e.into_string())
            .ok()
    }
}

/// Register the RndB inherent data provider, if not registered already.
#[cfg(feature = "std")]
pub fn register_rb_inherent_data_provider(
    inherent_data_providers: &InherentDataProviders,
    random_bytes: Arc<Mutex<InherentType>>,
) {
    if !inherent_data_providers.has_provider(&INHERENT_IDENTIFIER) {
        // always succeds due to the above check
        let _ = inherent_data_providers.register_provider(InherentDataProvider { random_bytes });
    }
}
