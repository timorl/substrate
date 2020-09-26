#![cfg_attr(not(feature = "std"), no_std)]

use codec::Encode;
use log::info;

#[cfg(feature = "std")]
use parking_lot::Mutex;
use std::sync::Arc;

#[cfg(feature = "std")]
use codec::Decode;
use sp_inherents::{InherentData, InherentDataProviders, InherentIdentifier, ProvideInherentData};

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
	WrongHeight((u64,u64)),
        InvalidRandomBytes,
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
pub fn register_rb_inherent_data_provider(
    inherent_data_providers: &InherentDataProviders,
    random_bytes: Arc<Mutex<InherentType>>,
) {
    if !inherent_data_providers.has_provider(&INHERENT_IDENTIFIER) {
        // always succeds due to the above check
        let _ = inherent_data_providers.register_provider(InherentDataProvider { random_bytes });
    }
}
