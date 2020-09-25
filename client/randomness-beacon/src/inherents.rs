#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
use parking_lot::Mutex;
use std::sync::Arc;
use log::info;

#[cfg(feature = "std")]
use codec::Decode;
use sp_inherents::{InherentDataProviders, ProvideInherentData, InherentIdentifier, InherentData};

use super::{RandomBytes, Nonce};
pub const INHERENT_IDENTIFIER: InherentIdentifier = *b"randbecn";
// TODO: Nonce should be a hash so that Randomness-Beacon Pallet may choose the right one, but we
// cannot make InherentType generic over BlockT. Figureout how to do it.
pub type InherentType = Vec<(Nonce, RandomBytes)>;

#[cfg(feature = "std")]
pub struct InherentDataProvider{
        random_bytes: Arc<Mutex<InherentType>>,
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
		sp_inherents::Error::decode(&mut &error[..]).map(|e| e.into_string()).ok()
	}
}


/// Register the RndB inherent data provider, if not registered already.
pub fn register_rb_inherent_data_provider(
	inherent_data_providers: &InherentDataProviders,
        random_bytes: Arc<Mutex<InherentType>>,
){
	if !inherent_data_providers.has_provider(&INHERENT_IDENTIFIER) {
                // always succeds due to the above check
	    	let _ = inherent_data_providers.register_provider(InherentDataProvider{random_bytes});
	} 
}


