#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
use parking_lot::Mutex;
use std::sync::Arc;

#[cfg(feature = "std")]
use codec::Decode;
use sp_inherents::{InherentDataProviders, ProvideInherentData, InherentIdentifier, InherentData};

use super::RandomBytes;
pub const INHERENT_IDENTIFIER: InherentIdentifier = *b"randbecn";
pub type InherentType = RandomBytes;

#[cfg(feature = "std")]
pub struct InherentDataProvider{
        random_bytes: Arc<Mutex<Option<RandomBytes>>>,
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
                // probably here should be logic for wating for next random bytes
                if let Some(id) = *self.random_bytes.lock() {
		    inherent_data.put_data(INHERENT_IDENTIFIER, &id)
                } else {
                    return Err("Didn't receive new random bytes".into());
                }
        }

	fn error_to_string(&self, error: &[u8]) -> Option<String> {
		sp_inherents::Error::decode(&mut &error[..]).map(|e| e.into_string()).ok()
	}
}


/// Register the RndB inherent data provider, if not registered already.
pub fn register_rb_inherent_data_provider(
	inherent_data_providers: &InherentDataProviders,
        random_bytes: Arc<Mutex<Option<RandomBytes>>>,
){
	if !inherent_data_providers.has_provider(&INHERENT_IDENTIFIER) {
                // always succeds due to the above check
	    	let _ = inherent_data_providers.register_provider(InherentDataProvider{random_bytes});
	} 
}


