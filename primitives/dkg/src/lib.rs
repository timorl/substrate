#![cfg_attr(not(feature = "std"), no_std)]

mod commitments;
mod threshold_signatures;

pub use commitments::{Commitment, EncryptionKey, EncryptionPublicKey, Scalar};
pub use threshold_signatures::{KeyBox, Share, ShareProvider, Signature, VerifyKey};

pub type AuthIndex = u64;
pub type RawSecret = [u64; 4];

use sp_core::crypto::KeyTypeId;
pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"dkg!");

pub mod crypto {
	use super::KEY_TYPE;
	use sp_runtime::app_crypto::{app_crypto, sr25519};
	app_crypto!(sr25519, KEY_TYPE);
	pub use sp_core::sr25519::CRYPTO_ID;
	pub type AuthorityId = Public;
}

use sp_runtime::traits::NumberFor;
use sp_std::vec::Vec;
sp_api::decl_runtime_apis! {
	pub trait DKGApi {
		fn master_verification_key() -> Option<VerifyKey>;
		fn master_key_ready() -> NumberFor<Block>;
		fn threshold() -> u64;
		fn authority_index() -> Option<AuthIndex>;
		fn verification_keys() -> Option<Vec<VerifyKey>>;
		fn public_keybox_parts() -> Option<(Option<AuthIndex>, Vec<VerifyKey>, VerifyKey, u64)>;
	}
}
