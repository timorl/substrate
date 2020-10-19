#![cfg_attr(not(feature = "std"), no_std)]
use sp_core::crypto::KeyTypeId;

pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"dkg!");

pub mod crypto {
	use super::KEY_TYPE;
	use sp_runtime::app_crypto::{app_crypto, sr25519};
	app_crypto!(sr25519, KEY_TYPE);
}
