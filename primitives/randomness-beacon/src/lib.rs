//! The Randomness Beacon runtime api primitives.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod inherents;

use codec::{Decode, Encode};
use sp_dkg::{Signature, VerifyKey};
use sp_runtime::traits::NumberFor;
use sp_std::vec::Vec;

sp_api::decl_runtime_apis! {
	   pub trait RandomnessBeaconApi {
			   fn start_beacon_height() -> NumberFor<Block> ;
	   }
}

pub type Nonce = Vec<u8>;

#[derive(Encode, Decode, Clone, Debug, Default, PartialEq)]
pub struct Randomness {
	nonce: Nonce,
	data: Signature,
}

impl Randomness {
	pub fn new(nonce: Nonce, data: Signature) -> Self {
		Randomness { nonce, data }
	}

	pub fn nonce(&self) -> Nonce {
		self.nonce.clone()
	}
}

#[derive(Clone, Debug, Default, PartialEq, Encode, Decode)]
pub struct RandomnessVerifier {
	master_key: VerifyKey,
}

impl RandomnessVerifier {
	pub fn new(master_key: VerifyKey) -> Self {
		RandomnessVerifier { master_key }
	}

	pub fn verify(&self, randomness: &Randomness) -> bool {
		self.master_key.verify(&randomness.nonce, &randomness.data)
	}
}
