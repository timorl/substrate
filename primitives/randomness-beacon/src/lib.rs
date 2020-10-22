//! The Randomness Beacon runtime api primitives.

#![cfg_attr(not(feature = "std"), no_std)]
pub mod inherents;

use codec::{Decode, Encode};
#[cfg(feature = "std")]
use sp_core::crypto::Pair;
use sp_std::vec::Vec;



pub mod app {
	use sp_application_crypto::{app_crypto, ed25519, key_types::RANDOMNESS_BEACON};
	app_crypto!(ed25519, RANDOMNESS_BEACON);
}

sp_application_crypto::with_pair! {
	pub type ShareProvider = app::Pair;
}

pub const START_BEACON_HEIGHT: u32 = 2;

pub const MASTER_SEED: &[u8; 32] = b"12345678901234567890123456789012";
const MASTER_MATERIAL: [u8; 32] = [
	47, 140, 97, 41, 216, 22, 207, 81, 195, 116, 188, 127, 8, 195, 230, 62, 209, 86, 207, 120, 174,
	251, 74, 101, 80, 217, 123, 135, 153, 121, 119, 238,
];

pub type VerifyKey = app::Public;

pub type Nonce = Vec<u8>;
#[derive(PartialEq, Decode, Encode)]
pub struct Share {
	creator: u32,
	nonce: Nonce,
	data: app::Signature,
}

#[derive(Encode, Decode, Clone, Debug, Default)]
pub struct Randomness {
	nonce: Nonce,
	data: app::Signature,
}

impl Randomness {
	pub fn nonce(&self) -> Nonce {
		self.nonce.clone()
	}
}

impl From<(Nonce, Vec<u8>)> for Randomness {
	fn from((nonce, random_bytes): (Nonce, Vec<u8>)) -> Randomness {
		let nonce = nonce.clone();
		let data = app::Signature::decode(&mut &random_bytes[..]).unwrap();
		Randomness { nonce, data }
	}
}

pub fn verify_randomness(verify_key: &VerifyKey, randomness: Randomness) -> bool {
	<VerifyKey as sp_runtime::RuntimeAppPublic>::verify(
		verify_key,
		&randomness.nonce,
		&randomness.data,
	)
}

pub fn generate_verify_key() -> VerifyKey {
	sp_application_crypto::ed25519::Public::from_raw(MASTER_MATERIAL).into()
}

/// A mock for BLS public key. An ed25519 key is used for now.
/// This will be replaced by actual BLS keys in Milestone 2.
#[derive(Clone)]
pub struct RandomnessVerifier {
	master_key: VerifyKey,
}

impl RandomnessVerifier {
	pub fn new(master_key: VerifyKey) -> Self {
		RandomnessVerifier { master_key }
	}

	pub fn verify(&self, randomness: Randomness) -> bool {
		<VerifyKey as sp_runtime::RuntimeAppPublic>::verify(
			&self.master_key,
			&randomness.nonce,
			&randomness.data,
		)
	}
}

/// A mock for a BLS-based set of threshold keys.
#[cfg(feature = "std")]
pub struct KeyBox {
	id: u32,
	share_provider: ShareProvider,
	verify_keys: Vec<VerifyKey>,
	master_key: RandomnessVerifier,
	threshold: usize,
}

#[cfg(feature = "std")]
impl Clone for KeyBox {
	fn clone(&self) -> Self {
		KeyBox {
			id: self.id.clone(),
			share_provider: self.share_provider.clone(),
			verify_keys: self.verify_keys.clone(),
			master_key: self.master_key.clone(),
			threshold: self.threshold.clone(),
		}
	}
}

/// The implementation mocks BLS threshold keys by using a set of ed25519 keys.
/// To be replaced in Milestone 2.
#[cfg(feature = "std")]
impl KeyBox {
	pub fn new(
		id: u32,
		share_provider: ShareProvider,
		verify_keys: Vec<VerifyKey>,
		master_key: RandomnessVerifier,
		threshold: usize,
	) -> Self {
		KeyBox {
			id,
			share_provider,
			verify_keys,
			master_key,
			threshold,
		}
	}

	pub fn generate_share(&self, nonce: &Nonce) -> Share {
		Share {
			creator: self.id,
			nonce: nonce.clone(),
			data: self.share_provider.sign(&nonce),
		}
	}

	pub fn verify_share(&self, share: &Share) -> bool {
		ShareProvider::verify(
			&share.data,
			share.nonce.clone(),
			&self.verify_keys[share.creator as usize],
		)
	}

	// Some(share) if succeeded and None if failed for some reason (e.g. not enough shares) -- should add error handling later
	pub fn combine_shares(&self, shares: &Vec<Share>) -> Option<Randomness> {
		if shares.len() == 0 {
			return None;
		}

		if shares.iter().any(|s| !self.verify_share(s)) {
			return None;
		}

		if shares
			.iter()
			.filter(|share| shares.iter().filter(|s| s == share).count() == 1)
			.count() < self.threshold
		{
			return None;
		}

		let nonce = shares[0].nonce.clone();
		if shares.iter().any(|s| s.nonce != nonce) {
			return None;
		}

		// TODO: replace the following mock
		let master_key = ShareProvider::from_seed(MASTER_SEED);
		let data = master_key.sign(&nonce);
		Some(Randomness { nonce, data })
	}

	pub fn verify_randomness(&self, randomness: Randomness) -> bool {
		self.master_key.verify(randomness)
	}

	pub fn n_members(&self) -> usize {
		self.verify_keys.len()
	}

	pub fn threshold(&self) -> usize {
		self.threshold
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use sp_core::crypto::{Pair, Public};

	#[test]
	fn reject_wrong_randomness() {
		let master_key = generate_verify_key();
		let verifier = RandomnessVerifier::new(master_key);

		let master_key = ShareProvider::from_seed(MASTER_SEED);

		let nonce = b"1729".to_vec();
		let data = master_key.sign(&nonce);
		let randomness = Randomness {
			nonce,
			data: data.clone(),
		};
		assert!(verifier.verify(randomness));

		let nonce = b"2137".to_vec();
		let randomness = Randomness { nonce, data };
		assert!(!verifier.verify(randomness));
	}

	#[test]
	fn reject_wrong_share() {
		let data = b"00000000000000000000000000000000";
		let _master_key = VerifyKey::from_slice(data);
		let verifier = RandomnessVerifier::new(_master_key);
		let seed = b"17291729172917291729172917291729";
		let share_provider1 = ShareProvider::from_seed(seed);
		let seed = b"21372137213721372137213721372137";
		let share_provider2 = ShareProvider::from_seed(seed);
		let verify_keys = vec![share_provider1.public(), share_provider2.public()];
		let id = 0;
		let threshold = 1;
		let keybox = KeyBox::new(id, share_provider1, verify_keys, verifier, threshold);

		let nonce = b"1729".to_vec();
		let mut share = keybox.generate_share(&nonce);
		assert!(keybox.verify_share(&share));
		share.nonce = b"2137".to_vec();
		assert!(!keybox.verify_share(&share));
		share.nonce = b"1729".to_vec();
		share.creator = 1;
		assert!(!keybox.verify_share(&share));
	}
}
