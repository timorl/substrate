#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use sp_core::crypto::Pair;
use sp_std::vec::Vec;

pub mod inherents;

pub mod app {
	use sp_application_crypto::{app_crypto, ed25519, KeyTypeId};
	app_crypto!(ed25519, KeyTypeId(*b"rndb"));
}

sp_application_crypto::with_pair! {
	pub type ShareProvider = app::Pair;
}

const _seed: &[u8; 32] = b"12345678901234567890123456789012";

pub type VerifyKey = app::Public;

pub type Nonce = Vec<u8>;
#[derive(PartialEq)]
pub struct Share {
	creator: usize,
	nonce: Nonce,
	data: app::Signature,
}

pub struct Randomness {
	nonce: Nonce,
	data: app::Signature,
}

impl From<(Nonce, Vec<u8>)> for Randomness {
	fn from((nonce, random_bytes): (Nonce, Vec<u8>)) -> Randomness {
		let nonce = Encode::encode(&nonce);
		let data = app::Signature::decode(&mut &random_bytes[..]).unwrap();
		Randomness { nonce, data }
	}
}

pub struct RandomnessVerifier {
	master_key: ShareProvider,
}

impl RandomnessVerifier {
	pub fn new(_master_key: VerifyKey) -> Self {
		let master_key = ShareProvider::from_seed(_seed);
		RandomnessVerifier { master_key }
	}

	pub fn verify(&self, randomness: Randomness) -> bool {
		ShareProvider::verify(
			&randomness.data,
			randomness.nonce,
			&self.master_key.public(),
		)
	}
}

pub struct KeyBox {
	id: usize,
	share_provider: ShareProvider,
	verify_keys: Vec<VerifyKey>,
	master_key: RandomnessVerifier,
	threshold: usize,
}

impl KeyBox {
	pub fn new(
		id: usize,
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

	pub fn generate_share(&self, nonce: Nonce) -> Share {
		Share {
			creator: self.id,
			nonce: nonce.clone(),
			data: self.share_provider.sign(&nonce),
		}
	}

	fn verify_share(&self, share: &Share) -> bool {
		ShareProvider::verify(
			&share.data,
			share.nonce.clone(),
			&self.verify_keys[share.creator],
		)
	}

	// Some(share) if succeeded and None if failed for some reason (e.g. not enough shares) -- should add error handling later
	fn combine_shares(&self, shares: Vec<Share>) -> Option<Randomness> {
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
		Some(Randomness {
			nonce: nonce.clone(),
			data: ShareProvider::from_seed(_seed).sign(&nonce),
		})
	}

	fn verify_randomness(&self, randomness: Randomness) -> bool {
		self.master_key.verify(randomness)
	}

	fn n_members(&self) -> usize {
		self.verify_keys.len()
	}

	fn threshold(&self) -> usize {
		self.threshold
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use sp_core::crypto::Public;
	use sp_runtime::testing::H256;
	use substrate_test_runtime_client::runtime::Block;

	#[test]
	fn reject_wrong_randomness() {
		let data = b"00000000000000000000000000000000";
		let _master_key = VerifyKey::from_slice(data);
		let verifier = RandomnessVerifier::new(_master_key);

		let master_key = ShareProvider::from_seed(_seed);

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
		let n_members = 2;
		let threshold = 1;
		let keybox = KeyBox::new(id, share_provider1, verify_keys, verifier, threshold);

		let nonce = b"1729".to_vec();
		let mut share = keybox.generate_share(nonce);
		assert!(keybox.verify_share(&share));
		share.nonce = b"2137".to_vec();
		assert!(!keybox.verify_share(&share));
		share.nonce = b"1729".to_vec();
		share.creator = 1;
		assert!(!keybox.verify_share(&share));
	}
}
