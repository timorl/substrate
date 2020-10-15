#![cfg_attr(not(feature = "std"), no_std)]
pub mod inherents;

use codec::{Decode, Encode, Error, Input, Output};
use sp_std::vec::Vec;

use bls12_381::{G1Affine, G2Affine, Scalar};
use sha3::{Digest, Sha3_256};

pub const START_BEACON_HEIGHT: u32 = 2;

pub struct VerifyKey {
	key: G2Affine,
}

pub struct SecretKey {
	key: Scalar,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Signature(G1Affine);

impl Encode for Signature {
	fn encode_to<T: Output>(&self, dest: &mut T) {
		Encode::encode_to(&self.0.to_compressed().to_vec(), dest);
	}
}

impl Decode for Signature {
	fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
		let mut bytes = [0u8; 48];
		let vec = Vec::decode(input)?;
		bytes.copy_from_slice(&vec[..]);
		let point = G1Affine::from_compressed(&bytes);
		if point.is_none().unwrap_u8() == 1 {
			return Err("could not decode G1Affine point".into());
		}

		Ok(Signature { 0: point.unwrap() })
	}
}

pub type Nonce = Vec<u8>;

#[derive(PartialEq, Decode, Encode)]
pub struct Share {
	creator: u32,
	nonce: Nonce,
	data: Signature,
}

#[derive(Encode, Decode, Clone, Debug, Default)]
pub struct Randomness {
	nonce: Nonce,
	data: Signature,
}

impl Randomness {
	pub fn nonce(&self) -> Nonce {
		self.nonce.clone()
	}
}

impl From<(Nonce, Vec<u8>)> for Randomness {
	fn from((nonce, random_bytes): (Nonce, Vec<u8>)) -> Randomness {
		let nonce = nonce.clone();
		let data = Signature::decode(&mut &random_bytes[..]).unwrap();
		Randomness { nonce, data }
	}
}

/*
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
*/

// TODO: this hashing function gen ^ hash(nonce) is not secure as the log is known for the result.
// Change to try-and-increment or a deterministic one at the earliest convinience.
pub fn hash_to_curve(nonce: Vec<u8>) -> G1Affine {
	let mut hasher = Sha3_256::new();
	hasher.input(&nonce);
	let data = hasher.result();

	let mut scalar_raw = [0u64; 4];
	for i in 0usize..4 {
		let mut bytes = [0u8; 8];
		bytes.copy_from_slice(&data[i * 8..(i + 1) * 8]);
		scalar_raw[i] = u64::from_le_bytes(bytes);
	}

	let scalar = Scalar::from_raw(scalar_raw);

	G1Affine::from(G1Affine::generator() * scalar)
}

#[cfg(test)]
mod tests {
	use super::*;
	use rand::{thread_rng, Rng};
	#[test]
	fn encode_decode_signature() {
		let mut rng = thread_rng();
		let scalar = Scalar::from_raw([rng.gen(), rng.gen(), rng.gen(), rng.gen()]);
		let sig = Signature {
			0: G1Affine::from(G1Affine::generator() * scalar),
		};

		let decoded = Signature::decode(&mut &Signature::encode(&sig)[..]);
		assert!(decoded.is_ok());
		assert_eq!(decoded.unwrap(), sig);
	}

	#[test]
	fn hash() {
		let nonce = [1u8; 48].to_vec();
		let point = hash_to_curve(nonce);
		assert_eq!(point.is_on_curve().unwrap_u8(), 1);
		assert_eq!(point.is_torsion_free().unwrap_u8(), 1);
	}

	/*
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
	*/
}
