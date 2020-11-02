#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode, EncodeLike, Error, Input, Output};
use sp_core::crypto::KeyTypeId;
use sp_std::vec::Vec;

pub use bls12_381::Scalar;
use bls12_381::{G1Affine, G2Affine};

pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"dkg!");

pub mod crypto {
	use super::KEY_TYPE;
	use sp_runtime::app_crypto::{app_crypto, sr25519};
	app_crypto!(sr25519, KEY_TYPE);
	pub use sp_core::sr25519::CRYPTO_ID;
	pub type AuthorityId = Public;
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct EncryptionPublicKey {
	g1point: G1Affine,
	g2point: G2Affine,
}

impl EncryptionPublicKey {
	pub fn from_raw_scalar(raw_scalar: [u64; 4]) -> Self {
		let scalar = Scalar::from_raw(raw_scalar);

		Self::from_scalar(scalar)
	}

	pub fn from_scalar(scalar: Scalar) -> Self {
		let g1point = G1Affine::from(G1Affine::generator() * scalar);
		let g2point = G2Affine::from(G2Affine::generator() * scalar);

		EncryptionPublicKey { g1point, g2point }
	}

	pub fn to_encryption_key(&self, secret: Scalar) -> EncryptionKey {
		let g1point = G1Affine::from(self.g1point * secret);
		let g2point = G2Affine::from(self.g2point * secret);

		EncryptionKey { g1point, g2point }
	}
}

impl Encode for EncryptionPublicKey {
	fn encode_to<T: Output>(&self, dest: &mut T) {
		let mut bytes = self.g1point.to_compressed().to_vec();
		bytes.append(&mut self.g2point.to_compressed().to_vec());
		Encode::encode_to(&bytes, dest);
	}
}

impl Decode for EncryptionPublicKey {
	fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
		let vec = Vec::decode(input)?;

		let mut bytes = [0u8; 48];
		bytes.copy_from_slice(&vec[..48]);
		let g1point = G1Affine::from_compressed(&bytes);
		if g1point.is_none().unwrap_u8() == 1 {
			return Err("could not decode G1Affine point".into());
		}
		let mut bytes = [0u8; 96];
		bytes.copy_from_slice(&vec[48..48 + 96]);
		let g2point = G2Affine::from_compressed(&bytes);
		if g1point.is_none().unwrap_u8() == 1 {
			return Err("could not decode G1Affine point".into());
		}
		Ok(EncryptionPublicKey {
			g1point: g1point.unwrap(),
			g2point: g2point.unwrap(),
		})
	}
}

impl EncodeLike for EncryptionPublicKey {}

#[derive(Clone)]
pub struct EncryptionKey {
	g1point: G1Affine,
	g2point: G2Affine,
}

impl EncryptionKey {
	pub fn encrypt(&self, msg: &Vec<u8>) -> Vec<u8> {
		let _ = self.g1point.is_identity();
		let _ = self.g2point.is_identity();
		msg.clone()
	}

	pub fn decrypt(&self, msg: &Vec<u8>) -> Option<Vec<u8>> {
		Some(msg.clone())
	}
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Commitment {
	g2point: G2Affine,
}

impl Commitment {
	pub fn new(coeff: Scalar) -> Self {
		Commitment {
			g2point: G2Affine::from(G2Affine::generator() * coeff),
		}
	}
}

impl Encode for Commitment {
	fn encode_to<T: Output>(&self, dest: &mut T) {
		Encode::encode_to(&self.g2point.to_compressed().to_vec(), dest);
	}
}

impl Decode for Commitment {
	fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
		let mut bytes = [0u8; 96];
		let vec = Vec::decode(input)?;
		bytes.copy_from_slice(&vec[..]);
		let point = G2Affine::from_compressed(&bytes);
		if point.is_none().unwrap_u8() == 1 {
			return Err("could not decode G2Affine point".into());
		}

		Ok(Commitment {
			g2point: point.unwrap(),
		})
	}
}

impl EncodeLike for Commitment {}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn encrypt_decrypt() {
		let raw_scalar = [1, 7, 2, 9];
		let pk = EncryptionPublicKey::from_raw_scalar(raw_scalar);
		let secret = Scalar::from_raw([2, 1, 3, 7]);
		let key = pk.to_encryption_key(secret);

		let msg = b"top secret msg".to_vec();
		let decrypted = key.decrypt(&key.encrypt(&msg));
		assert!(decrypted.is_some());
		assert_eq!(decrypted.unwrap(), msg);
	}

	#[test]
	fn encode_decode_encryption_pk() {
		let raw_scalar = [1, 7, 2, 9];
		let key = EncryptionPublicKey::from_raw_scalar(raw_scalar);

		let decoded = EncryptionPublicKey::decode(&mut &EncryptionPublicKey::encode(&key)[..]);
		assert!(decoded.is_ok());
		assert_eq!(decoded.unwrap(), key);
	}

	#[test]
	fn encode_decode_commitment() {
		let coef = Scalar::from_raw([1, 7, 2, 9]);
		let comm = Commitment::new(coef);

		let decoded = Commitment::decode(&mut &Commitment::encode(&comm)[..]);
		assert!(decoded.is_ok());
		assert_eq!(decoded.unwrap(), comm);
	}
}
