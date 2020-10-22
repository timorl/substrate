#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode, EncodeLike, Error, Input, Output};
use sp_core::crypto::KeyTypeId;
use sp_std::vec::Vec;

use bls12_381::{G1Affine, G2Affine, Scalar};

pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"dkg!");

pub mod crypto {
	use super::KEY_TYPE;
	use sp_runtime::app_crypto::{app_crypto, sr25519};
	app_crypto!(sr25519, KEY_TYPE);
	pub use sp_core::sr25519::CRYPTO_ID;
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct EncryptionPublicKey {
	g1point: G1Affine,
	g2point: G2Affine,
}

impl EncryptionPublicKey {
	pub fn from_raw_scalar(raw_scalar: [u64; 4]) -> Self {
		let scalar = Scalar::from_raw(raw_scalar);
		let g1point = G1Affine::from(G1Affine::generator() * scalar);
		let g2point = G2Affine::from(G2Affine::generator() * scalar);

		EncryptionPublicKey { g1point, g2point }
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

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn encode_decode_encryption_pk() {
		let raw_scalar = [1, 2, 3, 4];
		let key = EncryptionPublicKey::from_raw_scalar(raw_scalar);

		let decoded = EncryptionPublicKey::decode(&mut &EncryptionPublicKey::encode(&key)[..]);
		assert!(decoded.is_ok());
		assert_eq!(decoded.unwrap(), key);
	}
}
