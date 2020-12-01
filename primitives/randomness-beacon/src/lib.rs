//! The Randomness Beacon runtime api primitives.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod inherents;

use codec::{Decode, Encode};
use sp_dkg::{KeyBox, RawSecret, Share, ShareProvider, Signature, VerifyKey};
use sp_runtime::traits::NumberFor;
use sp_std::marker;
use sp_std::vec::Vec;

sp_api::decl_runtime_apis! {
	pub trait RandomnessBeaconApi {
		fn start_beacon_height() -> NumberFor<Block>;
		fn beacon_period() -> NumberFor<Block>;
	}
}

#[derive(Encode, Decode, Clone, Debug, Default, PartialEq)]
pub struct Randomness<Nonce> {
	nonce: Nonce,
	data: Signature,
}

impl<Nonce: Clone> Randomness<Nonce> {
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

	pub fn verify<Nonce: Encode>(&self, randomness: &Randomness<Nonce>) -> bool {
		self.master_key
			.verify(&randomness.nonce.encode(), &randomness.data)
	}
}

#[derive(Clone, Encode, Decode)]
pub struct RandomnessShare<Nonce: Encode + Decode> {
	nonce: Nonce,
	share: Share,
}

impl<Nonce: Encode + Decode> PartialEq<RandomnessShare<Nonce>> for RandomnessShare<Nonce> {
	fn eq(&self, rhs: &RandomnessShare<Nonce>) -> bool {
		self.share == rhs.share
	}
}

pub struct RBBox<Nonce> {
	keybox: KeyBox,
	_marker: marker::PhantomData<Nonce>,
}

impl<Nonce: Encode + Decode + Clone> RBBox<Nonce> {
	pub fn new(
		ix: Option<u64>,
		raw_secret: Option<RawSecret>,
		verification_keys: Vec<VerifyKey>,
		master_key: VerifyKey,
		threshold: u64,
	) -> Self {
		let sp = raw_secret.map(|rs| ShareProvider::from_raw_secret(ix.unwrap(), rs));
		RBBox {
			keybox: KeyBox::new(sp, verification_keys, master_key, threshold),
			_marker: marker::PhantomData,
		}
	}

	pub fn generate_randomness_share(&self, nonce: Nonce) -> Option<RandomnessShare<Nonce>> {
		let msg = nonce.encode();
		let maybe_share = self.keybox.generate_share(&msg);
		if let Some(share) = maybe_share {
			return Some(RandomnessShare { nonce, share });
		}
		None
	}

	pub fn verify_randomness_share(&self, randomness_share: &RandomnessShare<Nonce>) -> bool {
		let msg = randomness_share.nonce.encode();
		self.keybox.verify_share(&msg, &randomness_share.share)
	}

	pub fn combine_shares(
		&self,
		randomness_shares: &Vec<RandomnessShare<Nonce>>,
	) -> Randomness<Nonce> {
		let shares = randomness_shares
			.iter()
			.map(|rs| rs.share.clone())
			.collect();
		Randomness {
			nonce: randomness_shares[0].nonce.clone(),
			data: self.keybox.combine_shares(&shares),
		}
	}

	pub fn threshold(&self) -> u64 {
		self.keybox.threshold()
	}
}
