#![cfg_attr(not(feature = "std"), no_std)]
pub mod inherents;

use codec::{Decode, Encode, EncodeLike, Error, Input, Output};
use sp_std::vec::Vec;

use rand::{thread_rng, Rng};

use bls12_381::{G1Affine, G1Projective, G2Affine, Scalar};
use pairing::PairingCurveAffine;
use sha3::{Digest, Sha3_256};

pub const START_BEACON_HEIGHT: u32 = 2;

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

#[derive(Clone, Default)]
pub struct VerifyKey {
	point: G2Affine,
}

impl Encode for VerifyKey {
	fn encode_to<T: Output>(&self, dest: &mut T) {
		Encode::encode_to(&self.point.to_compressed().to_vec(), dest);
	}
}

impl Decode for VerifyKey {
	fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
		let mut bytes = [0u8; 96];
		let vec = Vec::decode(input)?;
		bytes.copy_from_slice(&vec[..]);
		let point = G2Affine::from_compressed(&bytes);
		if point.is_none().unwrap_u8() == 1 {
			return Err("could not decode G1Affine point".into());
		}

		Ok(VerifyKey {
			point: point.unwrap(),
		})
	}
}

// TODO this is a mock till a key box and randomness_verifier are not incorporated into pallet
pub fn verify_randomness(_verify_key: &VerifyKey, _randomness: &Randomness) -> bool {
	true
}

pub fn alice_bob_pairs() -> (Pair, Pair) {
	let secret = Scalar::from(1);
	let alice_pair = Pair {
		secret,
		verify: VerifyKey::from_secret(&secret),
	};
	let secret = Scalar::from(2);
	let bob_pair = Pair {
		secret,
		verify: VerifyKey::from_secret(&secret),
	};

	(alice_pair, bob_pair)
}

impl EncodeLike for VerifyKey {}

pub type Nonce = Vec<u8>;

impl VerifyKey {
	fn verify(&self, msg: &Vec<u8>, sgn: &Signature) -> bool {
		let p1 = sgn.0.pairing_with(&G2Affine::generator());
		let p2 = hash_to_curve(msg).pairing_with(&self.point);

		p1 == p2
	}

	fn from_secret(secret: &Scalar) -> Self {
		VerifyKey {
			point: G2Affine::from(G2Affine::generator() * secret),
		}
	}
}

#[derive(Clone)]
pub struct Pair {
	secret: Scalar,
	verify: VerifyKey,
}

fn random_scalar() -> Scalar {
	let mut rng = thread_rng();
	Scalar::from_raw([rng.gen(), rng.gen(), rng.gen(), rng.gen()])
}

impl Pair {
	pub fn generate() -> Self {
		let secret = random_scalar();
		let verify = VerifyKey::from_secret(&secret);

		Pair { secret, verify }
	}

	pub fn sign(&self, msg: &Vec<u8>) -> Signature {
		let point = hash_to_curve(msg);

		Signature {
			0: G1Affine::from(point * self.secret),
		}
	}

	pub fn verify(&self, msg: &Vec<u8>, sgn: &Signature) -> bool {
		self.verify.verify(msg, sgn)
	}

	pub fn verify_key(&self) -> VerifyKey {
		self.verify.clone()
	}
}

pub type ShareProvider = Pair;

fn poly_eval(coeffs: &Vec<Scalar>, x: &Scalar) -> Scalar {
	let mut eval = Scalar::zero();
	for coeff in coeffs.iter() {
		eval *= x;
		eval += coeff;
	}

	eval
}

pub fn generate_threshold_pairs(n_members: usize, threshold: usize) -> (Vec<Pair>, VerifyKey) {
	assert!(n_members >= threshold && threshold > 0);

	let mut pairs = Vec::new();

	let mut coeffs = Vec::new();
	for _ in 0..threshold {
		coeffs.push(random_scalar());
	}

	let secret = coeffs.last().unwrap().clone();
	let master_key = VerifyKey::from_secret(&secret);

	for i in 0..n_members {
		let x = Scalar::from((i + 1) as u64);
		let secret = poly_eval(&coeffs, &x);
		pairs.push(Pair {
			secret,
			verify: VerifyKey::from_secret(&secret),
		});
	}

	(pairs, master_key)
}

#[derive(PartialEq, Decode, Encode)]
pub struct Share {
	creator: u64,
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

#[derive(Clone)]
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

#[cfg(feature = "std")]
pub struct KeyBox {
	id: u64,
	share_provider: Pair,
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

fn lagrange_coef(shares: &Vec<Share>, x: u64) -> Scalar {
	let mut num = Scalar::one();
	let mut den = Scalar::one();

	for share in shares.iter() {
		if share.creator == x {
			continue;
		}
		let p = share.creator;
		num *= Scalar::from(p + 1).neg();
		if x > p {
			den *= Scalar::from(x - p);
		} else {
			den *= Scalar::from(p - x).neg();
		}
	}

	num * den.invert().unwrap()
}

#[cfg(feature = "std")]
impl KeyBox {
	pub fn new(
		id: u64,
		share_provider: Pair,
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
		self.verify_keys[share.creator as usize].verify(&share.nonce, &share.data)
	}

	// Some(share) if succeeded and None if failed for some reason (e.g. not enough shares) -- should add error handling later
	// Assumption: shares are for the same nonce, are valid, and there are exactly threshold of them
	pub fn combine_shares(&self, shares: &Vec<Share>) -> Randomness {
		let mut sum = G1Projective::identity();
		for share in shares.iter() {
			sum += share.data.0 * lagrange_coef(shares, share.creator);
		}

		Randomness {
			nonce: shares[0].nonce.clone(),
			data: Signature {
				0: G1Affine::from(sum),
			},
		}
	}

	pub fn verify_randomness(&self, randomness: &Randomness) -> bool {
		self.master_key.verify(randomness)
	}

	pub fn n_members(&self) -> usize {
		self.verify_keys.len()
	}

	pub fn threshold(&self) -> usize {
		self.threshold
	}
}

// TODO: this hashing function gen ^ hash(nonce) is not secure as the log is known for the result.
// Change to try-and-increment or a deterministic one at the earliest convinience.
pub fn hash_to_curve(nonce: &Vec<u8>) -> G1Affine {
	let mut hasher = Sha3_256::new();
	hasher.input(nonce);
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

	#[test]
	fn hash() {
		let nonce = random_nonce();
		let point = hash_to_curve(&nonce);
		assert_eq!(point.is_on_curve().unwrap_u8(), 1);
		assert_eq!(point.is_torsion_free().unwrap_u8(), 1);
	}

	#[test]
	fn encode_decode_signature() {
		let scalar = random_scalar();
		let sig = Signature {
			0: G1Affine::from(G1Affine::generator() * scalar),
		};

		let decoded = Signature::decode(&mut &Signature::encode(&sig)[..]);
		assert!(decoded.is_ok());
		assert_eq!(decoded.unwrap(), sig);
	}

	fn random_nonce() -> Nonce {
		rand::thread_rng().gen::<[u8; 32]>().to_vec()
	}

	#[test]
	fn correct_sign() {
		let pair = Pair::generate();
		let msg = random_nonce();
		let sgn = pair.sign(&msg);

		assert!(pair.verify(&msg, &sgn));
	}

	#[test]
	fn combine_shares() {
		let (n_members, threshold) = (3, 2);
		let (share_providers, master_key) = generate_threshold_pairs(n_members, threshold);
		let mut verifiers = Vec::new();
		for id in 0usize..n_members {
			verifiers.push(share_providers[id].verify_key());
		}
		let master_key = RandomnessVerifier::new(master_key);

		let mut kbs = Vec::new();
		for id in 0..n_members {
			kbs.push(KeyBox::new(
				id as u64,
				share_providers[id].clone(),
				verifiers.clone(),
				master_key.clone(),
				threshold,
			))
		}

		let nonce = random_nonce();
		let mut shares = Vec::new();
		for id in 0..threshold {
			shares.push(kbs[id].generate_share(&nonce));
		}

		let randomness = kbs[0].combine_shares(&shares);

		assert!(kbs[0].verify_randomness(&randomness));
	}
}
