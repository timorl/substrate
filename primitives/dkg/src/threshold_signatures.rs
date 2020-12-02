#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode, EncodeLike, Error, Input, Output};
use sp_std::vec::Vec;

#[cfg(feature = "std")]
use rand::{thread_rng, Rng};

use bls12_381::{G1Affine, G1Projective, G2Affine, Scalar};
use pairing::PairingCurveAffine;

use sha3::{Digest, Sha3_256};

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

impl EncodeLike for Signature {}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct VerifyKey {
	pub(crate) point: G2Affine,
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
			return Err("could not decode G2Affine point".into());
		}

		Ok(VerifyKey {
			point: point.unwrap(),
		})
	}
}

impl EncodeLike for VerifyKey {}

impl VerifyKey {
	pub fn verify(&self, msg: &Vec<u8>, sgn: &Signature) -> bool {
		let p1 = sgn.0.pairing_with(&G2Affine::generator());
		let p2 = hash_to_curve(msg).pairing_with(&self.point);

		p1 == p2
	}

	pub fn from_secret(secret: &Scalar) -> Self {
		VerifyKey {
			point: G2Affine::from(G2Affine::generator() * secret),
		}
	}

	pub fn from_raw_secret(raw_secret: RawSecret) -> Self {
		let secret = Scalar::from_raw(raw_secret);
		Self::from_secret(&secret)
	}
}

use super::RawSecret;

#[derive(Clone, Debug, PartialEq, Default)]
pub struct ShareProvider {
	id: u64,
	secret: Scalar,
	verify: VerifyKey,
}

impl Encode for ShareProvider {
	fn encode_to<T: Output>(&self, dest: &mut T) {
		let mut bytes = self.id.to_le_bytes().to_vec();
		bytes.append(&mut self.secret.to_bytes().to_vec());
		Encode::encode_to(&bytes, dest);
	}
}

impl Decode for ShareProvider {
	fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
		let vec = Vec::decode(input)?;
		let mut bytes = [0u8; 8];
		bytes.copy_from_slice(&vec[..8]);
		let id = u64::from_le_bytes(bytes);

		let mut bytes = [0u8; 32];
		bytes.copy_from_slice(&vec[8..8 + 32]);
		let secret = Scalar::from_bytes(&bytes);
		if secret.is_none().unwrap_u8() == 1 {
			return Err("could not decode scalar".into());
		}

		Ok(Self::from_secret(id, secret.unwrap()))
	}
}

#[cfg(feature = "std")]
fn random_scalar() -> Scalar {
	let mut rng = thread_rng();
	let raw_secret = [rng.gen(), rng.gen(), rng.gen(), rng.gen()];
	scalar_from_raw_secret(raw_secret)
}

fn scalar_from_raw_secret(raw_secret: RawSecret) -> Scalar {
	Scalar::from_raw(raw_secret)
}

impl ShareProvider {
	pub fn is_correct(&self) -> bool {
		let g2power = G2Affine::from(G2Affine::generator() * self.secret);
		return g2power == self.verify.point;
	}

	pub fn from_secret(id: u64, secret: Scalar) -> Self {
		let verify = VerifyKey::from_secret(&secret);
		ShareProvider { id, secret, verify }
	}

	#[cfg(feature = "std")]
	pub fn generate(id: u64) -> Self {
		let secret = random_scalar();
		Self::from_secret(id, secret)
	}

	pub fn from_raw_secret(id: u64, seed: RawSecret) -> Self {
		let secret = scalar_from_raw_secret(seed);
		Self::from_secret(id, secret)
	}

	pub fn sign(&self, msg: &Vec<u8>) -> Signature {
		let point = hash_to_curve(msg);

		Signature(G1Affine::from(point * self.secret))
	}

	pub fn verify(&self, msg: &Vec<u8>, sgn: &Signature) -> bool {
		self.verify.verify(msg, sgn)
	}

	pub fn verify_key(&self) -> VerifyKey {
		self.verify.clone()
	}
}

#[derive(PartialEq, Clone, Decode, Encode)]
pub struct Share {
	creator: u64,
	data: Signature,
}

/// A mock for a BLS-based set of threshold keys.
#[derive(Clone, Encode, Decode, Default)]
pub struct KeyBox {
	share_provider: Option<ShareProvider>,
	verify_keys: Vec<VerifyKey>,
	master_key: VerifyKey,
	threshold: u64,
}

fn lagrange_coef(knots: &Vec<Scalar>, knot: Scalar, target: Scalar) -> Scalar {
	let mut num = Scalar::one();
	let mut den = Scalar::one();

	for x in knots.iter() {
		if *x != knot {
			num *= target - x;
			den *= Scalar::from(knot - x);
		}
	}
	num * den.invert().unwrap()
}

/// The implementation mocks BLS threshold keys by using a set of ed25519 keys.
/// To be replaced in Milestone 2.
impl KeyBox {
	pub fn new(
		share_provider: Option<ShareProvider>,
		verify_keys: Vec<VerifyKey>,
		master_key: VerifyKey,
		threshold: u64,
	) -> Self {
		KeyBox {
			share_provider,
			verify_keys,
			master_key,
			threshold,
		}
	}

	pub fn generate_share(&self, msg: &Vec<u8>) -> Option<Share> {
		if let Some(ref share_provider) = self.share_provider {
			return Some(Share {
				creator: share_provider.id,
				data: share_provider.sign(msg),
			});
		}

		None
	}

	pub fn verify_share(&self, msg: &Vec<u8>, share: &Share) -> bool {
		self.verify_keys[share.creator as usize].verify(msg, &share.data)
	}

	// Some(share) if succeeded and None if failed for some reason (e.g. not enough shares) -- should add error handling later
	// Assumption: shares are for the same msg, are valid, and there are exactly threshold of them
	pub fn combine_shares(&self, shares: &Vec<Share>) -> Signature {
		assert!(shares.len() as u64 == self.threshold);
		let mut sum = G1Projective::identity();
		let knots = shares.iter().map(|s| Scalar::from(s.creator + 1)).collect();
		for (i, share) in shares.iter().enumerate() {
			sum += share.data.0 * lagrange_coef(&knots, knots[i], Scalar::from(0));
		}

		Signature(G1Affine::from(sum))
	}

	pub fn verify_signature(&self, msg: &Vec<u8>, signature: &Signature) -> bool {
		self.master_key.verify(msg, signature)
	}

	pub fn n_members(&self) -> usize {
		self.verify_keys.len()
	}

	pub fn threshold(&self) -> u64 {
		self.threshold
	}
}

// TODO: this hashing function gen ^ hash(msg) is not secure as the log is known for the result.
// Change to try-and-increment or a deterministic one at the earliest convinience.
pub fn hash_to_curve(msg: &Vec<u8>) -> G1Affine {
	let mut hasher = Sha3_256::new();
	hasher.input(msg);
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

	fn random_msg() -> Vec<u8> {
		rand::thread_rng().gen::<[u8; 32]>().to_vec()
	}

	fn poly_eval(coeffs: &Vec<Scalar>, x: &Scalar) -> Scalar {
		let mut eval = Scalar::zero();
		for coeff in coeffs.iter().rev() {
			eval *= x;
			eval += coeff;
		}

		eval
	}

	fn generate_threshold_pairs(
		n_members: usize,
		threshold: usize,
	) -> (Vec<ShareProvider>, VerifyKey) {
		assert!(n_members >= threshold && threshold > 0);

		let mut pairs = Vec::new();

		let mut coeffs = Vec::new();
		for _ in 0..threshold {
			coeffs.push(random_scalar());
		}

		let secret = coeffs[0].clone();
		let master_key = VerifyKey::from_secret(&secret);

		for i in 0..n_members {
			let x = Scalar::from((i + 1) as u64);
			let secret = poly_eval(&coeffs, &x);
			pairs.push(ShareProvider {
				id: i as u64,
				secret,
				verify: VerifyKey::from_secret(&secret),
			});
		}

		(pairs, master_key)
	}

	#[test]
	fn hash() {
		let msg = random_msg();
		let point = hash_to_curve(&msg);
		assert_eq!(point.is_on_curve().unwrap_u8(), 1);
		assert_eq!(point.is_torsion_free().unwrap_u8(), 1);
	}

	#[test]
	fn encode_decode_pair() {
		let secret = random_scalar();
		let pair = ShareProvider::from_secret(7, secret);

		let decoded = ShareProvider::decode(&mut &pair.encode()[..]);
		assert!(decoded.is_ok());
		assert_eq!(decoded.unwrap(), pair);
	}

	#[test]
	fn encode_decode_signature() {
		let scalar = random_scalar();
		let sig = Signature {
			0: G1Affine::from(G1Affine::generator() * scalar),
		};

		let decoded = Signature::decode(&mut &sig.encode()[..]);
		assert!(decoded.is_ok());
		assert_eq!(decoded.unwrap(), sig);
	}

	#[test]
	fn correct_sign() {
		let pair = ShareProvider::generate(7);
		let msg = random_msg();
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

		let mut kbs = Vec::new();
		for id in 0..n_members {
			kbs.push(KeyBox::new(
				Some(share_providers[id].clone()),
				verifiers.clone(),
				master_key.clone(),
				threshold as u64,
			))
		}

		let msg = random_msg();
		let mut shares = Vec::new();
		for id in 0..threshold {
			shares.push(kbs[id].generate_share(&msg).unwrap());
		}

		let signature = kbs[0].combine_shares(&shares);

		assert!(kbs[0].verify_signature(&msg, &signature));
	}
}
