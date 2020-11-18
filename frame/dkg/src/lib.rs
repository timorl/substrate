// This file is part of Substrate.

// Copyright (C) 2019-2020 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::{debug, decl_module, decl_storage, traits::Get, Parameter};
use frame_system::{
	ensure_signed,
	offchain::{AppCrypto, CreateSignedTransaction, SendSignedTransaction, Signer},
};
use sp_runtime::{
	offchain::storage::StorageValueRef,
	traits::{IdentifyAccount, Member},
	RuntimeAppPublic,
};
use sp_std::{convert::TryInto, vec::Vec};

use sp_dkg::{
	AuthIndex, Commitment, EncryptionKey, EncryptionPublicKey, RawScalar, Scalar, VerifyKey,
};

mod tests;

// TODO handle the situation when the node is not an authority

// TODO do we add protection against biasing?

// n is the number of nodes in the committee
// node indices are 1-based: 1, 2, ..., n
// t is the threshold: it is necessary and sufficient to have t shares to combine
// the degree of the polynomial is thus t-1

// TODO the following and the definition of AuthorityId probably needs a refactor. The problem is
// that the trait CreateSignedTransaction needed by Signer imposes that AuthorityId must extend
// AppCrypto and on the other hand if we want to use AuthorityId as public keys of validators, i.e.
// sign messages, determine index in the validator list and simply be their ids, then we need to
// extend AuthorityId with RuntimeAppPublic as keys in keystore are stored as RuntimeAppPublic.
pub mod crypto {
	use codec::{Decode, Encode};
	use sp_runtime::{MultiSignature, MultiSigner};

	#[cfg(feature = "std")]
	use serde::{Deserialize, Serialize};
	#[cfg_attr(feature = "std", derive(Deserialize, Serialize))]
	#[derive(Debug, Default, PartialEq, Eq, Clone, PartialOrd, Ord, Decode, Encode)]
	pub struct DKGId(sp_dkg::crypto::Public);
	impl frame_system::offchain::AppCrypto<MultiSigner, MultiSignature> for DKGId {
		type RuntimeAppPublic = sp_dkg::crypto::Public;
		type GenericSignature = sp_core::sr25519::Signature;
		type GenericPublic = sp_core::sr25519::Public;
	}

	impl From<sp_dkg::crypto::Public> for DKGId {
		fn from(pk: sp_dkg::crypto::Public) -> Self {
			DKGId(pk)
		}
	}

	impl From<MultiSigner> for DKGId {
		fn from(pk: MultiSigner) -> Self {
			match pk {
				MultiSigner::Sr25519(key) => DKGId(key.into()),
				_ => DKGId(Default::default()),
			}
		}
	}

	impl Into<MultiSigner> for DKGId {
		fn into(self) -> MultiSigner {
			MultiSigner::Sr25519(self.0.into())
		}
	}

	impl Into<sp_dkg::crypto::Public> for DKGId {
		fn into(self) -> sp_dkg::crypto::Public {
			self.0
		}
	}

	impl AsRef<[u8]> for DKGId {
		fn as_ref(&self) -> &[u8] {
			AsRef::<[u8]>::as_ref(&self.0)
		}
	}

	impl sp_runtime::RuntimeAppPublic for DKGId {
		const ID: sp_runtime::KeyTypeId = sp_runtime::KeyTypeId(*b"dkg!");
		const CRYPTO_ID: sp_runtime::CryptoTypeId = sp_dkg::crypto::CRYPTO_ID;
		type Signature = sp_dkg::crypto::Signature;

		fn all() -> sp_std::vec::Vec<Self> {
			sp_dkg::crypto::Public::all()
				.into_iter()
				.map(|p| p.into())
				.collect()
		}

		fn generate_pair(seed: Option<sp_std::vec::Vec<u8>>) -> Self {
			DKGId(sp_dkg::crypto::Public::generate_pair(seed))
		}

		fn sign<M: AsRef<[u8]>>(&self, msg: &M) -> Option<Self::Signature> {
			self.0.sign(msg)
		}

		fn verify<M: AsRef<[u8]>>(&self, msg: &M, signature: &Self::Signature) -> bool {
			self.0.verify(msg, signature)
		}

		fn to_raw_vec(&self) -> sp_std::vec::Vec<u8> {
			self.0.to_raw_vec()
		}
	}
}

pub trait Trait: CreateSignedTransaction<Call<Self>> {
	/// The identifier type for an offchain worker.
	type AuthorityId: Member
		+ Parameter
		+ RuntimeAppPublic
		+ AppCrypto<Self::Public, Self::Signature>
		+ Ord
		+ From<Self::Public>
		+ Into<Self::Public>;

	/// The overarching dispatch call type.
	type Call: From<Call<Self>>;

	// TODO maybe we could control the round boundaries with events?
	type RoundEnds: Get<[Self::BlockNumber; 4]>;
	type MasterKeyReady: Get<Self::BlockNumber>;
}

// An index of the authority on the list of validators.
pub type EncryptedShare = Vec<u8>;

// TODO pick hashing functions
decl_storage! {
	trait Store for Module<T: Trait> as DKGWorker {

		// round 0

		// EncryptionPKs: Vec<Option<EncryptionPubKey>>;
		EncryptionPKs get(fn encryption_pks): Vec<Option<EncryptionPublicKey>>;


		// round 1

		// ith entry is the CommitedPoly of (i+1)th node submitted in a tx in round 1
		// CommittedPolynomials: Vec<Option<CommittedPoly>>;
		CommittedPolynomials get(fn committed_polynomilas): Vec<Vec<Commitment>>;
		// ith entry is the EncShareList of (i+1)th node submitted in a tx in round 1
		// EncryptedSharesLists: Vec<Option<EncShareList>>;
		EncryptedSharesLists get(fn encrypted_shares_lists): Vec<Vec<Option<EncryptedShare>>>;


		// round 2

		// ith entry is a list of disputes against dealers raised by node i submitted in round 2
		DisputesAgainstDealer get(fn disputes_against_dealer): Vec<Vec<AuthIndex>>;
		// list of n bools: ith is true <=> both the below conditions are satisfied:
		// 1) (i+1)th node succesfully participated in round 0 and round 1
		// 2) there was no succesful dispute that proves cheating of (i+1)th node in round 2
		IsCorrectDealer get(fn is_correct_dealer): Vec<bool>;


		// round 3
		pub MasterVerificationKey: VerifyKey;
		VerificationKeys: Vec<VerifyKey>;


		/// The current authorities
		pub Authorities get(fn authorities): Vec<T::AuthorityId>;

		/// The threshold of BLS scheme
		pub Threshold: u64;
	}
	add_extra_genesis {
		config(authorities): Vec<T::AuthorityId>;
		config(threshold): u64;
		build(|config| {
			Module::<T>::init_store(&config.authorities);
			Module::<T>::set_threshold(config.threshold);
		})
	}
}

decl_module! {
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {

		// TODO: we need to be careful with weights -- for now they are 0, but need to think about them later
		#[weight = 0]
		pub fn post_encryption_key(origin, pk: EncryptionPublicKey)  {
			debug::RuntimeLogger::init();

			let now = <frame_system::Module<T>>::block_number();
			let who = ensure_signed(origin)?;

			match Self::authority_index(who){
				Some(ix) => {
					if now > T::RoundEnds::get()[0] {
						debug::info!("DKG POST_ENCRYPTION_KEY FROM: {:?} block {:?} TOO LATE; SKIPPING", ix, now);
					} else {
						debug::info!("DKG POST_ENCRYPTION_KEY FROM: {:?} block {:?}", ix, now);
						EncryptionPKs::mutate(|ref mut values| values[ix as usize] = Some(pk));
					}
				}
				None =>  debug::info!("DKG POST_ENCRYPTION_KEY FAILED FIND AUTH"),
			}
		}

		#[weight = 0]
		pub fn post_secret_shares(origin, shares: Vec<Option<EncryptedShare>>, comm_poly: Vec<Commitment>, hash_round0: T::Hash) {
			debug::RuntimeLogger::init();

			let now = <frame_system::Module<T>>::block_number();
			let who = ensure_signed(origin)?;

			match Self::authority_index(who){
				Some(ix) => {
					let round0_number: T::BlockNumber = T::RoundEnds::get()[0];
					let correct_hash_round0 = <frame_system::Module<T>>::block_hash(round0_number);
					match (hash_round0 == correct_hash_round0, now <= T::RoundEnds::get()[1]) {
						(false, _) => { debug::info!(
							"DKG POST_SECRET_SHARES CALL: wrong hash: {:?} instead of {:?} from {:?}",
							hash_round0, correct_hash_round0, ix);
						}
						(true, false) => { debug::info!(
								"DKG POST_SECRET_SHARES CALL: BLOCK: {:?} WHO {:?} TOO LATE; SKIPPING",
								now, ix);
						}
						(true, true) => { debug::info!(
							"DKG POST_SECRET_SHARES CALL: BLOCK_NUMBER: {:?} WHO {:?}", now, ix);
							EncryptedSharesLists::mutate(|ref mut values| values[ix as usize] = shares);
							CommittedPolynomials::mutate(|ref mut values| values[ix as usize] = comm_poly);
							IsCorrectDealer::mutate(|ref mut values| values[ix as usize] = true);
						}
					}
				}
				None =>  debug::info!("DKG POST_SECRET_SHARES FAILED FIND AUTH"),
			}
		}

		#[weight = 0]
		pub fn post_disputes(origin, disputes: Vec<AuthIndex>, hash_round1: T::Hash) {
			debug::RuntimeLogger::init();

			let now = <frame_system::Module<T>>::block_number();
			let who = ensure_signed(origin)?;

			match Self::authority_index(who){
				Some(ix) => {
					let round1_number: T::BlockNumber = T::RoundEnds::get()[1];
					let correct_hash_round1 = <frame_system::Module<T>>::block_hash(round1_number);
					match (hash_round1 == correct_hash_round1, now <= T::RoundEnds::get()[2]) {
						(false, _) => { debug::info!(
							"DKG POST_DISPUTES CALL: wrong hash: {:?} instead of {:?} from {:?}",
							hash_round1, correct_hash_round1, ix);
						}
						(true, false) => { debug::info!(
								"DKG POST_DISPUTES CALL: BLOCK: {:?} WHO {:?} TOO LATE; SKIPPING",
								now, ix);
						}
						(true, true) => { debug::info!(
							"DKG POST_DISPUTES CALL: BLOCK_NUMBER: {:?} WHO {:?} disputes {:?}",
							now, ix, disputes);
							DisputesAgainstDealer::mutate(|ref mut values| values[ix as usize] = disputes.clone());
							// TODO verify disputes
							IsCorrectDealer::mutate(|ref mut values|
								disputes.iter().for_each(|ix| values[*ix as usize] = false)
							);
						}
					}
				}
				None =>  debug::info!("DKG POST_DISPUTES FAILED FIND AUTH"),
			}
		}

		// TODO maybe it should be an event?
		#[weight = 0]
		pub fn post_verification_keys(origin, mvk: VerifyKey, vks: Vec<VerifyKey>, hash_round2: T::Hash) {
			debug::RuntimeLogger::init();

			let now = <frame_system::Module<T>>::block_number();
			let who = ensure_signed(origin)?;

			match Self::authority_index(who){
				Some(ix) => {
					debug::info!("DKG POST_VERIFICATION_KEYS FROM: {:?} block {:?}", ix, now);
					MasterVerificationKey::put(mvk);
					VerificationKeys::put(vks);
				}
				None =>  debug::info!("DKG POST_VERIFICATION_KEYS FAILED FIND AUTH"),
			}

		}

		fn offchain_worker(block_number: T::BlockNumber) {
			if block_number < T::RoundEnds::get()[0]  {
					Self::handle_round0(block_number);
			} else if block_number < T::RoundEnds::get()[1] {
				// implement creating tx for round 1
					Self::handle_round1(block_number);
			} else if block_number < T::RoundEnds::get()[2] {
				// implement creating tx for round 2
					Self::handle_round2(block_number);
			} else if block_number < T::RoundEnds::get()[3] {
				// implement creating tx for round 3
					Self::handle_round3(block_number);
			}
		}
	}
}

impl<T: Trait> Module<T> {
	fn init_store(authorities: &[T::AuthorityId]) {
		if !authorities.is_empty() {
			debug::info!("DKG GENESIS init_store with authorities {:?}", authorities);
			assert!(
				Self::authorities().is_empty(),
				"Authorities are already initialized!"
			);
			let mut authorities = authorities.to_vec();
			authorities.sort();
			<Authorities<T>>::put(&authorities);
			let n_members = authorities.len();
			EncryptionPKs::put(sp_std::vec![None::<EncryptionPublicKey>; n_members]);
			CommittedPolynomials::put(sp_std::vec![Vec::<Commitment>::new(); n_members]);
			EncryptedSharesLists::put(
				sp_std::vec![sp_std::vec![None::<EncryptedShare>; n_members]; n_members],
			);
			DisputesAgainstDealer::put(sp_std::vec![Vec::<AuthIndex>::new(); n_members]);
			IsCorrectDealer::put(sp_std::vec![false; n_members]);
		}
	}

	fn set_threshold(threshold: u64) {
		let n_members = Self::authorities().len();
		assert!(
			0 < threshold && threshold <= n_members as u64,
			"Wrong threshold or n_members"
		);
		debug::info!(
			"DKG GENESIS set_threshold {:?} when n_members {:?}",
			threshold,
			n_members
		);

		assert!(!Threshold::exists(), "Threshold is already initialized!");
		Threshold::set(threshold);
	}

	// generate encryption pair and send public key on chain
	fn handle_round0(block_number: T::BlockNumber) {
		const ALREADY_SET: () = ();

		let auth = match Self::local_authority_key() {
			Some((ix, auth)) => {
				debug::info!(
					"DKG handle_round0 called at block: {:?} by authority: {:?}",
					block_number,
					ix,
				);
				auth
			}
			None => {
				debug::info!(
					"DKG handle_round0 called at block: {:?} by non-authority, skipping",
					block_number
				);
				return;
			}
		};

		// TODO: encrypt the key in the store?
		let val = StorageValueRef::persistent(b"dkw::enc_key");
		let res = val.mutate(|last_set: Option<Option<RawScalar>>| match last_set {
			Some(Some(_)) => Err(ALREADY_SET),
			_ => {
				let scalar_raw = gen_raw_scalar();

				debug::info!("DKG setting a new encryption key: {:?}", scalar_raw);
				Ok(scalar_raw)
			}
		});

		if let Ok(Ok(raw_scalar)) = res {
			let signer =
				Signer::<T, T::AuthorityId>::all_accounts().with_filter([auth.into()].to_vec());
			if !signer.can_sign() {
				debug::info!("DKG ERROR NO KEYS FOR SIGNER!!!");
				return;
			}
			let enc_pk = EncryptionPublicKey::from_raw_scalar(raw_scalar);
			let tx_res =
				signer.send_signed_transaction(|_| Call::post_encryption_key(enc_pk.clone()));

			for (acc, res) in &tx_res {
				match res {
					Ok(()) => {
						debug::info!("DKG sending the encryption key generated by [{:?}]", acc.id,)
					}
					Err(e) => debug::error!(
						"DKG [{:?}] Failed to submit transaction with encryption key: {:?}",
						acc.id,
						e
					),
				}
			}
		}
	}

	// generate secret polynomial, encrypt it, and send it with commitments to the chain
	fn handle_round1(block_number: T::BlockNumber) {
		const ALREADY_SET: () = ();

		let auth = match Self::local_authority_key() {
			Some((ix, auth)) => {
				debug::info!(
					"DKG handle_round1 called at block: {:?} by authority: {:?}",
					block_number,
					ix,
				);
				auth
			}
			None => {
				debug::info!(
					"DKG handle_round1 called at block: {:?} by non-authority, skipping",
					block_number
				);
				return;
			}
		};

		// 0. generate secrets
		let n_members = Self::authorities().len();
		let threshold = Threshold::get();
		let val = StorageValueRef::persistent(b"dkw::secret_poly");
		let res = val.mutate(|last_set: Option<Option<Vec<RawScalar>>>| match last_set {
			Some(Some(_)) => Err(ALREADY_SET),
			_ => {
				let poly = gen_poly_coeffs(threshold - 1);

				debug::info!("DKG generating secret polynomial");
				Ok(poly)
			}
		});

		// TODO: meh borrow checker
		if res.is_err() {
			return;
		}
		let res = res.unwrap();
		if res.is_err() {
			return;
		}
		let res = res.unwrap();
		let poly = &res.into_iter().map(|raw| Scalar::from_raw(raw)).collect();

		// 1. generate encryption keys
		let encryption_keys = Self::encryption_keys();

		// 2. generate secret shares
		let mut enc_shares = sp_std::vec![None; n_members];

		for ix in 0..n_members {
			if let Some(ref enc_key) = encryption_keys[ix] {
				let x = &Scalar::from(ix as u64 + 1);
				let share = poly_eval(poly, x);
				let share_data = share.to_bytes().to_vec();
				enc_shares[ix] = Some(enc_key.encrypt(&share_data));
			}
		}

		// 3. generate commitments
		let mut comms = Vec::new();
		for i in 0..threshold {
			comms.push(Commitment::new(poly[i as usize]));
		}

		// 4. send encrypted secret shares
		let round0_number: T::BlockNumber = T::RoundEnds::get()[0];
		let hash_round0 = <frame_system::Module<T>>::block_hash(round0_number);
		let signer =
			Signer::<T, T::AuthorityId>::all_accounts().with_filter([auth.into()].to_vec());
		if !signer.can_sign() {
			debug::info!("DKG ERROR NO KEYS FOR SIGNER!!!");
			return;
		}
		let tx_res = signer.send_signed_transaction(|_| {
			Call::post_secret_shares(enc_shares.clone(), comms.clone(), hash_round0)
		});

		for (acc, res) in &tx_res {
			match res {
				Ok(()) => debug::info!("DKG sending the secret shares by [{:?}]", acc.id,),
				Err(e) => debug::error!(
					"DKG [{:?}] Failed to submit transaction with secret shares: {:?}",
					acc.id,
					e
				),
			}
		}
	}

	// decrypt secret shares and send disputes to the chain
	fn handle_round2(block_number: T::BlockNumber) {
		const ALREADY_SET: () = ();

		let (my_ix, auth) = match Self::local_authority_key() {
			Some((ix, auth)) => {
				debug::info!(
					"DKG handle_round2 called at block: {:?} by authority: {:?}",
					block_number,
					ix,
				);
				(ix, auth)
			}
			None => {
				debug::info!(
					"DKG handle_round2 called at block: {:?} by non-authority, skipping",
					block_number
				);
				return;
			}
		};

		let val = StorageValueRef::persistent(b"dkw::secret_shares");
		let res = val.mutate(
			|last_set: Option<Option<Vec<Option<[u8; 32]>>>>| match last_set {
				Some(Some(_)) => Err(ALREADY_SET),
				_ => Ok(Vec::new()),
			},
		);

		if res.is_err() || res.unwrap().is_err() {
			debug::info!("DKG handle_round2 error in init store for secret_shares");
			return;
		}

		let n_members = Self::authorities().len();

		// 0. generate encryption keys
		let encryption_keys = Self::encryption_keys();

		// 1. decrypt shares, check commitments
		let mut shares = sp_std::vec![None; n_members];
		let mut disputes = Vec::new();

		for creator in 0..n_members {
			let ek = &encryption_keys[creator];
			if ek.is_none() || Self::encrypted_shares_lists()[creator][my_ix as usize].is_none() {
				// TODO no one have seen shares from this creator, we just skip it
				continue;
			}
			let encrypted_share = &Self::encrypted_shares_lists()[creator][my_ix as usize]
				.clone()
				.unwrap();
			let share = ek.as_ref().unwrap().decrypt(&encrypted_share);
			if share.is_none() {
				// TODO add proper proof and commitment verification
				disputes.push(creator as AuthIndex);
			} else {
				let share_data: [u8; 32] = share.unwrap()[..]
					.try_into()
					.expect("slice with incorrect length");
				shares[creator] = Some(share_data);
			}
		}

		// 2. save shares
		let res: Result<_, ()> = val.mutate(|_| Ok(shares));

		if res.is_err() || res.unwrap().is_err() {
			debug::info!("DKG handle_round2 error in setting shares");
			return;
		}

		// 3. send disputes
		let round1_number: T::BlockNumber = T::RoundEnds::get()[1];
		let hash_round1 = <frame_system::Module<T>>::block_hash(round1_number);

		let signer =
			Signer::<T, T::AuthorityId>::all_accounts().with_filter([auth.into()].to_vec());
		if !signer.can_sign() {
			debug::info!("DKG ERROR NO KEYS FOR SIGNER {:?}!!!", my_ix);
			return;
		}

		let tx_res =
			signer.send_signed_transaction(|_| Call::post_disputes(disputes.clone(), hash_round1));

		for (acc, res) in &tx_res {
			match res {
				Ok(()) => debug::info!("DKG sending the disputes by [{:?}]", acc.id,),
				Err(e) => debug::error!(
					"DKG [{:?}] Failed to submit transaction with disputes: {:?}",
					acc.id,
					e
				),
			}
		}
	}

	// TODO move all computations of public stuff to on_finalize
	// derivie local key pair and master verification key, and send master key to the chain
	fn handle_round3(block_number: T::BlockNumber) {
		const ALREADY_SET: () = ();

		// 0. Check if there are enough qualified nodes
		let threshold = Threshold::get();
		let qualified = Self::is_correct_dealer();
		let n_qualified = qualified.iter().map(|&v| v as u64).sum::<u64>();
		assert!(
			n_qualified >= threshold,
			"not enough qualified nodes: needs at least {}, got {}",
			threshold,
			n_qualified,
		);

		let (my_ix, auth) = match Self::local_authority_key() {
			Some((ix, auth)) => {
				debug::info!(
					"DKG handle_round3 called at block: {:?} by authority: {:?} qualified nodes {:?}",
					block_number,
					ix,
					qualified,
				);
				(ix, auth)
			}
			None => {
				debug::info!(
					"DKG handle_round3 called at block: {:?} by non-authority, skipping",
					block_number
				);
				return;
			}
		};

		// 1. derive local threshold secret
		let val = StorageValueRef::persistent(b"dkw::threshold_secret_key");
		let res = val.mutate(|last_set: Option<Option<[u8; 32]>>| match last_set {
			Some(Some(_)) => Err(ALREADY_SET),
			_ => {
				debug::info!("DKG generating master_key");
				Ok([0; 32])
			}
		});

		if res.is_err() || res.unwrap().is_err() {
			debug::info!("DKG handle_round3 error in init store for threshold pair");
			return;
		}

		let secret = StorageValueRef::persistent(b"dkw::secret_shares")
			.get::<Vec<Option<[u8; 32]>>>()
			.unwrap()
			.unwrap()
			.iter()
			.enumerate()
			.filter_map(|(ix, &share)| match (qualified[ix], share) {
				(false, _) | (true, None) => None,
				(true, Some(share)) => Some(Scalar::from_bytes(&share).unwrap()),
			})
			.fold(Scalar::zero(), |a, b| a + b);

		let res: Result<_, ()> = val.mutate(|_| {
			let raw_secret = secret.to_bytes();
			debug::info!("DKG created secret key {:?}", raw_secret);
			Ok(raw_secret)
		});

		if res.is_err() || res.unwrap().is_err() {
			debug::info!("DKG handle_round3 error in ssecret");
			return;
		}

		// 2. derive and post master key and verification keys
		let comms = Self::committed_polynomilas()
			.into_iter()
			.enumerate()
			.filter(|(ix, comms)| qualified[*ix] && !comms.is_empty())
			.map(|(_, comms)| comms[0].clone())
			.collect();

		let mvk = Commitment::derive_key(comms);

		debug::info!("\n\ngenerated master key {:?}\n", mvk);

		let n_members = Self::authorities().len();
		let mut vks = Vec::new();
		for ix in 0..n_members {
			let x = &Scalar::from(ix as u64 + 1);
			let part_keys = (0..n_members)
				.filter(|dealer| {
					qualified[*dealer] && !Self::committed_polynomilas()[*dealer].is_empty()
				})
				.map(|dealer| Commitment::poly_eval(&Self::committed_polynomilas()[dealer], x))
				.collect();
			vks.push(Commitment::derive_key(part_keys))
		}

		let round2_number: T::BlockNumber = T::RoundEnds::get()[2];
		let hash_round2 = <frame_system::Module<T>>::block_hash(round2_number);

		let signer =
			Signer::<T, T::AuthorityId>::all_accounts().with_filter([auth.into()].to_vec());
		if !signer.can_sign() {
			debug::info!("DKG ERROR NO KEYS FOR SIGNER {:?}!!!", my_ix);
			return;
		}

		let tx_res = signer.send_signed_transaction(|_| {
			Call::post_verification_keys(mvk.clone(), vks.clone(), hash_round2)
		});

		for (acc, res) in &tx_res {
			match res {
				Ok(()) => debug::info!("DKG sending the master key by [{:?}]", acc.id,),
				Err(e) => debug::error!(
					"DKG [{:?}] Failed to submit transaction with master key: {:?}",
					acc.id,
					e
				),
			}
		}
	}

	fn authority_index(who: T::AccountId) -> Option<AuthIndex> {
		Self::authorities()
			.into_iter()
			.position(|auth| Into::<T::Public>::into(auth.clone()).into_account() == who)
			.map(|p| p as AuthIndex)
	}

	fn local_authority_key() -> Option<(AuthIndex, T::AuthorityId)> {
		let local_keys = T::AuthorityId::all();

		Self::authorities()
			.into_iter()
			.enumerate()
			.find_map(move |(index, authority)| {
				local_keys
					.clone()
					.into_iter()
					.position(|local_key| authority == local_key)
					.map(|location| (index as AuthIndex, local_keys[location].clone()))
			})
	}

	fn encryption_keys() -> Vec<Option<EncryptionKey>> {
		let raw_secret = StorageValueRef::persistent(b"dkw::enc_key")
			.get()
			.unwrap()
			.unwrap();
		let secret = Scalar::from_raw(raw_secret);
		let mut keys = Vec::new();
		Self::encryption_pks()
			.iter()
			.for_each(|enc_pk| match enc_pk {
				Some(enc_pk) => keys.push(Some(enc_pk.to_encryption_key(secret))),
				None => keys.push(None),
			});

		keys
	}

	pub fn master_verification_key() -> Option<VerifyKey> {
		match MasterVerificationKey::exists() {
			true => Some(MasterVerificationKey::get()),
			false => None,
		}
	}

	pub fn my_authority_index() -> Option<AuthIndex> {
		Self::local_authority_key().map(|(my_ix, _)| my_ix)
	}

	pub fn master_key_ready() -> T::BlockNumber {
		// this is the round number when the outside world expects master key to be ready
		T::MasterKeyReady::get()
	}

	pub fn public_keybox_parts() -> Option<(AuthIndex, Vec<VerifyKey>, VerifyKey, u64)> {
		let ix = match Self::my_authority_index() {
			Some(ix) => ix,
			None => return None,
		};

		let verification_keys = match Self::verification_keys() {
			Some(keys) => keys,
			None => return None,
		};

		let master_key = match Self::master_verification_key() {
			Some(key) => key,
			None => return None,
		};

		let threshold = Self::threshold();

		Some((ix, verification_keys, master_key, threshold))
	}

	pub fn verification_keys() -> Option<Vec<VerifyKey>> {
		if !VerificationKeys::exists() {
			return None;
		}

		Some(VerificationKeys::get())
	}

	pub fn threshold() -> u64 {
		Threshold::get()
	}
}

impl<T: Trait> sp_runtime::BoundToRuntimeAppPublic for Module<T> {
	type Public = T::AuthorityId;
}

fn u8_array_to_raw_scalar(bytes: [u8; 32]) -> RawScalar {
	let mut out = [0u64; 4];
	for i in 0..4 {
		out[i] = u64::from_le_bytes(
			bytes[8 * i..8 * (i + 1)]
				.try_into()
				.expect("slice with incorrect length"),
		);
	}
	out
}

fn gen_raw_scalar() -> RawScalar {
	u8_array_to_raw_scalar(sp_io::offchain::random_seed())
}

fn gen_poly_coeffs(deg: u64) -> Vec<RawScalar> {
	let mut coeffs = Vec::new();
	for _ in 0..deg + 1 {
		coeffs.push(gen_raw_scalar());
	}

	coeffs
}

fn poly_eval(coeffs: &Vec<Scalar>, x: &Scalar) -> Scalar {
	let mut eval = Scalar::zero();
	for coeff in coeffs.iter().rev() {
		eval *= x;
		eval += coeff;
	}

	eval
}
