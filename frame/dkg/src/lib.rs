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

use codec::Encode;
use frame_support::{debug, decl_module, decl_storage, traits::Get, Parameter};
use frame_system::{
	ensure_signed,
	offchain::{CreateSignedTransaction, SubmitTransaction},
};
use sp_runtime::{
	offchain::storage::StorageValueRef,
	traits::Member,
	transaction_validity::{
		InvalidTransaction, TransactionPriority, TransactionSource, TransactionValidity,
		ValidTransaction,
	},
	RuntimeAppPublic,
};
use sp_std::{convert::TryInto, vec::Vec};

use sp_dkg::{Commitment, EncryptionPublicKey};

// TODO maybe we could control the round boundaries with events?
// These should be perhaps in some config in the genesis block?
pub const END_ROUND_0: u32 = 5;
pub const END_ROUND_1: u32 = 10;
pub const END_ROUND_2: u32 = 15;
pub const END_ROUND_3: u32 = 15;

// TODO do we add protection against biasing

// n is the number of nodes in the committee
// node indices are 1-based: 1, 2, ..., n
// t is the threshold: it is necessary and sufficient to have t shares to combine
// the degree of the polynomial is thus t-1

// Should be a decrypted share (milestone 2) + along with a proof of descryption (only in milestone 3)
// #[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug)]
// pub struct DisputeAgainstDealer {
// }

// TODO the following and the definition of AuthorityId probably needs a refactor. The problem is
// that the trait CreateSignedTransaction needed by Signer imposes that AuthorityId must extend
// AppCrypto and on the other hand if we want to use AuthorityId as public keys of validators, i.e.
// sign messages, determine index in the validator list and simply be their ids, then we need to
// extend AuthorityId with RuntimeAppPublic as keys in keystore are stored as RuntimeAppPublic.
pub mod crypto {
	use codec::{Decode, Encode};
	use sp_runtime::{MultiSignature, MultiSigner};

	//pub type DKGId = sp_dkg::crypto::Public;
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
	type AuthorityId: Member + Parameter + RuntimeAppPublic + Default + Ord;

	/// The overarching dispatch call type.
	type Call: From<Call<Self>>;

	/// A configuration for base priority of unsigned transactions.
	///
	/// This is exposed so that it can be tuned for particular runtime, when
	/// multiple pallets send unsigned transactions.
	type UnsignedPriority: Get<TransactionPriority>;
}

// An index of the authority on the list of validators.
pub type AuthIndex = u64;

decl_storage! {
	trait Store for Module<T: Trait> as DKGWorker {

		// round 0

		// EncryptionPKs: Vec<Option<EncryptionPubKey>>;
		EncryptionPKs get(fn encryption_pks): map hasher(twox_64_concat) AuthIndex => EncryptionPublicKey;


		// round 1

		// ith entry is the CommitedPoly of (i+1)th node submitted in a tx in round 1
		// CommittedPolynomials: Vec<Option<CommittedPoly>>;
		CommittedPolynomials get(fn committed_polynomilas): map hasher(twox_64_concat) AuthIndex => Vec<Commitment>;

		// ith entry is the EncShareList of (i+1)th node submitted in a tx in round 1
		// EncryptedSharesLists: Vec<Option<EncShareList>>;
		EncryptedSharesLists get(fn encrypted_shares_lists): map hasher(twox_64_concat) AuthIndex => Vec<Vec<u8>>;


		// round 2

		// ith entry is a list of disputes against dealers raised by node i submitted in round 2
		DisputesAgainstDealer get(fn disputes_against_dealer): map hasher(twox_64_concat) AuthIndex => Vec<AuthIndex>;

		// list of n bools: ith is true <=> both the below conditions are satisfied:
		// 1) (i+1)th node succesfully participated in round 0 and round 1
		// 2) there was no succesful dispute that proves cheating of (i+1)th node in round 2
		IsCorrectDealer: Vec<bool>;

		/// The current authorities
		pub Authorities get(fn authorities): Vec<T::AuthorityId>;

		/// The threshold of BLS scheme
		pub Threshold: u32;
	}
	add_extra_genesis {
		config(authorities): Vec<T::AuthorityId>;
		config(threshold): u32;
		build(|config| {
			Module::<T>::initialize_authorities(&config.authorities);
			Module::<T>::set_threshold(config.threshold);
		})
	}
}

decl_module! {
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {

		// TODO: we need to be careful with weights -- for now they are 0, but need to think about them later
		#[weight = 0]
		pub fn post_encryption_key(
			origin,
			pk: EncryptionPublicKey,
			ix: AuthIndex,
			// since signature verification is done in `validate_unsigned`
			// we can skip doing it here again.
			_signature: <T::AuthorityId as RuntimeAppPublic>::Signature
		) {
			// TODO should we block receiving pk after END_ROUND_0?
			let now = <frame_system::Module<T>>::block_number();
			let _ = ensure_signed(origin)?;
			debug::RuntimeLogger::init();
			debug::info!("DKG POST_ENCRYPTION_KEY CALL: BLOCK_NUMBER: {:?} WHO {:?}", now, ix);
			EncryptionPKs::insert(ix, pk);
		}

		#[weight = 0]
		pub fn post_secret_shares(origin, shares: Vec<Vec<u8>>, comm_poly: Vec<Commitment>, ix: AuthIndex, hash_round0: T::Hash) {
			// TODO should we block receiving shares after END_ROUND_1?
			let now = <frame_system::Module<T>>::block_number();
			debug::RuntimeLogger::init();
			debug::info!("DKG POST_SECRET_SHARES CALL: BLOCK_NUMBER: {:?} WHO {:?}", now, ix);
			let _ = ensure_signed(origin)?;
			let round0_number: T::BlockNumber = END_ROUND_0.into();
			let correct_hash_round0 = <frame_system::Module<T>>::block_hash(round0_number);
			if hash_round0 != correct_hash_round0 {
				debug::info!("DKG POST_SECRET_SHARES CALL: received secret shares for wrong hash_round0:
					{:?} instead of {:?} from {:?}",hash_round0, correct_hash_round0, ix);
			} else {
				EncryptedSharesLists::insert(ix, shares);
				CommittedPolynomials::insert(ix, comm_poly);
			}
		}

		#[weight = 0]
		pub fn post_disputes(origin, disputes: Vec<AuthIndex>, ix: AuthIndex, hash_round1: T::Hash) {
			let now = <frame_system::Module<T>>::block_number();
			debug::RuntimeLogger::init();
			debug::info!("DKG POST_DISPUTES CALL: BLOCK_NUMBER: {:?} WHO {:?}", now, ix);
			let _ = ensure_signed(origin)?;
			let round1_number: T::BlockNumber = END_ROUND_1.into();
			let correct_hash_round1 = <frame_system::Module<T>>::block_hash(round1_number);
			if hash_round1 != correct_hash_round1 {
				debug::info!("DKG POST_DISPUTES CALL: received disputes for wrong hash_round1:
					{:?} instead of {:?} from {:?}",hash_round1, correct_hash_round1, ix);
			} else {
				DisputesAgainstDealer::insert(ix, disputes);
			}
		}

		fn offchain_worker(block_number: T::BlockNumber) {
			debug::info!("DKG Hello World from offchain workers!");

			if block_number < END_ROUND_0.into()  {
					Self::handle_round0(block_number);
			}
			//else if block_number < END_ROUND_1.into() {
			//	// implement creating tx for round 1
			//		Self::handle_round1(block_number);
			//} else if block_number < END_ROUND_2.into() {
			//	// implement creating tx for round 2
			//		Self::handle_round2(block_number);
			//}else if block_number < END_ROUND_3.into() {
			//	// implement creating tx for round 3
			//		Self::handle_round3(block_number);
			//}
		}
	}
}

// In round 0 we use persistent storage as we want to generate only one encryption key
// In subsecuent rounds we use local storage as the objects in subsecuent rounds may differ due to
// forks.
impl<T: Trait> Module<T> {
	fn initialize_authorities(authorities: &[T::AuthorityId]) {
		if !authorities.is_empty() {
			debug::info!("DKG GENESIS initialize_authorities {:?}", authorities);
			assert!(
				<Authorities<T>>::get().is_empty(),
				"Authorities are already initialized!"
			);
			let mut authorities = authorities.to_vec();
			authorities.sort();
			<Authorities<T>>::put(&authorities);
		}
	}

	fn set_threshold(threshold: u32) {
		let n_members = Self::authorities().len();
		assert!(
			0 < threshold && threshold <= n_members as u32,
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

	fn handle_round0(block_number: T::BlockNumber) {
		debug::info!("DKG handle_round0 called at block: {:?}", block_number);
		// TODO: encrypt the key in the local store?
		const ALREADY_SET: () = ();

		let val = StorageValueRef::persistent(b"dkw::enc_key");
		let res = val.mutate(|last_set: Option<Option<[u64; 4]>>| match last_set {
			Some(Some(_)) => Err(ALREADY_SET),
			_ => {
				let scalar_raw = gen_raw_scalar();

				debug::info!("DKG setting a new encryption key: {:?}", scalar_raw);
				Ok(scalar_raw)
			}
		});

		if let Ok(Ok(raw_scalar)) = res {
			if let Some((ix, key)) = Self::local_authority_key() {
				let enc_pk = EncryptionPublicKey::from_raw_scalar(raw_scalar);

				// TODO add signature for ix
				let signature = key.sign(&Encode::encode(&ix)).unwrap();
				let call = Call::post_encryption_key(enc_pk.clone(), ix, signature);

				match SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into()) {
					Ok(()) => debug::info!("DKG OK submit_unsigned_transaction: {:?}", ix),
					Err(()) => debug::info!("DKG ERR submit_unsigned_transaction: {:?}", ix),
				}
			}
		} else {
		}
	}

	fn _authority_index(account: T::AuthorityId) -> AuthIndex {
		let authorities = <Authorities<T>>::get();

		authorities
			.into_iter()
			.position(|auth| auth == account)
			.map(|ix| ix as AuthIndex)
			.unwrap()
	}

	fn local_authority_key() -> Option<(AuthIndex, T::AuthorityId)> {
		let authorities = <Authorities<T>>::get();
		let local_keys = T::AuthorityId::all();

		authorities
			.into_iter()
			.enumerate()
			.find_map(move |(index, authority)| {
				local_keys
					.clone()
					.into_iter()
					.position(|local_key| authority == local_key)
					.map(|location| (index as u64, local_keys[location].clone()))
			})
	}

	//	fn handle_round1(block_number: T::BlockNumber) {
	//		debug::info!("DKG handle_round1 called at block: {:?}", block_number);
	//		const ALREADY_SET: () = ();
	//		// TODO we don't generate shares for parties that didn't post their encryption keys. OK?
	//
	//		// 0. generate secrets
	//		let n_members = <Authorities<T>>::get().len() as u64;
	//		let threshold = Threshold::get();
	//		let val = StorageValueRef::local(b"dkw::secret_poly");
	//		let res = val.mutate(|last_set: Option<Option<Vec<[u64; 4]>>>| match last_set {
	//			Some(Some(_)) => Err(ALREADY_SET),
	//			_ => {
	//				let poly = gen_poly_coeffs(threshold - 1);
	//
	//				debug::info!("DKG generating secret polynomial");
	//				Ok(poly)
	//			}
	//		});
	//
	//		// TODO: meh borrow checker
	//		if res.is_err() {
	//			return;
	//		}
	//		let res = res.unwrap();
	//		if res.is_err() {
	//			return;
	//		}
	//		let res = res.unwrap();
	//		let poly = &res.into_iter().map(|raw| Scalar::from_raw(raw)).collect();
	//
	//		// 1. generate encryption keys
	//		let raw_secret = StorageValueRef::persistent(b"dkw::enc_key")
	//			.get()
	//			.unwrap()
	//			.unwrap();
	//		let secret = Scalar::from_raw(raw_secret);
	//		let mut encryption_keys = Vec::new();
	//		for i in 0..n_members {
	//			if EncryptionPKs::contains_key(i) {
	//				let enc_pk = Self::encryption_pks(i);
	//				encryption_keys.push(Some(enc_pk.to_encryption_key(secret)));
	//			} else {
	//				encryption_keys.push(None);
	//			}
	//		}
	//
	//		// 2. generate secret shares
	//		let mut enc_shares = Vec::new();
	//
	//		for id in 0..n_members {
	//			if let Some(ref enc_key) = encryption_keys[id as usize] {
	//				let x = &Scalar::from_raw([id + 1, 0, 0, 0]);
	//				let share = poly_eval(poly, x);
	//				let share_data = share.to_bytes().to_vec();
	//				enc_shares.push(enc_key.encrypt(&share_data));
	//			}
	//		}
	//
	//		// 3. generate commitments
	//		let mut comms = Vec::new();
	//		for id in 0..threshold {
	//			comms.push(Commitment::new(poly[id as usize]));
	//		}
	//
	//		// 4. send encrypted secret shares
	//		let round0_number: T::BlockNumber = END_ROUND_0.into();
	//		let hash_round0 = <frame_system::Module<T>>::block_hash(round0_number);
	//		let signer = Signer::<T, T::AuthorityId>::all_accounts();
	//		if !signer.can_sign() {
	//			debug::info!("DKG ERROR NO KEYS FOR SIGNER!!!");
	//			// return Err(
	//			// 	"No local accounts available. Consider adding one via `author_insertKey` RPC."
	//			// )?
	//		}
	//		let tx_res = signer.send_signed_transaction(|account| {
	//			let ix = Self::authority_index(account.public.clone().into());
	//			// TODO add signature for ix
	//			Call::post_secret_shares(enc_shares.clone(), comms.clone(), ix, hash_round0)
	//		});
	//
	//		for (acc, res) in &tx_res {
	//			match res {
	//				Ok(()) => debug::info!("DKG sending the secret shares by [{:?}]", acc.id,),
	//				Err(e) => debug::error!(
	//					"DKG [{:?}] Failed to submit transaction with secret shares: {:?}",
	//					acc.id,
	//					e
	//				),
	//			}
	//		}
	//	}
	//
	//	fn handle_round2(block_number: T::BlockNumber) {
	//		const ALREADY_SET: () = ();
	//		debug::info!("DKG handle_round2 called at block: {:?}", block_number);
	//		let val = StorageValueRef::local(b"dkw::secret_shares");
	//		let res = val.mutate(
	//			|last_set: Option<Option<Vec<(AuthIndex, Vec<[u64; 4]>)>>>| match last_set {
	//				Some(Some(_)) => Err(ALREADY_SET),
	//				_ => Ok(Vec::new()),
	//			},
	//		);
	//
	//		if res.is_err() && res.unwrap().is_err() {
	//			debug::info!("DKG handle_round2 error in retrieving list of raised disputes");
	//			return;
	//		}
	//
	//		let n_members = <Authorities<T>>::get().len() as u64;
	//
	//		// 0. generate encryption keys
	//		let raw_secret = StorageValueRef::persistent(b"dkw::enc_key")
	//			.get()
	//			.unwrap()
	//			.unwrap();
	//		let secret = Scalar::from_raw(raw_secret);
	//		let mut encryption_keys = Vec::new();
	//		for i in 0..n_members {
	//			if EncryptionPKs::contains_key(i) {
	//				let enc_pk = Self::encryption_pks(i);
	//				encryption_keys.push(Some(enc_pk.to_encryption_key(secret)));
	//			} else {
	//				encryption_keys.push(None);
	//			}
	//		}
	//
	//		// 1. decrypt shares, check commitments
	//		let mut all_shares = Vec::<(AuthIndex, Vec<[u64; 4]>)>::new();
	//		let mut all_disputes = Vec::new();
	//		for (my_ix, auth) in Self::local_authority_keys() {
	//			debug::info!("DKG handle_round2 for authority: {:?}: {:?}", my_ix, auth);
	//
	//			let mut shares: Vec<[u64; 4]> = Vec::new();
	//			let mut disputes = Vec::new();
	//
	//			for creator in 0..n_members {
	//				let ek = &encryption_keys[creator as usize];
	//				if ek.is_none() || !EncryptedSharesLists::contains_key(creator) {
	//					// TODO no one have seen shares from this creator, we just skip it
	//					continue;
	//				}
	//				// TODO add commitment verification
	//				let _commitment = &CommittedPolynomials::get(creator)[my_ix as usize];
	//				let encrypted_share = &EncryptedSharesLists::get(creator)[my_ix as usize];
	//				let share = ek.as_ref().unwrap().decrypt(&encrypted_share);
	//				if share.is_none() {
	//					// TODO add proper proof and commitment verification
	//					disputes.push(creator);
	//				} else {
	//					let bytes: [u8; 32] = share.unwrap()[..]
	//						.try_into()
	//						.expect("slice with incorrect length");
	//					let share_data = u8_to_u64(bytes);
	//					shares.push(share_data);
	//				}
	//			}
	//
	//			all_shares.push((my_ix, shares));
	//			all_disputes.push((my_ix, disputes));
	//		}
	//
	//		// 2. save shares
	//		let res: Result<_, ()> = val.mutate(|_| Ok(all_shares));
	//
	//		if res.is_err() && res.unwrap().is_err() {
	//			debug::info!("DKG handle_round2 error in retrieving list of raised disputes");
	//			return;
	//		}
	//
	//		// 3. send disputes
	//		let round1_number: T::BlockNumber = END_ROUND_1.into();
	//		let hash_round1 = <frame_system::Module<T>>::block_hash(round1_number);
	//
	//		for (my_ix, disputes) in all_disputes.into_iter() {
	//			let my_account = Self::authorities()[my_ix as usize].clone();
	//			let signer = Signer::<T, T::AuthorityId>::all_accounts()
	//				.with_filter([my_account.into()].to_vec());
	//			if !signer.can_sign() {
	//				debug::info!("DKG ERROR NO KEYS FOR SIGNER {:?}!!!", my_ix,);
	//			}
	//
	//			let tx_res = signer.send_signed_transaction(|_| {
	//				// TODO add signature for ix
	//				Call::post_disputes(disputes.clone(), my_ix, hash_round1)
	//			});
	//
	//			for (acc, res) in &tx_res {
	//				match res {
	//					Ok(()) => debug::info!("DKG sending the disputes by [{:?}]", acc.id,),
	//					Err(e) => debug::error!(
	//						"DKG [{:?}] Failed to submit transaction with disputes: {:?}",
	//						acc.id,
	//						e
	//					),
	//				}
	//			}
	//		}
	//	}
	//
	//	fn handle_round3(block_number: T::BlockNumber) {
	//		const ALREADY_SET: () = ();
	//		debug::info!("DKG handle_round3 called at block: {:?}", block_number);
	//		let val = StorageValueRef::persistent(b"dkw::master_key");
	//		let res = val.mutate(|last_set: Option<Option<bool>>| match last_set {
	//			Some(Some(_)) => Err(ALREADY_SET),
	//			_ => {
	//				debug::info!("DKG generating master_key");
	//				Ok(true)
	//			}
	//		});
	//
	//		if res.is_err() || res.unwrap().is_err() {
	//			return;
	//		}
	//
	//		let n_members = <Authorities<T>>::get().len() as u64;
	//		let _threshold = Threshold::get();
	//
	//		// 1. determine the set of share providers
	//		let mut share_providers = Vec::new();
	//		for i in 0..n_members {
	//			share_providers.push(i);
	//		}
	//	}
}

impl<T: Trait> sp_runtime::BoundToRuntimeAppPublic for Module<T> {
	type Public = T::AuthorityId;
}

impl<T: Trait> frame_support::unsigned::ValidateUnsigned for Module<T> {
	type Call = Call<T>;

	fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
		if let Call::post_encryption_key(_pk, ix, signature) = call {
			// check if session index is correct
			//let current_session = <pallet_session::Module<T>>::current_index();
			//if session_index != current_session {
			//	return InvalidTransaction::Stale.into();
			//}

			// verify that the incoming (unverified) pubkey is actually an authority id
			let keys = Authorities::<T>::get();
			let authority_id = match keys.get(*ix as usize) {
				Some(id) => id,
				None => return InvalidTransaction::BadProof.into(),
			};

			// check signature (this is expensive so we do it last).
			let signature_valid = authority_id.verify(&Encode::encode(ix), &signature);

			if !signature_valid {
				return InvalidTransaction::BadProof.into();
			}

			debug::info!("DKG VALIDATED!! AUTHOR {:?}", ix);
			ValidTransaction::with_tag_prefix("DKG")
				.priority(T::UnsignedPriority::get())
				.and_provides(authority_id)
				.propagate(true)
				.build()
		} else {
			InvalidTransaction::Call.into()
		}
	}
}

fn u8_to_u64(bytes: [u8; 32]) -> [u64; 4] {
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

fn gen_raw_scalar() -> [u64; 4] {
	u8_to_u64(sp_io::offchain::random_seed())
}

// fn gen_poly_coeffs(deg: u32) -> Vec<[u64; 4]> {
// 	let mut coeffs = Vec::new();
// 	for _ in 0..deg + 1 {
// 		coeffs.push(gen_raw_scalar());
// 	}
//
// 	coeffs
// }
//
// fn poly_eval(coeffs: &Vec<Scalar>, x: &Scalar) -> Scalar {
// 	let mut eval = Scalar::zero();
// 	for coeff in coeffs.iter() {
// 		eval *= x;
// 		eval += coeff;
// 	}
//
// 	eval
// }
