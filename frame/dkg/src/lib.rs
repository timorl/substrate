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

use frame_support::{debug, decl_module, decl_storage, dispatch::DispatchResult, Parameter};
use frame_system::{
	ensure_signed,
	offchain::{AppCrypto, CreateSignedTransaction, SendSignedTransaction, Signer},
};
use sp_runtime::{offchain::storage::StorageValueRef, traits::Member, RuntimeAppPublic};
use sp_std::{convert::TryInto, vec::Vec};

use sp_dkg::EncryptionPublicKey;

// TODO maybe we could control the round boundaries with events?
// These should be perhaps in some config in the genesis block?
pub const END_ROUND_0: u32 = 5;
pub const END_ROUND_1: u32 = 10;
pub const END_ROUND_2: u32 = 15;

// n is the number of nodes in the committee
// node indices are 1-based: 1, 2, ..., n
// t is the threshold: it is necessary and sufficient to have t shares to combine
// the degree of the polynomial is thus t-1

// A commitment to a polynomial p(x) := p_0 + p_1 x + ... + p_{t-1} x^{t-1}
// Should be a t-tuple of elements of G2=<g2>: g2^{p_0}, g2^{p_1}, ..., g2^{p_{t-1}}
// #[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug)]
// pub struct CommittedPoly {}

// Should be an n-tuple of suitably encoded scalars: enc_1(s_1), ..., enc_{n}(s_n)
// where s_i = p(i) for a polynomial p(x) of degree t-1
// #[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug)]
// pub struct EncShareList {
// for milestone 2 we do not encrypt
//shares: Vec<Scalar>,
// }

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
		+ From<Self::Public>;
	//type AuthorityId: Member + Parameter + RuntimeAppPublic + Default;

	/// The overarching dispatch call type.
	type Call: From<Call<Self>>;
}

// An index of the authority on the list of validators.
pub type AuthIndex = u32;

decl_storage! {
	trait Store for Module<T: Trait> as DKGWorker {

		// round 0

		// EncryptionPKs: Vec<Option<EncryptionPubKey>>;
		EncryptionPKs get(fn encryption_pks): map hasher(twox_64_concat) AuthIndex => EncryptionPublicKey;


		// round 1

		// ith entry is the CommitedPoly of (i+1)th node submitted in a tx in round 1
		// CommittedPolynomials: Vec<Option<CommittedPoly>>;
		CommittedPolynomials: Vec<Option<Vec<u8>>>;

		// ith entry is the EncShareList of (i+1)th node submitted in a tx in round 1
		// EncryptedSharesLists: Vec<Option<EncShareList>>;
		EncryptedSharesLists: Vec<Option<Vec<u8>>>;


		// round 2

		// list of n bools: ith is true <=> both the below conditions are satisfied:
		// 1) (i+1)th node succesfully participated in round 0 and round 1
		// 2) there was no succesful dispute that proves cheating of (i+1)th node in round 2
		IsCorrectDealer: Vec<bool>;

		/// The current authorities
		pub Authorities get(fn authorities): Vec<T::AuthorityId>;
	}
	add_extra_genesis {
		config(authorities): Vec<T::AuthorityId>;
		build(|config| Module::<T>::initialize_authorities(&config.authorities))
	}
}

decl_module! {
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {

		// TODO: we need to be careful with weights -- for now they are 0, but need to think about them later
		#[weight = 0]
		pub fn post_encryption_key(origin, pk: EncryptionPublicKey, ix: AuthIndex) -> DispatchResult {
			let now = <frame_system::Module<T>>::block_number();
			let _ = ensure_signed(origin)?;
			debug::info!("DKG POST_ENCRYPTION_KEY CALL: BLOCK_NUMBER: {:?} WHO {:?}", now, ix);
			EncryptionPKs::insert(ix, pk);

			Ok(())
		}

		#[weight = 0]
		pub fn round1(origin, comm_poly: Vec<u8>, shares: Vec<u8>, hash_round0: T::Hash) -> DispatchResult {
			let _who = ensure_signed(origin)?;
			// logic for receiving round1 tx
			Ok(())
		}

		#[weight = 0]
		pub fn round2(origin, disputes: Vec<Vec<u8>>, hash_round1: T::Hash) -> DispatchResult {
			let _who = ensure_signed(origin)?;
			// logic for receiving round2 tx
			Ok(())
		}


		fn offchain_worker(block_number: T::BlockNumber) {
			debug::info!("DKG Hello World from offchain workers!");

			if block_number < END_ROUND_0.into()  {
					Self::handle_round0(block_number);
			} else if block_number < END_ROUND_1.into() {
				// implement creating tx for round 1
					Self::handle_round1(block_number);
			} else if block_number < END_ROUND_2.into() {
				// implement creating tx for round 2
					Self::handle_round2(block_number);
			}
		}
	}
}

// Most of the functions are moved outside of the `decl_module!` macro.
//
// This greatly helps with error messages, as the ones inside the macro
// can sometimes be hard to debug.
impl<T: Trait> Module<T> {
	fn initialize_authorities(authorities: &[T::AuthorityId]) {
		if !authorities.is_empty() {
			debug::info!("DKG AUTHIRITIES initialize_authorities {:?}", authorities);
			assert!(
				<Authorities<T>>::get().is_empty(),
				"Authorities are already initialized!"
			);
			let mut authorities = authorities.to_vec();
			authorities.sort();
			<Authorities<T>>::put(&authorities);
		}
	}

	fn _my_id() -> Option<usize> {
		// TODO: I give up:( I don't know how to use values in authorities
		// let authorities = Self::authorities().iter().map();

		// let local_keys =
		// 	<T::AuthorityId as AppCrypto<T::Public, T::Signature>>::RuntimeAppPublic::all();
		// local_keys
		// 	.into_iter()
		// 	.filter_map(|authority| {
		// 		let generic_public = <T::AuthorityId as AppCrypto<T::Public, T::Signature>>::GenericPublic::from(authority);

		// 		authorities.binary_search(&authority.into()).ok()})
		// 	.next()
		None
	}

	fn handle_round0(block_number: T::BlockNumber) {
		debug::info!("DKG handle_round0 called at block: {:?}", block_number);
		// TODO: encrypt the key
		const ALREADY_SET: () = ();

		let val = StorageValueRef::persistent(b"dkw::enc_key");
		let res = val.mutate(|last_set: Option<Option<[u64; 4]>>| match last_set {
			Some(Some(_)) => Err(ALREADY_SET),
			_ => {
				let seed = sp_io::offchain::random_seed();
				let mut scalar_raw = [0u64; 4];
				for i in 0..4 {
					scalar_raw[i] = u64::from_le_bytes(
						seed[8 * i..8 * (i + 1)]
							.try_into()
							.expect("slice with incorrect length"),
					);
				}
				debug::info!("DKG setting a new encryption key: {:?}", scalar_raw);
				Ok(scalar_raw)
			}
		});

		if let Ok(Ok(raw_scalar)) = res {
			// send tx with key
			let signer = Signer::<T, T::AuthorityId>::all_accounts();
			if !signer.can_sign() {
				debug::info!("DKG ERROR NO KEYS FOR SIGNER!!!");
				// return Err(
				// 	"No local accounts available. Consider adding one via `author_insertKey` RPC."
				// )?
			}
			let enc_pk = EncryptionPublicKey::from_raw_scalar(raw_scalar);
			let tx_res = signer.send_signed_transaction(|account| {
				let ix = Self::authority_index(account.public.clone().into());
				// TODO add signature for ix
				Call::post_encryption_key(enc_pk.clone(), ix)
			});

			for (acc, res) in &tx_res {
				match res {
					Ok(()) => debug::info!(
						"DKG sending the encryption key: {:?} by [{:?}]",
						enc_pk,
						acc.id,
					),
					Err(e) => {
						debug::error!("DKG [{:?}] Failed to submit transaction: {:?}", acc.id, e)
					}
				}
			}
		}
	}

	fn authority_index(account: T::AuthorityId) -> AuthIndex {
		let authorities = <Authorities<T>>::get();

		authorities
			.into_iter()
			.position(|auth| auth == account)
			.map(|ix| ix as AuthIndex)
			.unwrap()
	}

	fn _local_authority_keys() -> impl Iterator<Item = (u32, T::AuthorityId)> {
		let authorities = <Authorities<T>>::get();
		let local_keys = T::AuthorityId::all();

		authorities
			.into_iter()
			.enumerate()
			.filter_map(move |(index, authority)| {
				local_keys
					.clone()
					.into_iter()
					.position(|local_key| authority == local_key)
					.map(|location| (index as u32, local_keys[location].clone()))
			})
	}

	fn handle_round1(block_number: T::BlockNumber) {
		debug::info!("DKG handle_round1 called at block: {:?}", block_number);
	}

	fn handle_round2(block_number: T::BlockNumber) {
		debug::info!("DKG handle_round2 called at block: {:?}", block_number);
	}
}

// TODO check if needed
impl<T: Trait> sp_runtime::BoundToRuntimeAppPublic for Module<T> {
	type Public = T::AuthorityId;
}
