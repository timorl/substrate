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

// use codec::{Decode, Encode};
use frame_support::{debug, decl_module, decl_storage, dispatch::DispatchResult};
use frame_system::{
	ensure_signed,
	offchain::{AppCrypto, CreateSignedTransaction, SendSignedTransaction, Signer},
};
use sp_runtime::offchain::storage::StorageValueRef;
use sp_std::{convert::TryInto, vec::Vec};

use sp_dkg::EncryptionPublicKey;

// TODO maybe we could control the round boundaries with events?
// These should be perhaps in some config in the genesis block?
pub const END_ROUND_0: u32 = 5;
pub const END_ROUND_1: u32 = 10;
pub const END_ROUND_2: u32 = 15;

pub mod crypto {
	use sp_runtime::{MultiSignature, MultiSigner};

	pub struct DKGId;
	impl frame_system::offchain::AppCrypto<MultiSigner, MultiSignature> for DKGId {
		type RuntimeAppPublic = sp_dkg::crypto::Public;
		type GenericSignature = sp_core::sr25519::Signature;
		type GenericPublic = sp_core::sr25519::Public;
	}
}

pub trait Trait: CreateSignedTransaction<Call<Self>> {
	/// The identifier type for an offchain worker.
	type AuthorityId: AppCrypto<Self::Public, Self::Signature>;

	/// The overarching dispatch call type.
	type Call: From<Call<Self>>;
}

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

decl_storage! {
	trait Store for Module<T: Trait> as DKGWorker {

		// round 0

		FinishedRound0: bool;
		// EncryptionPKs: Vec<Option<EncryptionPubKey>>;
		EncryptionPKs: Vec<Option<EncryptionPublicKey>>;


		// round 1

		FinishedRound1: bool;
		// ith entry is the CommitedPoly of (i+1)th node submitted in a tx in round 1
		// CommittedPolynomials: Vec<Option<CommittedPoly>>;
		CommittedPolynomials: Vec<Option<Vec<u8>>>;

		// ith entry is the EncShareList of (i+1)th node submitted in a tx in round 1
		// EncryptedSharesLists: Vec<Option<EncShareList>>;
		EncryptedSharesLists: Vec<Option<Vec<u8>>>;


		// round 2

		FinishedRound2: bool;
		// list of n bools: ith is true <=> both the below conditions are satisfied:
		// 1) (i+1)th node succesfully participated in round 0 and round 1
		// 2) there was no succesful dispute that proves cheating of (i+1)th node in round 2
		IsCorrectDealer: Vec<bool>;
	}
}

decl_module! {
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {

		// TODO: we need to be careful with weights -- for now they are 0, but need to think about them later
		#[weight = 0]
		pub fn post_encryption_key(origin, _pk: EncryptionPublicKey) -> DispatchResult {
			let now = <frame_system::Module<T>>::block_number();
			let who = ensure_signed(origin)?;
			sp_runtime::print("DKG post_encryption_key");
			debug::info!("DKG post_encryption_key call: block_number: {:?} who {:?}", now, who);
			// logic for receiving round0 tx
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
				if !<Self as Store>::FinishedRound0::exists() {
					Self::handle_round0(block_number);
				}
			} else if block_number < END_ROUND_1.into() {
				// implement creating tx for round 1
				if !<Self as Store>::FinishedRound0::exists() {
					Self::handle_round1(block_number);
				}
			} else if block_number < END_ROUND_2.into() {
				// implement creating tx for round 2
				if !<Self as Store>::FinishedRound0::exists() {
					Self::handle_round2(block_number);
				}
			}
		}
	}
}

// Most of the functions are moved outside of the `decl_module!` macro.
//
// This greatly helps with error messages, as the ones inside the macro
// can sometimes be hard to debug.
impl<T: Trait> Module<T> {
	// TODO: add a custom type for id number?
	fn _my_id() -> u64 {
		// this should be able to look at our own public key and
		// at the committee members's public keys that are in the pallet
		// and simply find out our id
		// It might make sense to then cache this id in our local storage?
		// Some access to our keys we can get using the line below:
		// let signer = Signer::<T, T::AuthorityId>::all_accounts();
		0
	}

	fn handle_round0(block_number: T::BlockNumber) {
		debug::native::info!("DKG handle_round0 called at block: {:?}", block_number);
		// TODO: encrypt the key
		const ALREADY_SET: () = ();

		let val = StorageValueRef::persistent(b"dkw::enc_key");
		let res = val.mutate(|last_set: Option<Option<[u64; 4]>>| match last_set {
			Some(Some(key)) => {
				debug::native::info!("DKG error with encryption key already set {:?}", key);
				Err(ALREADY_SET)
			}
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
				debug::native::info!("DKG setting a new encryption key: {:?}", scalar_raw);
				Ok(scalar_raw)
			}
		});

		if let Ok(Ok(raw_scalar)) = res {
			// send tx with key
			debug::native::info!("DKG sending the encryption key for raw: {:?}", raw_scalar);
			let signer = Signer::<T, T::AuthorityId>::all_accounts();
			if !signer.can_sign() {
				// return Err(
				// 	"No local accounts available. Consider adding one via `author_insertKey` RPC."
				// )?
			}
			<Self as Store>::FinishedRound0::put(true);
			let _ = signer.send_signed_transaction(|_account| {
				let enc_pk = EncryptionPublicKey::from_raw_scalar(raw_scalar);
				Call::post_encryption_key(enc_pk)
			});
		}
	}

	fn handle_round1(block_number: T::BlockNumber) {
		debug::native::info!("DKG handle_round1 called at block: {:?}", block_number);
	}

	fn handle_round2(block_number: T::BlockNumber) {
		debug::native::info!("DKG handle_round2 called at block: {:?}", block_number);
	}
}
