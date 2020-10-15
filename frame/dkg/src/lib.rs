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

use frame_system::{
	ensure_signed,
	offchain::{
		AppCrypto, CreateSignedTransaction, Signer,
	}
};
use frame_support::{
	dispatch::DispatchResult, decl_module, decl_storage,
};
use sp_core::crypto::KeyTypeId;
use sp_runtime::{
	RuntimeDebug,
	offchain::{storage::StorageValueRef},
};
use codec::{Encode, Decode};
use sp_std::vec::Vec;

//use bls12_381::{G1Affine, G2Affine, Scalar};


// These should be perhaps in some config in the genesis block?
pub const END_ROUND_0: u32 = 5;
pub const END_ROUND_1: u32 = 10;
pub const END_ROUND_2: u32 = 15;


pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"btc!");

/// Based on the above `KeyTypeId` we need to generate a pallet-specific crypto type wrappers.
/// We can use from supported crypto kinds (`sr25519`, `ed25519` and `ecdsa`) and augment
/// the types with this pallet-specific identifier.
pub mod crypto {
	use super::KEY_TYPE;
	use sp_runtime::{
		app_crypto::{app_crypto, sr25519},
		traits::Verify,
	};
	use sp_core::sr25519::Signature as Sr25519Signature;
	app_crypto!(sr25519, KEY_TYPE);

	pub struct TestAuthId;
	impl frame_system::offchain::AppCrypto<<Sr25519Signature as Verify>::Signer, Sr25519Signature> for TestAuthId {
		type RuntimeAppPublic = Public;
		type GenericSignature = sp_core::sr25519::Signature;
		type GenericPublic = sp_core::sr25519::Public;
	}
}

/// This pallet's configuration trait
pub trait Trait: CreateSignedTransaction<Call<Self>> {
	/// The identifier type for an offchain worker.
	type AuthorityId: AppCrypto<Self::Public, Self::Signature>;

	/// The overarching event type.
	//type Event: From<Event<Self>> + Into<<Self as frame_system::Trait>::Event>;
	/// The overarching dispatch call type.
	type Call: From<Call<Self>>;
}


// n is the number of nodes in the committee
// node indices are 1-based: 1, 2, ..., n
// t is the threshold: it is necessary and sufficient to have t shares to combine
// the degree of the polynomial is thus t-1

// EncryptPubKey is a pair (g1^s, g2^s), where g1, g2 are generators of G1 nad G2 resp. and s is a secret scalar
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug)]
pub struct EncryptionPubKey {
	//group1_elem: G1Affine,
	//group2_elem: G2Affine,
}

// EncryptPubKey is a pair scalar s
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug)]
pub struct EncryptionPrivKey {
	//key: Scalar,
}

// A commitment to a polynomial p(x) := p_0 + p_1 x + ... + p_{t-1} x^{t-1}
// Should be a t-tuple of elements of G2=<g2>: g2^{p_0}, g2^{p_1}, ..., g2^{p_{t-1}}
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug)]
pub struct CommittedPoly {

}


// Should be an n-tuple of suitably encoded scalars: enc_1(s_1), ..., enc_{n}(s_n)
// where s_i = p(i) for a polynomial p(x) of degree t-1
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug)]
pub struct EncShareList {
	// for milestone 2 we do not encrypt
	//shares: Vec<Scalar>,
}


// Should be a decrypted share (milestone 2) + along with a proof of descryption (only in milestone 3)
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug)]
pub struct DisputeAgainstDealer {
}


decl_storage! {
	trait Store for Module<T: Trait> as DKGWorker {

		// round 0

		EncryptionPKs: Vec<Option<EncryptionPubKey>>;


		// round 1

		// ith entry is the CommitedPoly of (i+1)th node submitted in a tx in round 1
		CommittedPolynomials: Vec<Option<CommittedPoly>>;

		// ith entry is the EncShareList of (i+1)th node submitted in a tx in round 1
		EncryptedSharesLists: Vec<Option<EncShareList>>;

		// round 2

		// list of n bools: ith is true <=> both the below conditions are satisfied:
		// 1) (i+1)th node succesfully participated in round 0 and round 1
		// 2) there was no succesful dispute that proves cheating of (i+1)th node in round 2
		IsCorrectDealer: Vec<bool>;




		/// A vector of recently submitted prices.
		///
		/// This is used to calculate average price, should have bounded size.
		Prices get(fn prices): Vec<u32>;
		/// Defines the block when next unsigned transaction will be accepted.
		///
		/// To prevent spam of unsigned (and unpayed!) transactions on the network,
		/// we only allow one transaction every `T::UnsignedInterval` blocks.
		/// This storage entry defines when new transaction is going to be accepted.
		NextUnsignedAt get(fn next_unsigned_at): T::BlockNumber;
	}
}

//decl_event!(
	// Not sure if we need events?
//);

decl_module! {
	/// A public part of the pallet.
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {

		// TODO: we need to be careful with weights -- for now they are 0, but need to think about them later
		#[weight = 0]
		pub fn round0(origin, pk: EncryptionPubKey) -> DispatchResult {
			let _who = ensure_signed(origin)?;
			// logic for receiving round0 tx
			Ok(())
		}

		#[weight = 0]
		pub fn round1(origin, comm_poly: CommittedPoly, shares: EncShareList, hash_round0: T::Hash) -> DispatchResult {
			let _who = ensure_signed(origin)?;
			// logic for receiving round1 tx
			Ok(())
		}

		#[weight = 0]
		pub fn round2(origin, disputes: Vec<DisputeAgainstDealer>, hash_round1: T::Hash) -> DispatchResult {
			let _who = ensure_signed(origin)?;
			// logic for receiving round2 tx
			Ok(())
		}


		fn offchain_worker(block_number: T::BlockNumber) {

			//implement creating tx for round 0
			Self::handle_round0(block_number);


			if block_number >= END_ROUND_0.into() {
				// implement creating tx for round 1
				Self::handle_round1(block_number);
			}

			if block_number >= END_ROUND_1.into() {
				// implement creating tx for round 2
				Self::handle_round2(block_number);
			}

			if block_number >= END_ROUND_2.into() {
				// we might want to finalize the DKG here?
			}
		}
	}
}

/// Most of the functions are moved outside of the `decl_module!` macro.
///
/// This greatly helps with error messages, as the ones inside the macro
/// can sometimes be hard to debug.
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

	fn handle_round0(_block_number: T::BlockNumber) {
		let _val = StorageValueRef::local(b"dkw::enc_key");

		// we should use val.mutate() here to check if enc_key was already set
		// if so we just ignore this call (means we have generated and sent tx for round 0 in the past)
		// or we should generate the encryption key sk and store it in the local storage
		// afterwards we send a signed transaction with the resulting public key (see code below)

		let _signer = Signer::<T, T::AuthorityId>::all_accounts();
		// let _ = signer.send_signed_transaction(
		// 	|_account| {
		// 		// we should compute pk out of sk
		// 		// and output Call::round0(pk)
		// 		//Call::submit_price(price)
		// 	}
		// );
	}

	fn handle_round1(_block_number: T::BlockNumber) {
	}

	fn handle_round2(_block_number: T::BlockNumber) {
	}
}
