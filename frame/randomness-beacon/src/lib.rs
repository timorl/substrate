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

use codec::{Decode, Encode};
use frame_support::{
	decl_error, decl_module, decl_storage, traits::Randomness as RandomnessT, weights::Weight,
};
use frame_system::ensure_none;
use sp_inherents::{InherentData, InherentIdentifier, ProvideInherent};
use sp_randomness_beacon::{
	inherents::{InherentError, INHERENT_IDENTIFIER},
	Randomness, VerifyKey, START_BEACON_HEIGHT,
};
use sp_runtime::print;
use sp_std::{result, vec::Vec};


pub trait Trait: frame_system::Trait {}

decl_storage! {
	trait Store for Module<T: Trait> as RandomnessBeacon {
		// It seems that having this map is not necessary as we only need
		// to store random_bytes for the most recent block
		// will change it once everything else works properly
		SeedByHeight: map hasher(blake2_128_concat) T::BlockNumber => Vec<u8>;
		/// Was random_bytes was set in this block?
		DidUpdate: bool;
		/// Stores verifier needed to check randomness in blocks
		RandomnessVerifier get(fn verifier): VerifyKey;
	}
}

decl_error! {
	pub enum Error for Module<T: Trait> {
		SeedNotAvailable,
	}
}

decl_module! {
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		type Error = Error<T>;

		fn on_initialize(now: T::BlockNumber) -> Weight {
			if now == 1.into() && !<Self as Store>::RandomnessVerifier::exists() {
				 <Self as Store>::RandomnessVerifier::set(sp_randomness_beacon::generate_verify_key());
			}

			0
		}

		#[weight = 0]
		fn set_random_bytes(origin, height: T::BlockNumber, random_bytes: Vec<u8>)  {
			ensure_none(origin)?;

			assert!(!<Self as Store>::DidUpdate::exists(), "Randomness must be set only once in the block");

			<Self as Store>::SeedByHeight::insert(height, random_bytes);
			<Self as Store>::DidUpdate::put(true);
		}

		fn on_finalize(bn: T::BlockNumber) {
			if bn >= START_BEACON_HEIGHT.into() {
				assert!(<Self as Store>::DidUpdate::take(), "Randomness must be put into the block");
			}
		}
	}
}

impl<T: Trait> Module<T> {
	pub fn set_randomness_verifier(verifier: VerifyKey) {
		<Self as Store>::RandomnessVerifier::put(verifier)
	}
}

pub trait RandomSeedInherentData {
	/// Get random random_bytes
	fn get_random_bytes(&self) -> Vec<u8>;
}

impl RandomSeedInherentData for InherentData {
	fn get_random_bytes(&self) -> Vec<u8> {
		let randomness: Result<Option<Randomness>, _> = self.get_data(&INHERENT_IDENTIFIER);
		assert!(
			randomness.is_ok(),
			"Panic because of error in retrieving inherent_data with err {:?}.",
			randomness.err().unwrap()
		);
		let randomness = randomness.unwrap();
		assert!(
			randomness.is_some(),
			"Panic because no random_bytes found in inherent_data."
		);
		Randomness::encode(&randomness.unwrap())
	}
}

use sp_std::convert::TryInto;

impl<T: Trait> ProvideInherent for Module<T> {
	type Call = Call<T>;
	type Error = InherentError;
	const INHERENT_IDENTIFIER: InherentIdentifier = INHERENT_IDENTIFIER;

	fn create_inherent(data: &InherentData) -> Option<Self::Call> {
		let now = <frame_system::Module<T>>::block_number();
		print((
			"create_inherent block height: ",
			now.try_into().unwrap_or_default(),
		));
		if now >= T::BlockNumber::from(START_BEACON_HEIGHT) {
			return Some(Self::Call::set_random_bytes(now, data.get_random_bytes()));
		}
		None
	}

	fn check_inherent(call: &Self::Call, _: &InherentData) -> result::Result<(), Self::Error> {
		let now = <frame_system::Module<T>>::block_number();
		print((
			"check_inherent block height: ",
			now.try_into().unwrap_or_default(),
		));
		if now < T::BlockNumber::from(START_BEACON_HEIGHT) {
			return Ok(());
		}

		if !<Self as Store>::RandomnessVerifier::exists() {
			return Err(sp_randomness_beacon::inherents::InherentError::VerifyKeyNotSet);
		}

		let (height, random_bytes) = match call {
			Call::set_random_bytes(ref height, ref random_bytes) => {
				(height.clone(), random_bytes.clone())
			}
			_ => return Ok(()),
		};

		if height != now {
			return Err(sp_randomness_beacon::inherents::InherentError::WrongHeight);
		}

		let verify_key = Self::verifier();
		let randomness = Randomness::decode(&mut &*random_bytes).unwrap();
		if !sp_randomness_beacon::verify_randomness(&verify_key, randomness) {
			return Err(sp_randomness_beacon::inherents::InherentError::InvalidRandomBytes);
		}
		Ok(())
	}
}

impl<T: Trait> RandomnessT<T::Hash> for Module<T> {
	// TODO: implement
	fn random(_subject: &[u8]) -> T::Hash {
		T::Hash::default()
	}
}
