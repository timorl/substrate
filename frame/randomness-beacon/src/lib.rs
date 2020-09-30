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


use frame_support::weights::{Weight};

use sp_std::{result, vec::Vec};
use sp_runtime;
use frame_support::{decl_module, decl_storage, decl_error};
use frame_system::ensure_none;
use codec::{Encode, Decode};
use sp_inherents::{InherentIdentifier, ProvideInherent, InherentData};
use sp_randomness_beacon::{InherentError, INHERENT_IDENTIFIER};

const START_BEACON_HEIGHT: u32 = 2;

pub trait Trait: frame_system::Trait {

}

decl_storage! {
    trait Store for Module<T: Trait> as RandomnessBeacon {
    	// It seems that having this map is not necessary as we only need
    	// to store random_bytes for the most recent block
    	// will change it once everything else works properly
        SeedByHeight: map hasher(blake2_128_concat) T::BlockNumber => Vec<u8>;
		/// Was random_bytes was set in this block?
		DidUpdate: bool;
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
			sp_runtime::print("on init");
			0
		}

		#[weight = 0]
		fn set_random_bytes(origin, height: T::BlockNumber, random_bytes: Vec<u8>)  {
			sp_runtime::print("on set");
			ensure_none(origin)?;

			assert!(!<Self as Store>::DidUpdate::exists(), "Randomness must be set only once in the block");

			<Self as Store>::SeedByHeight::insert(height, random_bytes);
			<Self as Store>::DidUpdate::put(true);
		}

		fn on_finalize(bn: T::BlockNumber) {
			sp_runtime::print("on fin");
			if bn >= START_BEACON_HEIGHT.into() {
				assert!(<Self as Store>::DidUpdate::take(), "Randomness must be put into the block");
			}
		}
	}
}


pub trait RandomSeedInherentData<H: Decode + Eq> {
	/// Get random random_bytes for hash or None
	fn get_random_bytes(&self, block_hash: H) -> Option<Vec<u8>>;
}

impl<H: Decode + Eq> RandomSeedInherentData<H> for InherentData {
	fn get_random_bytes(&self, block_hash: H) -> Option<Vec<u8>> {
		sp_runtime::print("in get_random_bytes");
		let list_hash_random_bytes: Option<Vec<(H, Vec<u8>)>> = self.get_data(&INHERENT_IDENTIFIER).unwrap_or_default();
		if list_hash_random_bytes.is_none() {
			sp_runtime::print("get_data output none, it means random_bytes not available yet");
		    return None;
		}
		for (hash, random_bytes) in list_hash_random_bytes.unwrap() {
			if hash == block_hash {
				return Some(random_bytes);
			}
		}
		None
	}
}

// TODO: implement after adding some keys
fn check_random_bytes(_nonce: Vec<u8>, _random_bytes: Vec<u8>) -> bool {
    true
}

use sp_std::convert::TryInto;

impl<T: Trait> ProvideInherent for Module<T> {
	type Call = Call<T>;
	type Error = InherentError;
        const INHERENT_IDENTIFIER: InherentIdentifier = INHERENT_IDENTIFIER;

	fn create_inherent(data: &InherentData) -> Option<Self::Call> {
		let now = <frame_system::Module<T>>::block_number();
		sp_runtime::print(("create_inherent block height: ", now.try_into().unwrap_or_default()));
		if now >= T::BlockNumber::from(START_BEACON_HEIGHT) {
			let parent_hash = <frame_system::Module<T>>::parent_hash();
			return match data.get_random_bytes(parent_hash.encode()) {
				Some(random_bytes) => Some(Self::Call::set_random_bytes(now, random_bytes)),
				None => None,
			};
		}
		None
	}

	fn check_inherent(call: &Self::Call, _: &InherentData) -> result::Result<(), Self::Error> {
		let now = <frame_system::Module<T>>::block_number();
		sp_runtime::print(("check_inherent block height: ", now.try_into().unwrap_or_default()));
		let (height, random_bytes) = match call {
			Call::set_random_bytes(ref height, ref random_bytes) => (height.clone(), random_bytes.clone()),
			_ => return Ok(()),
		};

		if height != now {
			return Err(sp_randomness_beacon::InherentError::WrongHeight);
		}

		let parent_hash = <frame_system::Module<T>>::parent_hash();
		let parent_nonce = Encode::encode(&parent_hash);

		if !check_random_bytes(parent_nonce, random_bytes) {
			return Err(sp_randomness_beacon::InherentError::InvalidRandomBytes);
		}
		Ok(())
	}
}
