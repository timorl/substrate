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

use sp_std::{result, prelude::*};
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
        SeedByHeight: map hasher(blake2_128_concat) T::BlockNumber => Vec<u8>;

		/// Did the random_bytes was set in this block?
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
			0
		}

		#[weight = 0]
		fn set_random_bytes(origin, height: T::BlockNumber, random_bytes: Vec<u8>)  {
			ensure_none(origin)?;

			assert!(!<Self as Store>::DidUpdate::exists(), "Timestamp must be updated only once in the block");

			<Self as Store>::SeedByHeight::insert(height, random_bytes);
			<Self as Store>::DidUpdate::put(true);
                        
                        // a possiblity to clear used random_bytes, from pallet_timestamp:
			// <T::OnTimestampSet as OnTimestampSet<_>>::on_timestamp_set(now);
		}

		fn on_finalize() {
			assert!(<Self as Store>::DidUpdate::take(), "Timestamp must be updated once in the block");
		}
	}
}


pub trait RandomSeedInherentData<H: Decode + Eq> {
	/// Get random random_bytes for hash or None
	fn random_random_bytes(&self, block_hash: H) -> Option<Vec<u8>>;
}

impl<H: Decode + Eq> RandomSeedInherentData<H> for InherentData {
	fn random_random_bytes(&self, block_hash: H) -> Option<Vec<u8>> {
		let list_hash_random_bytes: Vec<(H, Vec<u8>)> = self.get_data(&INHERENT_IDENTIFIER).unwrap_or_default().unwrap();
		for (hash, random_bytes) in list_hash_random_bytes {
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

impl<T: Trait> ProvideInherent for Module<T> {
	type Call = Call<T>;
	type Error = InherentError;
        const INHERENT_IDENTIFIER: InherentIdentifier = INHERENT_IDENTIFIER;

	fn create_inherent(data: &InherentData) -> Option<Self::Call> {
		let now = <frame_system::Module<T>>::block_number();
		if now >= T::BlockNumber::from(START_BEACON_HEIGHT) {
			let parent_hash = <frame_system::Module<T>>::parent_hash();
			return match data.random_random_bytes(parent_hash) {
				Some(random_bytes) => Some(Self::Call::set_random_bytes(now, random_bytes)),
				None => None,
			};
		}
		None
	}

	fn check_inherent(call: &Self::Call, _data: &InherentData) -> result::Result<(), Self::Error> {
		let (height, random_bytes) = match call {
			Call::set_random_bytes(ref height, ref random_bytes) => (height.clone(), random_bytes.clone()),
			_ => return Ok(()),
		};

                let now = <frame_system::Module<T>>::block_number();
                if height != now - 1.into() {
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

