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
//use sp_std::collections::btree_set::BTreeSet;
use frame_support::{decl_module, decl_storage, decl_error};
//use frame_support::traits::{FindAuthor, VerifySeal, Get};
use codec::{Decode};
//use frame_system::ensure_none;
//use sp_runtime::traits::{Header as HeaderT, One, Zero};
//use frame_support::weights::{Weight};
use sp_inherents::{InherentIdentifier, ProvideInherent, InherentData};
//use sp_authorship::{INHERENT_IDENTIFIER, UnclesInherentData, InherentError};
use sp_authorship::{InherentError};
//use sp_runtime::traits::{Block};
//use sc_randomness_beacon::{RandomSeedInherentData};

const START_BEACON_HEIGHT: u32 = 2;

pub trait Trait: frame_system::Trait {

}

decl_storage! {
    trait Store for Module<T: Trait> as RandomnessBeacon {
        SeedByHeight: map hasher(blake2_128_concat) T::BlockNumber => Vec<u8>;
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

		fn on_finalize() {
		}

		#[weight = 0]
		fn set_seed(origin, height: T::BlockNumber, seed: Vec<u8>)  {
			<Self as Store>::SeedByHeight::insert(height, seed);
		}
	}
}


// The trait below should be in the same file as the Inherent Data Provider

const INHERENT_IDENTIFIER: InherentIdentifier = *b"randbecn";

pub trait RandomSeedInherentData<H: Decode + Eq> {
	/// Get random seed for hash or None
	fn random_seed(&self, block_hash: H) -> Option<Vec<u8>>;
}

impl<H: Decode + Eq> RandomSeedInherentData<H> for InherentData {
	fn random_seed(&self, block_hash: H) -> Option<Vec<u8>> {
		let list_hash_seed: Vec<(H, Vec<u8>)> = self.get_data(&INHERENT_IDENTIFIER).unwrap_or_default().unwrap();
		for (hash, seed) in list_hash_seed {
			if hash == block_hash {
				return Some(seed);
			}
		}
		None
	}
}


impl<T: Trait> ProvideInherent for Module<T> {
	type Call = Call<T>;
	type Error = InherentError;
	const INHERENT_IDENTIFIER: InherentIdentifier = INHERENT_IDENTIFIER;


	fn create_inherent(data: &InherentData) -> Option<Self::Call> {
		let now = <frame_system::Module<T>>::block_number();
		if now >= T::BlockNumber::from(START_BEACON_HEIGHT) {
			let parent_hash = <frame_system::Module<T>>::parent_hash();
			let res = match data.random_seed(parent_hash) {
				Some(seed) => Some(Self::Call::set_seed(now, seed)),
				None => None,
			};
			return res;
		}
		None
	}

	fn check_inherent(_call: &Self::Call, _data: &InherentData) -> result::Result<(), Self::Error> {
		// should check if the seed we are trying to set is correct
		Ok(())
	}
}

