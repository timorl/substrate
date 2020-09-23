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

use sp_std::{result, prelude::*};
use sp_std::collections::btree_set::BTreeSet;
use frame_support::{decl_module, decl_storage, decl_error, dispatch, ensure};
use frame_support::traits::{FindAuthor, VerifySeal, Get};
use codec::{Encode, Decode};
use frame_system::ensure_none;
use sp_runtime::traits::{Header as HeaderT, One, Zero};
use frame_support::weights::{Weight, DispatchClass};
use sp_inherents::{InherentIdentifier, ProvideInherent, InherentData};
use sp_authorship::{INHERENT_IDENTIFIER, UnclesInherentData, InherentError};

const START_BEACON_HEIGHT: usize = 2;

pub trait Trait: frame_system::Trait {

}




decl_storage! {
    trait Store for Module<T: Trait> as RandomnessBeacon {
        SeedByHeight get(fn seed_by_height): map hasher(blake2_128_concat) T::BlockNumber => Vec<u8>;
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
			//<Self as Store>::DidSetUncles::kill();
		}

	}
}


impl<T: Trait> ProvideInherent for Module<T> {
	type Call = Call<T>;
	type Error = InherentError;
	const INHERENT_IDENTIFIER: InherentIdentifier = INHERENT_IDENTIFIER;

	fn create_inherent(data: &InherentData) -> Option<Self::Call> {
		let parent_hash = <frame_system::Module<T>>::parent_hash();
		None
	}

	fn check_inherent(call: &Self::Call, _data: &InherentData) -> result::Result<(), Self::Error> {
		Ok(())
	}
}

