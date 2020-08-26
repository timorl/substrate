//! ### Example - Get random seed for the current block
//!
//! ```
//! use frame_support::{decl_module, dispatch, traits::Randomness};
//!
//! pub trait Trait: frame_system::Trait {}
//!
//! decl_module! {
//! 	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
//! 		#[weight = 0]
//! 		pub fn random_beacon_example(origin) -> dispatch::DispatchResult {
//! 			let _random_value = <pallet_random_beacon::Module<T>>::random(&b"my context"[..]);
//! 			Ok(())
//! 		}
//! 	}
//! }
//! # fn main() { }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

/// Edit this file to define custom logic or remove it if it is not needed.
/// Learn more about FRAME and the core library of Substrate FRAME pallets:
/// https://substrate.dev/docs/en/knowledgebase/runtime/frame

use frame_support::{decl_event, decl_error, decl_module, decl_storage, dispatch, weights::Weight, ensure, traits::Randomness};
use frame_system::ensure_signed;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

/// Configure the pallet by specifying the parameters and types on which it depends.
pub trait Trait: frame_system::Trait {
    /// Because this pallet emits events, it depends on the runtime's definition of an event.
    type Event: From<Event<Self>> + Into<<Self as frame_system::Trait>::Event>;
}

// The pallet's runtime storage items.
// https://substrate.dev/docs/en/knowledgebase/runtime/storage
decl_storage! {
	trait Store for Module<T: Trait> as RandomBeacon{
                /// Get random bytes from block of given number
		RandomBytes: map hasher(blake2_128_concat) T::BlockNumber => T::Hash;
	}
}

// Pallets use events to inform users when important changes are made.
// https://substrate.dev/docs/en/knowledgebase/runtime/events
decl_event!{
	pub enum Event<T> where 
                    AccountId   = <T as frame_system::Trait>::AccountId,
                    BlockNumber = <T as frame_system::Trait>::BlockNumber,
                    RandomBytes = <T as frame_system::Trait>::Hash {
		/// Event emitted when random bytes has been read. [who, block_number, random_bytes]
		RandomBytesRead(AccountId, BlockNumber, RandomBytes),
	}
}

// Errors inform users that something went wrong.
decl_error! {
	pub enum Error for Module<T: Trait> {
		/// An attempt to read random bytes from non-existing block
		WrongBlockNumber,
	}
}

// Dispatchable functions allows users to interact with the pallet and invoke state changes.
// These functions materialize as "extrinsics", which are often compared to transactions.
// Dispatchable functions must be annotated with a weight and must return a DispatchResult.
decl_module! {
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
               // Errors must be initialized if they are used by the pallet.
               type Error = Error<T>;

                // Events must be initialized if they are used by the pallet.
                fn deposit_event() = default;

                // on_initialize is called on the first block after genesis
                fn on_initialize(block_number: T::BlockNumber) -> Weight{
                    let random_bytes = <frame_system::Module<T>>::parent_hash();
                    RandomBytes::<T>::insert(block_number, random_bytes);

                    0
                }

		#[weight = 10_000]
		pub fn get_current_random_bytes(origin) -> dispatch::DispatchResult {
			// Check that the extrinsic was signed and get the signer.
			// This function will return an error if the extrinsic is not signed.
			// https://substrate.dev/docs/en/knowledgebase/runtime/origin
			let sender = ensure_signed(origin)?;

			// read random bytes from current block
                        let current_block = <frame_system::Module<T>>::block_number();
                        let random_bytes = RandomBytes::<T>::get(current_block);

                        // Emit an event that random bytes were read
                        Self::deposit_event(RawEvent::RandomBytesRead(sender, current_block, random_bytes));

                        Ok(())
		}

		#[weight = 10_000]
		pub fn get_random_bytes(origin, block_number: T::BlockNumber) -> dispatch::DispatchResult {
			// Check that the extrinsic was signed and get the signer.
			// This function will return an error if the extrinsic is not signed.
			// https://substrate.dev/docs/en/knowledgebase/runtime/origin
			let sender = ensure_signed(origin)?;

                        let current_block = <frame_system::Module<T>>::block_number();
                        ensure!(block_number <= current_block, Error::<T>::WrongBlockNumber);

                        let random_bytes = RandomBytes::<T>::get(current_block);

                        // Emit an event that random bytes were read
                        Self::deposit_event(RawEvent::RandomBytesRead(sender, block_number, random_bytes));

                        Ok(())
		}
	}
}

impl<T: Trait> Randomness<T::Hash> for Module<T> {
    fn random(_subject: &[u8]) -> T::Hash {
        let current_block = <frame_system::Module<T>>::block_number();
        
        if current_block == 0.into() {
            T::Hash::default()
        } else {
            RandomBytes::<T>::get(current_block)
        }
    }
}
