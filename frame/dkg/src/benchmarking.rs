#![cfg(feature = "runtime-benchmarks")]

use super::*;

use frame_benchmarking::benchmarks;
use frame_system::RawOrigin;

use crate::Module as DKG;
use sp_dkg::{AuthIndex, Commitment, EncryptedShare, EncryptionPublicKey, Scalar};
use sp_std::prelude::*;

const MAX_SIZE: u32 = 256;
benchmarks! {
	_ {
		let n in 1..MAX_SIZE/4=> ();
	}

	handle_round0 {
		let n in ...;
		let n = (4*n) as usize;
		let threshold = n/ 3 + 1;

		init::<T>(n, threshold as u64);
	}: {DKG::<T>::handle_round0();}

	post_encryption_key {
		let n in ...;
		let n = (4*n) as usize;
		let threshold = n/ 3 + 1;

		init::<T>(n, threshold as u64);
		let caller = T::AccountId::default();
		let enc_pk = EncryptionPublicKey::default();
	}: _(RawOrigin::Signed(caller), 0, enc_pk)
	verify {
		assert!(<DKG::<T> as Store>::EncryptionPKs::contains_key(0));
	}

	handle_round1 {
		let n in ...;
		let n = (4*n) as usize;
		let threshold = n/ 3 + 1;

		init::<T>(n, threshold as u64);
	}: {DKG::<T>::handle_round1();}

	post_secret_shares {
		let n in ...;
		let n = (4*n) as usize;
		let threshold = n/ 3 + 1;

		init::<T>(n, threshold as u64);
		let caller = T::AccountId::default();
		frame_system::Module::<T>::set_block_number(DKG::<T>::round_end(1));

		let mut secret_shares = vec![];
		for _ in 0..n {
			secret_shares.push(Some(EncryptedShare::default()));
		}
		let mut comm_poly = vec![];
		for _ in 0..threshold {
			comm_poly.push(Commitment::default());
		}
		let hash_round0 = T::Hash::default();

		<DKG::<T> as Store>::CommittedPolynomials::remove(0);
		for ix in 0..n {
			<DKG::<T> as Store>::EncryptedShares::remove((0, ix as AuthIndex));
		}

	}: _(RawOrigin::Signed(caller), 0, secret_shares, comm_poly, hash_round0)
	verify {
		assert_eq!(<DKG::<T> as Store>::CommittedPolynomials::get(0).len(), threshold);
		for ix in 0..n {
			assert!(<DKG::<T> as Store>::EncryptedShares::contains_key((0, ix as AuthIndex)));
		}
	}

	post_disputes {
		let n in ...;
		let n = (4*n) as usize;
		let threshold = n/ 3 + 1;

		init::<T>(n, threshold as u64);
		let caller = T::AccountId::default();
		frame_system::Module::<T>::set_block_number(DKG::<T>::round_end(2));

		let my_ix = 0usize;
		let bad_dealer = n-1;
		let my_secret_key = Scalar::from(my_ix as u64);
		let enc_key = <DKG<T> as Store>::EncryptionPKs::get(bad_dealer as AuthIndex).to_encryption_key(my_secret_key);
		let share = Scalar::from(1);
		let enc_share = enc_key.encrypt(&share);
		<DKG::<T> as Store>::EncryptedShares::insert((bad_dealer as AuthIndex, my_ix as AuthIndex), enc_share);
		assert_eq!(DKG::<T>::verify_share(&share, bad_dealer, my_ix as u64), false);
		let disputes = vec![(bad_dealer as u64, enc_key)];
		let hash_round1 = T::Hash::default();
	}: _(RawOrigin::Signed(caller),my_ix as AuthIndex, disputes, hash_round1)
	verify {
		assert_eq!(<DKG::<T> as Store>::IsCorrectDealer::get(bad_dealer as AuthIndex), false);
	}
}

fn init<T: Trait>(n_members: usize, threshold: u64) {
	<DKG<T> as Store>::NMembers::put(n_members as u64);
	<DKG<T> as Store>::Threshold::put(threshold);
	for ix in 0..n_members {
		<DKG<T> as Store>::Authorities::insert(ix as AuthIndex, T::AuthorityId::default());
		<DKG<T> as Store>::EncryptionPKs::insert(
			ix as AuthIndex,
			EncryptionPublicKey::from_raw_scalar([ix as u64, 0, 0, 0]),
		);
		<DKG<T> as Store>::CommittedPolynomials::insert(
			ix as AuthIndex,
			vec![Commitment::default(); threshold as usize],
		);
		for ix_rec in 0..n_members {
			<DKG<T> as Store>::EncryptedShares::insert(
				(ix as AuthIndex, ix_rec as AuthIndex),
				EncryptedShare::default(),
			);
		}
		<DKG<T> as Store>::IsCorrectDealer::insert(ix as AuthIndex, true);
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::tests::{new_test_ext, Runtime};
	use frame_support::assert_ok;
	#[test]
	fn test_benchmarks() {
		let (mut t, states, _) = new_test_ext();
		t.execute_with(|| {
			let mut seed = [0; 32];
			(0..32u64)
				.enumerate()
				.for_each(|(i, b)| seed[i] = b.pow(2) as u8);
			states.offchain.write().seed = seed;
			assert_ok!(test_benchmark_handle_round0::<Runtime>());
			assert_ok!(test_benchmark_post_encryption_key::<Runtime>());
			assert_ok!(test_benchmark_handle_round1::<Runtime>());
			assert_ok!(test_benchmark_post_secret_shares::<Runtime>());
			assert_ok!(test_benchmark_post_disputes::<Runtime>());
		});
	}
}
