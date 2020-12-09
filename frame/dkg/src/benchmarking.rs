#![cfg(feature = "runtime-benchmarks")]

use super::*;

use frame_benchmarking::benchmarks;
use frame_system::RawOrigin;

use crate::Module as DKG;
use sp_dkg::{Commitment, EncryptedShare, EncryptionPublicKey, Scalar, AuthIndex};
use sp_std::prelude::*;

benchmarks! {
	_{ }

	handle_round0 {
		let n=10;
		let n = n as usize;
		let threshold = n/ 3 + 1;
		let n_dkg = <DKG::<T> as Store>::NMembers::get();
		assert!(<DKG::<T> as Store>::Authorities::contains_key((n_dkg-1) as AuthIndex));
		init::<T>(n, threshold as u64);
	}: {DKG::<T>::handle_round0();}
	verify {
		// how to verify offchain state?
	}

	post_encryption_key {
		let n_dkg = <DKG::<T> as Store>::NMembers::get();
		assert!(<DKG::<T> as Store>::Authorities::contains_key((n_dkg-1) as AuthIndex));
		let caller = <DKG::<T> as Store>::Authorities::get((n_dkg-1) as AuthIndex).into().into_account();
		let enc_pk = EncryptionPublicKey::default();
	}: _(RawOrigin::Signed(caller),(n_dkg-1) as AuthIndex, enc_pk)
	verify {
		let n_dkg = <DKG::<T> as Store>::NMembers::get();
		assert!(<DKG::<T> as Store>::EncryptionPKs::contains_key((n_dkg-1) as AuthIndex));
	}

	handle_round1 {
		let n=10;
		let n = n as usize;
		let threshold = n/ 3 + 1;
		let n_dkg = <DKG::<T> as Store>::NMembers::get();
		assert!(<DKG::<T> as Store>::Authorities::contains_key((n_dkg-1) as AuthIndex));
		init::<T>(n as usize, threshold as u64);
	}: {DKG::<T>::handle_round1();}
	verify {
		// how to verify offchain state?
	}

	post_secret_shares {
		let n=10;
		let n = n as usize;
		let threshold = n/ 3 + 1;

		let n_dkg = <DKG::<T> as Store>::NMembers::get();
		assert!(<DKG::<T> as Store>::Authorities::contains_key((n_dkg-1) as AuthIndex));


		init::<T>(n as usize, threshold as u64);
		let caller = <DKG::<T> as Store>::Authorities::get((n-1) as AuthIndex).into().into_account();

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

	}: _(RawOrigin::Signed(caller), (n-1) as AuthIndex, secret_shares, comm_poly, hash_round0)
	verify {
		assert_eq!(<DKG::<T> as Store>::CommittedPolynomials::get((n-1) as AuthIndex).len(), threshold);
		for ix in 0..n {
			assert!(<DKG::<T> as Store>::EncryptedShares::contains_key(((n-1) as AuthIndex, ix as AuthIndex)));
		}

	}

	post_disputes {
		let n=10;
		let n = n as usize;
		let threshold = n/ 3 + 1;

		let n_dkg = <DKG::<T> as Store>::NMembers::get();
		assert!(<DKG::<T> as Store>::Authorities::contains_key((n_dkg-1) as AuthIndex));

		init::<T>(n as usize, threshold as u64);
		let caller = <DKG::<T> as Store>::Authorities::get((n-1) as AuthIndex).into().into_account();

		frame_system::Module::<T>::set_block_number(DKG::<T>::round_end(2));

		let my_ix = n-1;
		let bad_dealer = 0usize;
		let my_secret_key = Scalar::from(n as u64 -1);
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
	let n_dkg = <DKG<T> as Store>::NMembers::get();
	let auth = <DKG<T> as Store>::Authorities::get((n_dkg) as AuthIndex);
	for ix in 0..(n_dkg) {
		<DKG<T> as Store>::Authorities::remove(ix as AuthIndex);
	}
	<DKG<T> as Store>::NMembers::put(n_members as u64);
	for ix in 0..(n_members) {
		if ix < n_members - 1 {
			<DKG<T> as Store>::Authorities::insert(ix as AuthIndex, T::AuthorityId::default());
		} else {
			<DKG<T> as Store>::Authorities::insert(ix as AuthIndex, auth.clone());
		}
	}
	<DKG<T> as Store>::Threshold::set(threshold);
	for ix in 0..n_members {
		<DKG<T> as Store>::EncryptionPKs::insert(ix as AuthIndex, EncryptionPublicKey::from_raw_scalar([ix as u64, 0, 0, 0]));
		//<DKG<T> as Store>::CommittedPolynomials::insert(ix as AuthIndex, vec![Commitment::default(); threshold as usize	]);
		//for ix_rec in 0..n_members {
		//	<DKG<T> as Store>::EncryptedShares::insert((ix as AuthIndex, ix_rec as AuthIndex), EncryptedShare::default());
		//}
		<DKG<T> as Store>::IsCorrectDealer::insert(ix as AuthIndex, true);
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::tests::{init, new_test_ext, Runtime};
	use frame_support::assert_ok;
	#[test]
	fn test_benchmarks() {
		let (mut t, states, my_id) = new_test_ext();
		t.execute_with(|| {
			let _ = init(my_id.clone(), 1, 1);
			assert_ok!(test_benchmark_handle_round0::<Runtime>());

			let _ = init(my_id.clone(), 1, 1);
			assert_ok!(test_benchmark_post_encryption_key::<Runtime>());

			let _ = init(my_id.clone(), 1, 1);
			let mut seed = [0; 32];
			(0..32u64)
				.enumerate()
				.for_each(|(i, b)| seed[i] = b.pow(2) as u8);
			states.offchain.write().seed = seed;
			assert_ok!(test_benchmark_handle_round1::<Runtime>());

			let _ = init(my_id.clone(), 1, 1);
			assert_ok!(test_benchmark_post_secret_shares::<Runtime>());

			let _ = init(my_id.clone(), 1, 1);
			assert_ok!(test_benchmark_post_disputes::<Runtime>());
		});
	}
}
