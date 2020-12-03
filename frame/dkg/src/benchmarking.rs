#![cfg(feature = "runtime-benchmarks")]

use super::*;

use frame_benchmarking::benchmarks;
use frame_system::RawOrigin;

use crate::Module as DKG;
use sp_dkg::{Commitment, EncryptedShare, EncryptionPublicKey};

benchmarks! {
	_{ }

	handle_round0 {
		let n=10;
		let n = n as usize;
		let threshold = n/ 3 + 1;
		assert!(<DKG::<T> as Store>::Authorities::get().last().is_some());
		init::<T>(n, threshold as u64);
	}: {DKG::<T>::handle_round0();}
	verify {
		// how to verify offchain state?
	}

	post_encryption_key {
		assert!(<DKG::<T> as Store>::Authorities::get().last().is_some());
		let caller = <DKG::<T> as Store>::Authorities::get().last().unwrap().clone().into().into_account();
		let enc_pk = EncryptionPublicKey::default();
	}: _(RawOrigin::Signed(caller), enc_pk)
	verify {
		assert!(<DKG::<T> as Store>::EncryptionPKs::get().last().is_some());
	}

	handle_round1 {
		let n=10;
		let n = n as usize;
		let threshold = n/ 3 + 1;
		assert!(<DKG::<T> as Store>::Authorities::get().last().is_some());
		init::<T>(n as usize, threshold as u64);
	}: {DKG::<T>::handle_round1();}
	verify {
		// how to verify offchain state?
	}

	post_secret_shares {
		let n=10;
		let n = n as usize;
		let threshold = n/ 3 + 1;

		assert!(<DKG::<T> as Store>::Authorities::get().last().is_some());
		let caller = <DKG::<T> as Store>::Authorities::get().last().unwrap().clone().into().into_account();

		init::<T>(n as usize ,threshold as u64);
		<DKG::<T> as Store>::CommittedPolynomials::mutate(|ref mut values| values[n-1] = vec![]);
		<DKG::<T> as Store>::EncryptedSharesLists::mutate(|ref mut values| values[n-1] = vec![None; n]);

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

	}: _(RawOrigin::Signed(caller), secret_shares, comm_poly, hash_round0)
	verify {
		assert_eq!(<DKG::<T> as Store>::CommittedPolynomials::get()[n-1].len(), threshold);
		assert!(<DKG::<T> as Store>::EncryptedSharesLists::get()[n-1].iter().all(|es| es.is_some()));
	}

}

fn init<T: Trait>(n_members: usize, threshold: u64) {
	let auth = <DKG<T> as Store>::Authorities::get()
		.last()
		.unwrap()
		.clone();
	let mut authorities = vec![T::AuthorityId::default(); n_members];
	authorities[n_members - 1] = auth;
	<DKG<T> as Store>::Authorities::put(&authorities);
	<DKG<T> as Store>::Threshold::set(threshold);
	<DKG<T> as Store>::EncryptionPKs::put(
		(0..n_members)
			.map(|ix| Some(EncryptionPublicKey::from_raw_scalar([ix as u64, 0, 0, 0])))
			.collect::<Vec<Option<EncryptionPublicKey>>>(),
	);
	<DKG<T> as Store>::CommittedPolynomials::put(vec![
		vec![
			Commitment::default();
			threshold as usize
		];
		n_members
	]);
	<DKG<T> as Store>::EncryptedSharesLists::put(vec![
		vec![
			Some(EncryptedShare::default());
			n_members
		];
		n_members
	]);
	<DKG<T> as Store>::IsCorrectDealer::put(vec![true; n_members]);
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
		});
	}
}
