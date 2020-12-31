#![cfg(test)]

use crate::*;
use codec::Decode;
use frame_support::{impl_outer_origin, parameter_types, traits::OnFinalize, weights::Weight};
use parking_lot::RwLock;
use sp_core::{
	offchain::{
		testing::{OffchainState, PoolState, TestOffchainExt, TestTransactionPoolExt},
		OffchainExt, OffchainStorage, TransactionPoolExt,
	},
	H256,
};
use sp_dkg::{KeyBox, ShareProvider, AuthIndex};
use sp_keystore::{
	testing::KeyStore,
	{KeystoreExt, SyncCryptoStore},
};
use sp_runtime::testing::{Header, TestXt};
use sp_runtime::traits::{BlakeTwo256, Extrinsic as ExtrinsicT, IdentityLookup, Verify};
use sp_runtime::{MultiSignature, Perbill};
use std::sync::Arc;

const N_MEMBERS: usize = 4;
const THRESHOLD: usize = 3;

#[test]
fn dkg() {
	let (mut t, states, my_id) = new_test_ext();
	t.execute_with(|| {
		let my_ix = init(my_id, N_MEMBERS, THRESHOLD as u64);
		test_handle_round0(&states, my_ix);
		test_handle_round1(&states, my_ix);
		test_handle_round2(&states, my_ix);
		test_handle_round3(&states, my_ix);
		test_keybox(&states, my_ix);
	});
}

#[derive(Clone)]
pub(crate) struct States {
	pub(crate) offchain: Arc<RwLock<OffchainState>>,
	pool: Arc<RwLock<PoolState>>,
}

pub(crate) fn new_test_ext() -> (
	sp_io::TestExternalities,
	States,
	sp_dkg::crypto::AuthorityId,
) {
	const PHRASE: &str =
		"news slush supreme milk chapter athlete soap sausage put clutch what kitten";

	let (offchain, offchain_state) = TestOffchainExt::new();
	let (pool, pool_state) = TestTransactionPoolExt::new();
	let keystore = KeyStore::new();
	let my_id: sp_dkg::crypto::AuthorityId = SyncCryptoStore::sr25519_generate_new(
		&keystore,
		sp_dkg::crypto::AuthorityId::ID,
		Some(&format!("{}/alice", PHRASE)),
	)
	.unwrap()
	.into();

	let mut ext = sp_io::TestExternalities::default();
	ext.register_extension(OffchainExt::new(offchain));
	ext.register_extension(TransactionPoolExt::new(pool));
	ext.register_extension(KeystoreExt(Arc::new(keystore)));

	let states = States {
		offchain: offchain_state,
		pool: pool_state,
	};
	(ext, states, my_id)
}

pub(crate) fn init(my_id: sp_dkg::crypto::AuthorityId, n_members: usize, threshold: u64) -> AuthIndex {
	let mut authorities = vec![crypto::DKGId::default(); n_members];
	authorities[0] = my_id.clone().into();
	authorities.sort();

	DKG::init_store(&authorities[..]);
	for ix in 0..n_members {
		assert_eq!(authorities[ix], <DKG as Store>::Authorities::get(ix as AuthIndex));
	}
	DKG::set_threshold(threshold);
	assert_eq!(<DKG as Store>::Threshold::get(), threshold);

	authorities
		.iter()
		.position(|id| *id == my_id.clone().into())
		.unwrap()
		as AuthIndex
}

fn get_secret_enc_key(offchain_state: Arc<RwLock<OffchainState>>) -> RawSecret {
	let st_key = DKG::build_storage_key(b"enc_key", 0);
	let raw_secret_encoded = offchain_state
		.read()
		.persistent_storage
		.get(b"", &st_key)
		.unwrap();
	<RawSecret>::decode(&mut &raw_secret_encoded[..]).unwrap()
}

fn test_handle_round0(states: &States, my_ix: AuthIndex) {
	// do the round
	DKG::handle_round0();

	// check if correct values was submitted on chain
	let raw_secret = get_secret_enc_key(states.offchain.clone());
	let enc_pk = EncryptionPublicKey::from_raw_scalar(raw_secret);

	let tx = states.pool.write().transactions.pop().unwrap();
	assert!(states.pool.read().transactions.is_empty());
	let tx = Extrinsic::decode(&mut &*tx).unwrap();
	assert_eq!(tx.signature.unwrap().0, 0);
	assert_eq!(tx.call, Call::post_encryption_key(my_ix, enc_pk.clone()));

	// manually add the rest encryption public keys
	for ix in 0..N_MEMBERS {
		if ix as AuthIndex == my_ix {
			<DKG as Store>::EncryptionPKs::insert(ix as AuthIndex, enc_pk.clone());
		} else {
			<DKG as Store>::EncryptionPKs::insert(ix as AuthIndex, EncryptionPublicKey::from_raw_scalar([ix as u64, 0, 0, 0]));
		}
	}
	for ix in 0..N_MEMBERS {
		assert!(<DKG as Store>::EncryptionPKs::contains_key(ix as AuthIndex));
	}
}

fn encryption_keys(secret: Scalar) -> Vec<EncryptionKey> {
	let mut enc_keys = Vec::new();
	for ix in 0..N_MEMBERS {
		enc_keys.push(EncryptionPKs::get(ix as AuthIndex).to_encryption_key(secret));
	}
	enc_keys
}

fn enc_shares_comms(
	secret_enc_key: Scalar,
	poly: Vec<Scalar>,
) -> (Vec<Option<EncryptedShare>>, Vec<Commitment>) {
	let enc_shares = encryption_keys(secret_enc_key)
		.iter()
		.enumerate()
		.map(|(ix, enc_key)| {
			let x = &Scalar::from(ix as u64 + 1);
			let share = poly_eval(&poly, x);
			Some(enc_key.encrypt(&share))
		})
		.collect();

	let comms = (0..THRESHOLD).map(|i| Commitment::new(poly[i])).collect();

	(enc_shares, comms)
}

fn set_shares_comms(ix: AuthIndex, shares: Vec<Option<EncryptedShare>>, comms: Vec<Commitment>) {
	for (share_ix, maybe_share) in shares.iter().enumerate() {
		if let Some(share) = maybe_share {
			<DKG as Store>::EncryptedShares::insert((ix as AuthIndex, share_ix as AuthIndex), share);
		}
	}
	<DKG as Store>::CommittedPolynomials::insert(ix as AuthIndex, comms);
	<DKG as Store>::IsCorrectDealer::insert(ix as AuthIndex, true);
}

fn test_handle_round1(states: &States, my_ix: AuthIndex) {
	// do the round
	let mut seed = [0; 32];
	(0..32u64)
		.enumerate()
		.for_each(|(i, b)| seed[i] = b.pow(2) as u8);
	states.offchain.write().seed = seed;
	DKG::handle_round1();

	// check if correct values was submitted on chain
	let st_key = DKG::build_storage_key(b"secret_poly", 1);
	let raw_poly_coeffs_encoded = states
		.offchain
		.read()
		.persistent_storage
		.get(b"", &st_key)
		.unwrap();
	let raw_poly_coeffs = <Vec<RawSecret>>::decode(&mut &raw_poly_coeffs_encoded[..]).unwrap();
	let poly = raw_poly_coeffs
		.into_iter()
		.map(|raw| Scalar::from_raw(raw))
		.collect();

	let secret_enc_key = Scalar::from_raw(get_secret_enc_key(states.offchain.clone()));
	let (enc_shares, commitments) = enc_shares_comms(secret_enc_key, poly);
	set_shares_comms(my_ix, enc_shares.clone(), commitments.clone());

	let tx = states.pool.write().transactions.pop().unwrap();
	assert!(states.pool.read().transactions.is_empty());
	let tx = Extrinsic::decode(&mut &*tx).unwrap();
	assert_eq!(tx.signature.unwrap().0, 1);

	assert_eq!(
		tx.call,
		Call::post_secret_shares(my_ix, enc_shares, commitments, Default::default())
	);

	// manually add enc_shares and commitments
	for ix in 0..N_MEMBERS {
		if ix as AuthIndex == my_ix {
			continue;
		}
		let poly = [ix, 1, 1].iter().map(|i| Scalar::from(*i as AuthIndex)).collect();
		let secret = Scalar::from(ix as AuthIndex);
		let (shares, comms) = enc_shares_comms(secret, poly);
		set_shares_comms(ix as AuthIndex, shares, comms);
	}
}

fn test_handle_round2(states: &States, my_ix: AuthIndex) {
	// do the round
	DKG::handle_round2();

	// check if correct values was submitted on chain
	let tx = states.pool.write().transactions.pop().unwrap();
	assert!(states.pool.read().transactions.is_empty());
	let tx = Extrinsic::decode(&mut &*tx).unwrap();
	assert_eq!(tx.signature.unwrap().0, 2);

	assert_eq!(tx.call, Call::post_disputes(my_ix, Vec::new(), Default::default()));
}

fn derive_tsk(my_ix: usize) -> Scalar {
	let secret_enc_key = Scalar::from(my_ix as u64);
	let encryption_keys = encryption_keys(secret_enc_key);
	let mut tsk = Scalar::zero();
	for (creator, ek) in encryption_keys.iter().enumerate() {
		let encrypted_share = &<DKG as Store>::EncryptedShares::get((creator as AuthIndex, my_ix as AuthIndex)).clone();
		let share = ek.decrypt(&encrypted_share).unwrap();
		tsk += share;
	}

	tsk
}

fn test_handle_round3(states: &States, my_ix: AuthIndex) {
	// do the round
	DKG::handle_round3();
	let round2_end = DKG::round_end(2);
	<DKG as OnFinalize<u64>>::on_finalize(round2_end);

	// check if correct values was submitted on chain
	let st_key = DKG::build_storage_key(b"threshold_secret_key", 3);
	let tsk_encoded = states
		.offchain
		.read()
		.persistent_storage
		.get(b"", &st_key)
		.unwrap();
	let tsk = Scalar::from_bytes(&<[u8; 32]>::decode(&mut &tsk_encoded[..]).unwrap()).unwrap();

	let st_key = DKG::build_storage_key(b"secret_shares", 2);
	let tsk_shares_encoded = states
		.offchain
		.read()
		.persistent_storage
		.get(b"", &st_key)
		.unwrap();
	let tsk_shares = <Vec<Option<[u8; 32]>>>::decode(&mut &tsk_shares_encoded[..])
		.unwrap()
		.into_iter()
		.map(|raw| Scalar::from_bytes(&raw.unwrap()).unwrap());
	assert_eq!(tsk, tsk_shares.fold(Scalar::zero(), |a, b| a + b));

	let mut comms = Vec::new();
	for ix in 0..N_MEMBERS {
		comms.push(<DKG as Store>::CommittedPolynomials::get(ix as AuthIndex)[0].clone());
	}

	let mvk = Commitment::derive_key(comms);
	assert_eq!(mvk, <DKG as Store>::MasterVerificationKey::get());

	let st_key = DKG::build_storage_key(b"secret_poly", 1);
	let raw_poly_coeffs_encoded = states
		.offchain
		.read()
		.persistent_storage
		.get(b"", &st_key)
		.unwrap();
	let raw_poly_coeffs = <Vec<RawSecret>>::decode(&mut &raw_poly_coeffs_encoded[..]).unwrap();
	let local_secret = Scalar::from_raw(raw_poly_coeffs[0]);
	let mut msk = local_secret;
	for ix in 0..N_MEMBERS {
		if ix as AuthIndex == my_ix {
			continue;
		}
		msk += Scalar::from(ix as AuthIndex);
	}

	assert_eq!(mvk, Commitment::derive_key(vec![Commitment::new(msk)]));

	let mut vks = Vec::new();
	for ix in 0..N_MEMBERS {
		let x = &Scalar::from(ix as u64 + 1);
		let part_keys = (0..N_MEMBERS)
			.map(|dealer| Commitment::poly_eval(&<DKG as Store>::CommittedPolynomials::get(dealer as AuthIndex), x))
			.collect();
		vks.push(Commitment::derive_key(part_keys))
	}
	assert_eq!(vks, <DKG as Store>::VerificationKeys::get());

	for ix in 0..N_MEMBERS {
		if ix as AuthIndex == my_ix {
			assert_eq!(vks[ix], VerifyKey::from_secret(&tsk));
		} else {
			assert_eq!(vks[ix], VerifyKey::from_secret(&derive_tsk(ix)));
		}
	}
}

fn test_keybox(states: &States, my_ix: AuthIndex) {
	let mut kbs = Vec::new();
	let vks = <DKG as Store>::VerificationKeys::get();
	let mvk = <DKG as Store>::MasterVerificationKey::get();
	let st_key = DKG::build_storage_key(b"threshold_secret_key", 3);
	for ix in 0..N_MEMBERS {
		if ix as AuthIndex == my_ix {
			let tsk_encoded = states
				.offchain
				.read()
				.persistent_storage
				.get(b"", &st_key)
				.unwrap();
			let tsk =
				Scalar::from_bytes(&<[u8; 32]>::decode(&mut &tsk_encoded[..]).unwrap()).unwrap();
			let tsp = ShareProvider::from_secret(ix as AuthIndex, tsk);
			kbs.push(KeyBox::new(
				Some(tsp),
				vks.clone(),
				mvk.clone(),
				THRESHOLD as u64,
			));
		} else {
			let tsp = ShareProvider::from_secret(ix as AuthIndex, derive_tsk(ix));
			kbs.push(KeyBox::new(
				Some(tsp),
				vks.clone(),
				mvk.clone(),
				THRESHOLD as u64,
			));
		}
	}

	let mut msgs = Vec::new();
	for pow in 1..5 {
		let mut msg = [0; 32];
		(0..32u64)
			.enumerate()
			.for_each(|(i, b)| msg[i] = b.pow(pow) as u8);
		msgs.push(msg.to_vec());
	}

	for msg in msgs.iter() {
		let mut shares = Vec::new();
		for ix in 0..N_MEMBERS {
			let share = kbs[ix].generate_share(msg).unwrap();
			assert!(kbs[ix].verify_share(&msg, &share));
			shares.push(share);
		}

		for ix in 0..N_MEMBERS {
			let shares = shares
				.clone()
				.into_iter()
				.filter(|s| *s != shares[ix])
				.collect();
			let signature = kbs[ix].combine_shares(&shares);
			assert!(kbs[ix].verify_signature(&msg, &signature));
		}
	}
}

impl_outer_origin! {
	pub enum Origin for Runtime where system = frame_system {}
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Runtime;

parameter_types! {
	pub const BlockHashCount: u64 = 250;
	pub const MaximumBlockWeight: Weight = 1024;
	pub const MaximumBlockLength: u32 = 2 * 1024;
	pub const AvailableBlockRatio: Perbill = Perbill::one();
}

impl frame_system::Trait for Runtime {
	type BaseCallFilter = ();
	type Origin = Origin;
	type Index = u64;
	type BlockNumber = u64;
	type Call = ();
	type Hash = H256;
	type Hashing = BlakeTwo256;
	type AccountId = AccountId;
	type Lookup = IdentityLookup<Self::AccountId>;
	type Header = Header;
	type Event = ();
	type BlockHashCount = BlockHashCount;
	type MaximumBlockWeight = MaximumBlockWeight;
	type DbWeight = ();
	type BlockExecutionWeight = ();
	type ExtrinsicBaseWeight = ();
	type MaximumExtrinsicWeight = MaximumBlockWeight;
	type MaximumBlockLength = MaximumBlockLength;
	type AvailableBlockRatio = AvailableBlockRatio;
	type Version = ();
	type PalletInfo = ();
	type AccountData = ();
	type OnNewAccount = ();
	type OnKilledAccount = ();
	type SystemWeightInfo = ();
}

type Signature = MultiSignature;
type Extrinsic = TestXt<Call<Runtime>, ()>;
type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;

impl frame_system::offchain::SigningTypes for Runtime {
	type Public = <Signature as Verify>::Signer;
	type Signature = Signature;
}

impl<LocalCall> frame_system::offchain::SendTransactionTypes<LocalCall> for Runtime
where
	Call<Runtime>: From<LocalCall>,
{
	type OverarchingCall = Call<Runtime>;
	type Extrinsic = Extrinsic;
}

impl<LocalCall> frame_system::offchain::CreateSignedTransaction<LocalCall> for Runtime
where
	Call<Runtime>: From<LocalCall>,
{
	fn create_transaction<C: frame_system::offchain::AppCrypto<Self::Public, Self::Signature>>(
		call: Call<Runtime>,
		_public: <Signature as Verify>::Signer,
		_account: AccountId,
		msg: u64,
	) -> Option<(Call<Runtime>, <Extrinsic as ExtrinsicT>::SignaturePayload)> {
		Some((call, (msg, ())))
	}
}

parameter_types! {
	pub const UnsignedPriority: u64 = 1 << 20;
}

parameter_types! {
	pub const DKGReady: u64 = 10;
}

impl Trait for Runtime {
	type Call = Call<Runtime>;
	type AuthorityId = crypto::DKGId;
	type DKGReady = DKGReady;
	type Event = ();
}

pub type DKG = Module<Runtime>;
