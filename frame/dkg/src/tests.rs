#![cfg(test)]

use crate::*;
use codec::Decode;
use frame_support::{impl_outer_origin, parameter_types, weights::Weight};
use parking_lot::RwLock;
use sp_core::{
	offchain::{
		testing::{OffchainState, PoolState, TestOffchainExt, TestTransactionPoolExt},
		OffchainExt, OffchainStorage, TransactionPoolExt,
	},
	H256,
};
use sp_keystore::{
	testing::KeyStore,
	{KeystoreExt, SyncCryptoStore},
};
use sp_runtime::testing::{Header, TestXt};
use sp_runtime::traits::{BlakeTwo256, Extrinsic as ExtrinsicT, IdentityLookup, Verify};
use sp_runtime::{MultiSignature, Perbill};
use std::sync::Arc;

#[test]
fn dkg() {
	let (mut t, states, authorities) = new_test_ext();
	t.execute_with(|| {
		let my_ix = do_init(authorities);
		do_test_handle_round0(states.clone(), my_ix);
		do_test_handle_round1(states.clone(), my_ix);
		do_test_handle_round2(states.clone());
		do_test_handle_round3(states, my_ix);
	});
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
		nonce: u64,
	) -> Option<(Call<Runtime>, <Extrinsic as ExtrinsicT>::SignaturePayload)> {
		Some((call, (nonce, ())))
	}
}

parameter_types! {
	pub const UnsignedPriority: u64 = 1 << 20;
}

parameter_types! {
	pub const RoundEnds: [u64; 4] = [2, 4, 6, 8];
	pub const MasterKeyReady: u64 = 10;
}

impl Trait for Runtime {
	type Call = Call<Runtime>;
	type AuthorityId = crypto::DKGId;
	type RoundEnds = RoundEnds;
	type MasterKeyReady = MasterKeyReady;
}

pub type DKG = Module<Runtime>;
pub type System = frame_system::Module<Runtime>;

#[derive(Clone)]
struct States {
	offchain: Arc<RwLock<OffchainState>>,
	pool: Arc<RwLock<PoolState>>,
}

fn new_test_ext() -> (
	sp_io::TestExternalities,
	States,
	sp_dkg::crypto::AuthorityId,
) {
	const PHRASE: &str =
		"news slush supreme milk chapter athlete soap sausage put clutch what kitten";

	let (offchain, offchain_state) = TestOffchainExt::new();
	let (pool, pool_state) = TestTransactionPoolExt::new();
	let keystore = KeyStore::new();
	let my_id = SyncCryptoStore::sr25519_generate_new(
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

fn do_init(my_id: sp_dkg::crypto::AuthorityId) -> usize {
	let mut authorities = vec![crypto::DKGId::default(); 4];
	authorities[0] = my_id.clone().into();
	authorities.sort();

	DKG::init_store(&authorities[..]);
	assert_eq!(DKG::authorities()[..], authorities[..]);
	DKG::set_threshold(3);
	assert_eq!(<DKG as Store>::Threshold::get(), 3);

	authorities
		.iter()
		.position(|id| *id == my_id.clone().into())
		.unwrap()
}

fn get_secret_enc_key(offchain_state: Arc<RwLock<OffchainState>>) -> [u64; 4] {
	let raw_secret_encoded = offchain_state
		.read()
		.persistent_storage
		.get(b"", b"dkw::enc_key")
		.unwrap();
	<[u64; 4]>::decode(&mut &raw_secret_encoded[..]).unwrap()
}

fn do_test_handle_round0(states: States, my_ix: usize) {
	// do the round
	let block_number = 1;
	System::set_block_number(block_number);
	DKG::handle_round0(block_number);

	// check if correct values was submitted on chain
	let raw_secret = get_secret_enc_key(states.offchain);
	let enc_pk = EncryptionPublicKey::from_raw_scalar(raw_secret);

	let tx = states.pool.write().transactions.pop().unwrap();
	assert!(states.pool.read().transactions.is_empty());
	let tx = Extrinsic::decode(&mut &*tx).unwrap();
	assert_eq!(tx.signature.unwrap().0, 0);
	assert_eq!(tx.call, Call::post_encryption_key(enc_pk.clone()));

	// manually add the rest encryption public keys
	<DKG as Store>::EncryptionPKs::mutate(|ref mut values| {
		for ix in 0..4 {
			if ix == my_ix {
				values[ix] = Some(enc_pk.clone())
			} else {
				values[ix] = Some(EncryptionPublicKey::from_raw_scalar([ix as u64, 0, 0, 0]))
			}
		}
	});

	<DKG as Store>::EncryptionPKs::get()
		.iter()
		.for_each(|pk| assert!(pk.is_some()));
}

fn encryption_keys(secret: Scalar) -> impl Iterator<Item = EncryptionKey> {
	DKG::encryption_pks()
		.into_iter()
		.map(move |enc_pk| enc_pk.unwrap().to_encryption_key(secret))
}

fn enc_shares_comms(
	secret_enc_key: Scalar,
	poly: Vec<Scalar>,
) -> (Vec<Option<EncryptedShare>>, Vec<Commitment>) {
	let enc_shares = encryption_keys(secret_enc_key)
		.enumerate()
		.map(|(ix, enc_key)| {
			let x = &Scalar::from(ix as u64 + 1);
			let share = poly_eval(&poly, x).to_bytes().to_vec();
			Some(enc_key.encrypt(&share))
		});

	let comms = (0..3).map(|i| Commitment::new(poly[i])).collect();

	(enc_shares.collect(), comms)
}

fn set_shares_commes(ix: usize, shares: Vec<Option<EncryptedShare>>, comms: Vec<Commitment>) {
	<DKG as Store>::EncryptedSharesLists::mutate(|ref mut values| values[ix] = shares);
	<DKG as Store>::CommittedPolynomials::mutate(|ref mut values| values[ix] = comms);
	<DKG as Store>::IsCorrectDealer::mutate(|ref mut values| values[ix] = true);
}

fn do_test_handle_round1(states: States, my_ix: usize) {
	// do the round
	let block_number = 3;
	System::set_block_number(block_number);
	// TODO set sth more fancy
	let mut seed = [0u8; 32];
	seed[0] = 1;
	states.offchain.write().seed = seed;
	DKG::handle_round1(block_number);

	// check if correct values was submitted on chain
	let raw_poly_coeffs_encoded = states
		.offchain
		.read()
		.persistent_storage
		.get(b"", b"dkw::secret_poly")
		.unwrap();
	let raw_poly_coeffs = <Vec<[u64; 4]>>::decode(&mut &raw_poly_coeffs_encoded[..]).unwrap();
	let poly = raw_poly_coeffs
		.into_iter()
		.map(|raw| Scalar::from_raw(raw))
		.collect();

	let secret_enc_key = Scalar::from_raw(get_secret_enc_key(states.offchain));
	let (enc_shares, commitments) = enc_shares_comms(secret_enc_key, poly);
	set_shares_commes(my_ix, enc_shares.clone(), commitments.clone());

	let tx = states.pool.write().transactions.pop().unwrap();
	assert!(states.pool.read().transactions.is_empty());
	let tx = Extrinsic::decode(&mut &*tx).unwrap();
	assert_eq!(tx.signature.unwrap().0, 1);

	assert_eq!(
		tx.call,
		Call::post_secret_shares(enc_shares, commitments, Default::default())
	);

	// manually add enc_shares and commitments
	for ix in 0..4 {
		if ix == my_ix {
			continue;
		}
		let poly = [ix, 1, 1].iter().map(|i| Scalar::from(*i as u64)).collect();
		let secret = Scalar::from(ix as u64);
		let (shares, comms) = enc_shares_comms(secret, poly);
		set_shares_commes(ix, shares, comms);
	}
}

fn do_test_handle_round2(states: States) {
	// do the round
	let block_number = 5;
	System::set_block_number(block_number);
	DKG::handle_round2(block_number);

	// check if correct values was submitted on chain
	let tx = states.pool.write().transactions.pop().unwrap();
	assert!(states.pool.read().transactions.is_empty());
	let tx = Extrinsic::decode(&mut &*tx).unwrap();
	assert_eq!(tx.signature.unwrap().0, 2);

	assert_eq!(tx.call, Call::post_disputes(Vec::new(), Default::default()));
}

fn do_test_handle_round3(states: States, my_ix: usize) {
	// do the round
	let block_number = 7;
	System::set_block_number(block_number);
	DKG::handle_round3(block_number);

	// check if correct values was submitted on chain
	let tsk_encoded = states
		.offchain
		.read()
		.persistent_storage
		.get(b"", b"dkw::threshold_secret_key")
		.unwrap();
	let tsk = Scalar::from_bytes(&<[u8; 32]>::decode(&mut &tsk_encoded[..]).unwrap()).unwrap();

	let tsk_shares_encoded = states
		.offchain
		.read()
		.persistent_storage
		.get(b"", b"dkw::secret_shares")
		.unwrap();
	let tsk_shares = <Vec<Option<[u8; 32]>>>::decode(&mut &tsk_shares_encoded[..])
		.unwrap()
		.into_iter()
		.map(|raw| Scalar::from_bytes(&raw.unwrap()).unwrap());
	assert_eq!(tsk, tsk_shares.fold(Scalar::zero(), |a, b| a + b));

	let comms = DKG::committed_polynomilas()
		.into_iter()
		.map(|comms| comms[0].clone())
		.collect();

	let mvk = Commitment::derive_key(comms);

	let raw_poly_coeffs_encoded = states
		.offchain
		.read()
		.persistent_storage
		.get(b"", b"dkw::secret_poly")
		.unwrap();
	let raw_poly_coeffs = <Vec<[u64; 4]>>::decode(&mut &raw_poly_coeffs_encoded[..]).unwrap();
	let local_secret = Scalar::from_raw(raw_poly_coeffs[0]);
	let mut msk = local_secret;
	for ix in 0..4 {
		if ix == my_ix {
			continue;
		}
		msk += Scalar::from(ix as u64);
	}
	assert_eq!(mvk, Commitment::derive_key(vec![Commitment::new(msk)]));

	let tx = states.pool.write().transactions.pop().unwrap();
	assert!(states.pool.read().transactions.is_empty());
	let tx = Extrinsic::decode(&mut &*tx).unwrap();
	assert_eq!(tx.signature.unwrap().0, 3);

	// TODO manually check vks as mvk
	let mut vks = Vec::new();
	for ix in 0..4 {
		let x = &Scalar::from(ix as u64 + 1);
		let part_keys = (0..4)
			.map(|dealer| Commitment::poly_eval(&DKG::committed_polynomilas()[dealer], x))
			.collect();
		vks.push(Commitment::derive_key(part_keys))
	}

	assert_eq!(
		tx.call,
		Call::post_verification_keys(mvk, vks, Default::default())
	);
}
