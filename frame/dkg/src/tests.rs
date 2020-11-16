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
	Pair, H256,
};
use sp_keystore::{
	testing::KeyStore,
	{KeystoreExt, SyncCryptoStore},
};
use sp_runtime::testing::{Header, TestXt};
use sp_runtime::traits::{BlakeTwo256, Extrinsic as ExtrinsicT, IdentityLookup, Verify};
use sp_runtime::{MultiSignature, Perbill};
use std::sync::Arc;

impl_outer_origin! {
	pub enum Origin for Runtime where system = frame_system {}
}

//impl_outer_dispatch! {
//	pub enum Call for Runtime where origin: Origin {
//		pallet_dkg::DKG,
//	}
//}

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

fn gen_key(seed: &str) -> crypto::DKGId {
	sp_dkg::crypto::AuthorityPair::from_string(seed, None)
		.unwrap()
		.public()
		.into()
}

fn new_test_ext() -> (sp_io::TestExternalities, States, Vec<crypto::DKGId>) {
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

	let mut authorities = vec![
		my_id.into(),
		gen_key("/bob"),
		gen_key("/charlie"),
		gen_key("/dave"),
	];
	authorities.sort();

	let mut ext = sp_io::TestExternalities::default();
	ext.register_extension(OffchainExt::new(offchain));
	ext.register_extension(TransactionPoolExt::new(pool));
	ext.register_extension(KeystoreExt(Arc::new(keystore)));

	let states = States {
		offchain: offchain_state,
		pool: pool_state,
	};
	(ext, states, authorities)
}

fn do_init(authorities: Vec<crypto::DKGId>) {
	DKG::init_store(&authorities[..]);
	assert_eq!(DKG::authorities()[..], authorities[..]);
}

#[test]
fn init() {
	let (mut t, _, authorities) = new_test_ext();
	t.execute_with(|| do_init(authorities));
}

fn do_test_handle_round0(states: States, authorities: Vec<crypto::DKGId>) {
	DKG::init_store(&authorities[..]);
	assert!(DKG::encryption_pks().len() == 4);

	let block_number = 1;
	System::set_block_number(block_number);

	DKG::handle_round0(block_number);
	let raw_secret_encoded = states
		.offchain
		.read()
		.persistent_storage
		.get(b"", b"dkw::enc_key")
		.unwrap();
	let raw_secret = <[u64; 4]>::decode(&mut &raw_secret_encoded[..]).unwrap();
	let enc_pk = EncryptionPublicKey::from_raw_scalar(raw_secret);

	let tx = states.pool.write().transactions.pop().unwrap();
	assert!(states.pool.read().transactions.is_empty());
	let tx = Extrinsic::decode(&mut &*tx).unwrap();
	assert_eq!(tx.signature.unwrap().0, 0);

	assert_eq!(tx.call, Call::post_encryption_key(enc_pk));
}

#[test]
fn test_handle_round0() {
	let (mut t, states, authorities) = new_test_ext();
	t.execute_with(|| do_test_handle_round0(states, authorities));
}
