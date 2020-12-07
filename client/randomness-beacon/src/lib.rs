//! Communication via random gossip for Randomness Beacon.
//! Implements all the primitives required to generate and broadcast data
//! necessary for functioning of the randomness beacon. More specifically
//! it sends and receives random shares for randomness seeds for subsequent
//! blocks in the blockchain. The main component -- RandomnessGossip
//! holds a receiving end of a channel at which it receives notifications
//! from block import that the procedure of randomness creation should be
//! started for a new block. It also holds a transmitting end of a channel
//! through which it transmits ready random seeds to the block proposer.
//! When creating a new block the proposer blocks until the random seed for
//! arrives through this channel.

use codec::{Decode, Encode};
use log::info;

use sc_network::PeerId;
use sc_network_gossip::{
	GossipEngine, Network, TopicNotification, ValidationResult, Validator, ValidatorContext,
};

use sp_runtime::{generic::BlockId, traits::Block as BlockT, traits::NumberFor};

use sp_dkg::DKGApi;
use sp_randomness_beacon::{RBBox, Randomness, RandomnessBeaconApi, RandomnessShare};

use futures::{channel::mpsc::Receiver, prelude::*};
use parking_lot::Mutex;
use std::{
	collections::HashMap,
	pin::Pin,
	sync::{mpsc::Sender, Arc},
	task::{Context, Poll},
	time,
};

use std::cmp::Ordering;
use std::collections::BinaryHeap;

//pub type NonceInfo<B> = (<B as BlockT>::Hash, NumberFor<B>);
pub type Nonce<B> = <B as BlockT>::Hash;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NonceInfo<B>
where
	B: BlockT,
{
	nonce: Nonce<B>,
	height: NumberFor<B>,
}

const RANDOMNESS_BEACON_ID: [u8; 4] = *b"rndb";
const RB_PROTOCOL_NAME: &'static str = "/randomness_beacon";
pub const SEND_INTERVAL: time::Duration = time::Duration::from_secs(5);
pub const INITIAL_WAIT: time::Duration = time::Duration::from_secs(0);

pub mod authorship;
pub mod import;

pub type ShareBytes = Vec<u8>;

#[derive(Debug, Clone, Encode, Decode)]
pub struct Message {
	share: ShareBytes,
}

#[derive(Debug, Encode, Decode)]
pub struct GossipMessage<B: BlockT> {
	nonce: Nonce<B>,
	message: Message,
}

impl<B: BlockT> NonceInfo<B> {
	fn new(nonce: <B as BlockT>::Hash, height: NumberFor<B>) -> Self {
		NonceInfo { nonce, height }
	}

	fn nonce(&self) -> &Nonce<B> {
		&self.nonce
	}

	fn height(&self) -> &NumberFor<B> {
		&self.height
	}
}

impl<B: BlockT> Ord for NonceInfo<B> {
	fn cmp(&self, other: &Self) -> Ordering {
		// We want the lowest height to come first
		other
			.height
			.cmp(&self.height)
			.then_with(|| self.nonce.cmp(&other.nonce))
	}
}

// `PartialOrd` needs to be implemented as well.
impl<B: BlockT> PartialOrd for NonceInfo<B> {
	fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
		Some(self.cmp(other))
	}
}

pub struct GossipValidator {}

impl GossipValidator {
	pub fn new() -> Self {
		GossipValidator {}
	}
}

#[derive(Debug, Clone)]
pub enum Error {
	Network(String),
	Signing(String),
}

/// Validator of the messages received via gossip.
/// It only needs to check that the received data corresponds to a share
impl<B: BlockT> Validator<B> for GossipValidator {
	fn validate(
		&self,
		_context: &mut dyn ValidatorContext<B>,
		_sender: &PeerId,
		data: &[u8],
	) -> ValidationResult<B::Hash> {
		match GossipMessage::<B>::decode(&mut data.clone()) {
			Ok(gm) => {
				let topic = gm.nonce;
				ValidationResult::ProcessAndKeep(topic)
			}
			Err(e) => {
				info!(
					target: RB_PROTOCOL_NAME,
					"Error decoding message: {}",
					e.what()
				);
				ValidationResult::Discard
			}
		}
	}
}

#[derive(Clone)]
pub struct OutgoingMessage<B: BlockT> {
	nonce: Nonce<B>,
	msg: Message,
	gossip_engine: Arc<Mutex<GossipEngine<B>>>,
}

impl<B: BlockT> OutgoingMessage<B> {
	fn send(&self) {
		let message = GossipMessage::<B> {
			nonce: self.nonce.clone(),
			message: self.msg.clone(),
		};
		let topic = self.nonce.clone();
		self.gossip_engine
			.lock()
			.gossip_message(topic, message.encode(), true);
	}
}

pub struct RandomnessGossip<B: BlockT, C> {
	threshold: u64,
	topics: HashMap<
		B::Hash,
		(
			Receiver<TopicNotification>,
			Option<OutgoingMessage<B>>,
			futures_timer::Delay,
			RBBox<Nonce<B>>,
			Vec<RandomnessShare<Nonce<B>>>,
		),
	>,
	height_queue: BinaryHeap<NonceInfo<B>>,
	gossip_engine: Arc<Mutex<GossipEngine<B>>>,
	randomness_nonce_rx: Receiver<NonceInfo<B>>,
	randomness_tx: Option<Sender<Randomness<Nonce<B>>>>,
	runtime_api: Arc<C>,
	http_rpc_port: u16,
}

impl<B: BlockT, C> Unpin for RandomnessGossip<B, C> {}

/// The component used for gossiping and combining shares of randomness.
impl<B: BlockT, C> RandomnessGossip<B, C>
where
	C: sp_api::ProvideRuntimeApi<B>,
	C::Api: DKGApi<B> + RandomnessBeaconApi<B>,
{
	pub fn new<N: Network<B> + Send + Clone + 'static>(
		threshold: u64,
		randomness_nonce_rx: Receiver<NonceInfo<B>>,
		network: N,
		randomness_tx: Option<Sender<Randomness<Nonce<B>>>>,
		runtime_api: Arc<C>,
		http_rpc_port: u16,
	) -> Self {
		let gossip_engine = Arc::new(Mutex::new(GossipEngine::new(
			network.clone(),
			RANDOMNESS_BEACON_ID,
			RB_PROTOCOL_NAME,
			Arc::new(GossipValidator::new()),
		)));

		RandomnessGossip {
			threshold,
			topics: HashMap::new(),
			height_queue: BinaryHeap::new(),
			gossip_engine,
			randomness_nonce_rx,
			randomness_tx,
			runtime_api,
			http_rpc_port,
		}
	}

	// prunes all topics that are >=30 blocks lower than at_height
	fn prune_old_topics(&mut self, at_height: NumberFor<B>) {
		while let Some(nonce_info) = self.height_queue.peek() {
			// TODO: make this constant 30 into a parameter
			if *nonce_info.height() + 30.into() <= at_height {
				// TODO: make sure it is safe to prune this way...
				// The channels are closed, is this fine?
				self.topics.remove(&nonce_info.nonce());
				self.height_queue.pop();
			}
		}
	}

	fn initialize_nonce(
		&mut self,
		nonce_info: NonceInfo<B>,
		rbbox: &RBBox<Nonce<B>>,
	) -> (
		Receiver<TopicNotification>,
		Option<OutgoingMessage<B>>,
		Vec<RandomnessShare<Nonce<B>>>,
	) {
		let nonce = nonce_info.nonce();
		let height = nonce_info.height();
		self.prune_old_topics(*height);
		let topic = nonce;

		let incoming = self
			.gossip_engine
			.lock()
			.messages_for(*topic)
			.filter_map(move |notification| {
				let decoded = GossipMessage::<B>::decode(&mut &notification.message[..]);
				match decoded {
					Ok(gm) => {
						// Some filtering may happen here
						future::ready(Some(gm))
					}
					Err(ref e) => {
						info!(
							target: RB_PROTOCOL_NAME,
							"Skipping malformed message {:?}: {}", notification, e
						);
						future::ready(None)
					}
				}
			})
			.into_inner();

		let mut message = None;
		let mut shares = Vec::new();
		let maybe_share = rbbox.generate_randomness_share(nonce.clone());
		if maybe_share.is_some() {
			let share = maybe_share.unwrap();
			shares.push(share.clone());
			message = Some(OutgoingMessage::<B> {
				msg: Message {
					share: share.encode(),
				},
				nonce: nonce.clone(),
				gossip_engine: self.gossip_engine.clone(),
			});
		}
		(incoming, message, shares)
	}

	fn get_rbbox(&mut self, nonce_info: &NonceInfo<B>) -> Option<RBBox<Nonce<B>>> {
		use hyper::rt;
		use hyper::rt::Future;
		use jsonrpc_core_client::transports::http;
		use sc_rpc::offchain::OffchainClient;
		use sp_core::{offchain::StorageKind, Bytes};

		let block_hash = nonce_info.nonce().clone();
		let block_height = nonce_info.height();

		let beacon_start = match self
			.runtime_api
			.runtime_api()
			.start_beacon_height(&BlockId::Hash(block_hash))
		{
			Ok(height) => height,
			_ => return None,
		};

		let beacon_period = match self
			.runtime_api
			.runtime_api()
			.beacon_period(&BlockId::Hash(block_hash))
		{
			Ok(height) => height,
			_ => return None,
		};

		if *block_height < beacon_start {
			// the keys are not ready yet
			return None;
		}

		if (*block_height - beacon_start) % beacon_period != 0.into() {
			return None;
		}

		let (ix, verification_keys, master_key, t) = match self
			.runtime_api
			.runtime_api()
			.public_keybox_parts(&BlockId::Hash(block_hash))
		{
			Ok(Some((ix, vks, mvk, t))) => (ix, vks, mvk, t),
			Ok(None) | Err(_) => return None,
		};
		let (tx, rx) = std::sync::mpsc::channel();
		let tx = Mutex::new(tx);

		let storage_key = match self
			.runtime_api
			.runtime_api()
			.storage_key_sk(&BlockId::Hash(block_hash))
		{
			Ok(Some(st_key)) => st_key,
			Ok(None) | Err(_) => return None,
		};

		// TODO: need to adjust this once the fork-aware version of the DKG pallet is ready
		let mut raw_key = None;
		if ix.is_some() {
			let url = format!("http://localhost:{}", self.http_rpc_port);
			rt::run(rt::lazy(move || {
				http::connect(url.as_str())
					.and_then(move |client: OffchainClient| {
						client
							.get_local_storage(StorageKind::PERSISTENT, Bytes(storage_key))
							.map(move |enc_key| {
								let raw_key =
									<[u64; 4]>::decode(&mut &enc_key.unwrap()[..]).unwrap();
								if let Err(e) = tx.lock().send(raw_key) {
									info!("Error while sending raw_key {:?}", e);
								}
							})
					})
					.map_err(|e| info!("didn't get key with err {:?}", e))
			}));
			raw_key = rx.recv().ok();
		}

		Some(RBBox::new(ix, raw_key, verification_keys, master_key, t))
	}
}

impl<B: BlockT, C> Future for RandomnessGossip<B, C>
where
	C: sp_api::ProvideRuntimeApi<B>,
	C::Api: DKGApi<B> + RandomnessBeaconApi<B>,
{
	type Output = ();

	/// A future is implemented which intertwines receiving new messages
	/// with periodically sending out outgoing messages. Apart from that
	/// it checks whether new notifications about blocks are received from
	/// the channel that goes between block import and this component.
	/// Each such notification triggers start of a gossip on a new topic,
	/// thus in particular a new message is being gossip by this node: its
	/// randomness share for the new topic (i.e. new block).
	fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
		match self.gossip_engine.lock().poll_unpin(cx) {
			Poll::Ready(()) => {
				return Poll::Ready(info!(
					target: RB_PROTOCOL_NAME,
					"RandomnessGossip future finished."
				))
			}
			Poll::Pending => {}
		};
		let new_nonce_info = match self.randomness_nonce_rx.poll_next_unpin(cx) {
			Poll::Pending => None,
			Poll::Ready(None) => return Poll::Ready(()),
			Poll::Ready(new_nonce_info) => new_nonce_info,
		};

		if new_nonce_info.is_some() {
			let new_nonce_info = new_nonce_info.unwrap();
			let new_nonce = new_nonce_info.nonce();
			let topic = new_nonce.clone();
			if !self.topics.contains_key(&topic) {
				// received new nonce, need to fetch the corresponding rbbox
				let maybe_rbbox = self.get_rbbox(&new_nonce_info);
				if let Some(rbbox) = maybe_rbbox {
					let (incoming, msg, shares) =
						self.initialize_nonce(new_nonce_info.clone(), &rbbox);
					let periodic_sender = futures_timer::Delay::new(INITIAL_WAIT);
					self.topics
						.insert(topic, (incoming, msg, periodic_sender, rbbox, shares));
				} else {
					info!(
						"Obtained a new nonce {:?} but could not retrieve the corresponding rbbox.",
						new_nonce
					);
				}
			}
		}
		let randomness_tx = self.randomness_tx.clone();
		let threshold = self.threshold.clone() as usize;

		for (_, (incoming, maybe_msg, periodic_sender, rbbox, shares)) in self.topics.iter_mut() {
			if let Some(msg) = maybe_msg {
				// msg is our share, we need to send it from time to time.
				// This executes only if the node is in the committee.
				while let Poll::Ready(()) = periodic_sender.poll_unpin(cx) {
					periodic_sender.reset(SEND_INTERVAL);
					msg.send();
				}
			}

			if shares.len() < threshold {
				let poll = incoming.poll_next_unpin(cx);
				match poll {
					Poll::Ready(Some(notification)) => {
						let GossipMessage::<B> { message, .. } =
							GossipMessage::<B>::decode(&mut &notification.message[..]).unwrap();
						let share = RandomnessShare::decode(&mut &*message.share).unwrap();
						if rbbox.verify_randomness_share(&share) {
							shares.push(share);
						}
					}
					Poll::Ready(None) => info!(
						target: RB_PROTOCOL_NAME,
						"poll_next_unpin returned Ready(None) ==> investigate!"
					),
					Poll::Pending => {}
				}

				if shares.len() == threshold {
					assert!(shares
						.iter()
						.take(shares.len() - 1)
						.enumerate()
						.all(|(i, s)| !shares[i + 1..].contains(s)));

					let randomness = rbbox.combine_shares(shares);

					// When randomness succesfully combined, notify block proposer
					if let Some(ref randomness_tx) = randomness_tx {
						assert!(
							randomness_tx.send(randomness).is_ok(),
							"problem with sending new randomness to the block proposer"
						);
					}
				}
			}
		}
		return Poll::Pending;
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use futures::channel::mpsc::channel;
	use futures::channel::mpsc::{unbounded, UnboundedSender};
	use jsonrpc_core::IoHandler;
	use jsonrpc_http_server::{RestApi, Server, ServerBuilder};
	use sc_network::{Event, ReputationChange};
	use sc_network_gossip::Network;
	use sc_rpc::offchain::{Offchain, OffchainApi};
	use sc_rpc_api::DenyUnsafe;
	use sp_api::{ApiRef, ProvideRuntimeApi};
	use sp_core::{offchain::storage::InMemOffchainStorage, offchain::StorageKind, Bytes};
	use sp_dkg::{AuthIndex, DKGApi, Scalar, VerifyKey};
	use sp_runtime::traits::Block as BlockT;
	use sp_runtime::ConsensusEngineId;
	use std::borrow::Cow;
	use std::sync::{Arc, Mutex};
	use substrate_test_runtime_client::runtime::{Block, BlockNumber, Hash};

	const KEY: &[u8; 3] = b"key";

	fn serve() -> Server {
		let builder = ServerBuilder::new(io()).rest_api(RestApi::Unsecure);
		builder.start_http(&"127.0.0.1:0".parse().unwrap()).unwrap()
	}

	fn io() -> IoHandler {
		let mut io = IoHandler::default();
		let storage = InMemOffchainStorage::default();
		let offchain = Offchain::new(storage, DenyUnsafe::No);
		let key = Bytes(KEY.to_vec());
		let value = Bytes(Scalar::from_raw([1, 7, 2, 9]).to_bytes().to_vec());

		assert!(offchain
			.set_local_storage(StorageKind::PERSISTENT, key, value)
			.is_ok());

		io.extend_with(sc_rpc::offchain::OffchainApi::to_delegate(offchain));

		io
	}

	#[derive(Clone, Default)]
	struct TestNetwork {
		inner: Arc<Mutex<TestNetworkInner>>,
	}

	#[derive(Clone, Default)]
	struct TestNetworkInner {
		event_senders: Vec<UnboundedSender<Event>>,
	}

	impl<B: BlockT> Network<B> for TestNetwork {
		fn event_stream(&self) -> Pin<Box<dyn Stream<Item = Event> + Send>> {
			let (tx, rx) = unbounded();
			self.inner.lock().unwrap().event_senders.push(tx);

			Box::pin(rx)
		}

		fn report_peer(&self, _: PeerId, _: ReputationChange) {}

		fn disconnect_peer(&self, _: PeerId) {
			unimplemented!();
		}

		fn write_notification(&self, _: PeerId, _: ConsensusEngineId, _: Vec<u8>) {
			unimplemented!();
		}

		fn register_notifications_protocol(&self, _: ConsensusEngineId, _: Cow<'static, str>) {}

		fn announce(&self, _: B::Hash, _: Vec<u8>) {
			unimplemented!();
		}
	}

	#[derive(Default, Clone)]
	struct TestApi {
		master_verification_key: Option<VerifyKey>,
		master_key_ready: NumberFor<Block>,
		threshold: u64,
		verification_keys: Option<Vec<VerifyKey>>,
		public_keybox_parts: Option<(Option<AuthIndex>, Vec<VerifyKey>, VerifyKey, u64)>,
		storage_key_sk: Option<Vec<u8>>,
		beacon_start: NumberFor<Block>,
		beacon_period: NumberFor<Block>,
	}

	impl TestApi {
		fn new(
			master_verification_key: Option<VerifyKey>,
			master_key_ready: NumberFor<Block>,
			threshold: u64,
			verification_keys: Option<Vec<VerifyKey>>,
			public_keybox_parts: Option<(Option<AuthIndex>, Vec<VerifyKey>, VerifyKey, u64)>,
			storage_key_sk: Option<Vec<u8>>,
			beacon_start: NumberFor<Block>,
			beacon_period: NumberFor<Block>,
		) -> Self {
			TestApi {
				master_verification_key,
				master_key_ready,
				threshold,
				verification_keys,
				public_keybox_parts,
				storage_key_sk,
				beacon_start,
				beacon_period,
			}
		}
	}

	#[derive(Default, Clone)]
	struct RuntimeApi {
		inner: TestApi,
	}

	impl ProvideRuntimeApi<Block> for TestApi {
		type Api = RuntimeApi;

		fn runtime_api<'a>(&'a self) -> ApiRef<'a, Self::Api> {
			RuntimeApi {
				inner: self.clone(),
			}
			.into()
		}
	}

	sp_api::mock_impl_runtime_apis! {
		impl DKGApi<Block> for RuntimeApi {
			fn master_verification_key(&self) -> Option<VerifyKey> {
				self.inner.master_verification_key.clone()
			}

			fn master_key_ready() -> NumberFor<Block>{
				self.inner.master_key_ready.clone()
			}

			fn threshold() -> u64{
				self.inner.threshold.clone()
			}

			fn verification_keys() -> Option<Vec<VerifyKey>>{
				self.inner.verification_keys.clone()
			}

			fn public_keybox_parts() -> Option<(Option<AuthIndex>, Vec<VerifyKey>, VerifyKey, u64)>{
				self.inner.public_keybox_parts.clone()
			}

			fn storage_key_sk() -> Option<Vec<u8>>{
				self.inner.storage_key_sk.clone()
			}
		}

		impl RandomnessBeaconApi<Block> for RuntimeApi {
			fn start_beacon_height(&self) -> NumberFor<Block> {
				self.inner.beacon_start.clone()
			}

			fn beacon_period(&self) -> NumberFor<Block> {
				self.inner.beacon_period.clone()
			}
		}
	}

	#[test]
	fn starts_messaging_on_nonce_notification() {
		let threshold = 1;

		let server = serve();
		let (mut ni_tx, ni_rx) = channel(1);
		let (tx, _rx) = std::sync::mpsc::channel();
		let randomness_tx = Some(tx);

		let public_keybox_parts = Some((
			Some(0),
			vec![VerifyKey::default()],
			VerifyKey::default(),
			threshold,
		));
		let storage_key_sk = Some(KEY.to_vec());
		let runtime_api = Arc::new(TestApi::new(
			None,
			0,
			threshold,
			Some(0),
			None,
			public_keybox_parts,
			storage_key_sk,
			0,
			1,
		));
		let network = TestNetwork::default();

		let mut alice_rg = RandomnessGossip::new(
			threshold,
			ni_rx,
			network.clone(),
			randomness_tx,
			runtime_api,
			0,
		);

		let ni = NonceInfo {
			nonce: Hash::default(),
			height: BlockNumber::default(),
		};
		assert!(ni_tx.try_send(ni.clone()).is_ok());

		futures::executor::block_on(futures::future::poll_fn(|cx| {
			for _ in 0..50 {
				let res = alice_rg.poll_unpin(cx);
				info!("res: {:?}", res);
				if let Poll::Ready(()) = res {
					unreachable!("As long as network is alive, RandomnessGossip should go on.");
				}
			}
			Poll::Ready(())
		}));
		assert!(alice_rg.topics.contains_key(&ni.nonce));
		server.close();
	}

	#[test]
	#[ignore]
	fn gathers_shares() {
		let threshold = 2;
		let network = TestNetwork::default();

		let server = serve();

		let public_keybox_parts = Some((
			Some(0),
			vec![VerifyKey::default()],
			VerifyKey::default(),
			threshold,
		));
		let storage_key_sk = Some(KEY.to_vec());
		let runtime_api = Arc::new(TestApi::new(
			Some(VerifyKey::default()),
			0,
			threshold,
			Some(0),
			None,
			public_keybox_parts,
			storage_key_sk,
			0,
			1,
		));

		let (tx, alice_rrx) = std::sync::mpsc::channel();
		let alice_rtx = Some(tx);
		let (mut alice_ni_tx, alice_ni_rx) = channel(1);

		let mut alice_rg = RandomnessGossip::new(
			threshold,
			alice_ni_rx,
			network.clone(),
			alice_rtx,
			runtime_api.clone(),
			0,
		);

		let (tx, bob_rrx) = std::sync::mpsc::channel();
		let bob_rtx = Some(tx);
		let (mut bob_ni_tx, bob_ni_rx) = channel(1);

		let mut bob_rg = RandomnessGossip::new(
			threshold,
			bob_ni_rx,
			network.clone(),
			bob_rtx,
			runtime_api,
			0,
		);

		let ni = NonceInfo {
			nonce: Hash::default(),
			height: BlockNumber::default(),
		};

		assert!(alice_ni_tx.try_send(ni.clone()).is_ok());
		assert!(bob_ni_tx.try_send(ni.clone()).is_ok());

		futures::executor::block_on(futures::future::poll_fn(|cx| {
			for _ in 0..10 {
				let res = alice_rg.poll_unpin(cx);
				if let Poll::Ready(()) = res {
					unreachable!("As long as network is alive, RandomnessGossip should go on.");
				}
				let res = bob_rg.poll_unpin(cx);
				if let Poll::Ready(()) = res {
					unreachable!("As long as network is alive, RandomnessGossip should go on.");
				}
			}
			Poll::Ready(())
		}));
		assert!(alice_rg.topics.contains_key(&ni.nonce));
		assert!(bob_rg.topics.contains_key(&ni.nonce));
		assert!(alice_rrx.recv().is_ok());
		assert!(bob_rrx.recv().is_ok());
		server.close();
	}
}
