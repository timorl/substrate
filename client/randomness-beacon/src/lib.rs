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

use sp_runtime::{generic::BlockId, traits::Block as BlockT};

use sp_dkg::{DKGApi, Pair, Scalar};
use sp_randomness_beacon::{KeyBox, Nonce, Randomness, Share};

use futures::{channel::mpsc::Receiver, prelude::*};
use parking_lot::Mutex;
use std::{
	collections::HashMap,
	pin::Pin,
	sync::{mpsc::Sender, Arc},
	task::{Context, Poll},
	time,
};

const RANDOMNESS_BEACON_ID: [u8; 4] = *b"rndb";
const RB_PROTOCOL_NAME: &'static str = "/randomness_beacon";
pub const SEND_INTERVAL: time::Duration = time::Duration::from_secs(1);

pub mod authorship;
pub mod import;

pub type ShareBytes = Vec<u8>;

#[derive(Debug, Clone, Encode, Decode)]
pub struct Message {
	pub data: ShareBytes,
}

#[derive(Debug, Encode, Decode)]
pub struct GossipMessage {
	pub nonce: Nonce,
	pub message: Message,
}

fn nonce_to_topic<B: BlockT>(nonce: Nonce) -> B::Hash {
	B::Hash::decode(&mut &*nonce).unwrap()
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
/// for BLS threshold signatures. The appropriate logic for that will be
/// added in Milestone 2 (when BLS crypto will be incorporated in the code).
impl<B: BlockT> Validator<B> for GossipValidator {
	fn validate(
		&self,
		_context: &mut dyn ValidatorContext<B>,
		_sender: &PeerId,
		data: &[u8],
	) -> ValidationResult<B::Hash> {
		match GossipMessage::decode(&mut data.clone()) {
			Ok(gm) => {
				let topic = nonce_to_topic::<B>(gm.nonce);
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
	nonce: Nonce,
	msg: Message,
	gossip_engine: Arc<Mutex<GossipEngine<B>>>,
}

impl<B: BlockT> OutgoingMessage<B> {
	fn send(&self) {
		let message = GossipMessage {
			nonce: self.nonce.clone(),
			message: self.msg.clone(),
		};
		let topic = nonce_to_topic::<B>(self.nonce.clone());
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
			OutgoingMessage<B>,
			futures_timer::Delay,
			Vec<Share>,
		),
	>,
	keybox: Option<KeyBox>,
	gossip_engine: Arc<Mutex<GossipEngine<B>>>,
	randomness_nonce_rx: Receiver<Nonce>,
	randomness_tx: Option<Sender<Randomness>>,
	dkg_api: Arc<C>,
	http_rpc_port: u16,
}

impl<B: BlockT, C> Unpin for RandomnessGossip<B, C> {}

/// The component used for gossiping and combining shares of randomness.
impl<B: BlockT, C> RandomnessGossip<B, C>
where
	C: sp_api::ProvideRuntimeApi<B>,
	C::Api: DKGApi<B>,
{
	pub fn new<N: Network<B> + Send + Clone + 'static>(
		threshold: u64,
		randomness_nonce_rx: Receiver<Nonce>,
		network: N,
		randomness_tx: Option<Sender<Randomness>>,
		dkg_api: Arc<C>,
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
			keybox: None,
			gossip_engine,
			randomness_nonce_rx,
			randomness_tx,
			dkg_api,
			http_rpc_port,
		}
	}

	fn initialize_nonce(
		&self,
		nonce: Nonce,
	) -> (Receiver<TopicNotification>, OutgoingMessage<B>, Vec<Share>) {
		let topic = nonce_to_topic::<B>(nonce.clone());

		let incoming = self
			.gossip_engine
			.lock()
			.messages_for(topic)
			.filter_map(move |notification| {
				let decoded = GossipMessage::decode(&mut &notification.message[..]);
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

		let share = self.keybox.as_ref().unwrap().generate_share(&nonce);

		let msg = Message {
			data: share.encode(),
		};

		let outgoing = OutgoingMessage::<B> {
			msg,
			nonce: nonce,
			gossip_engine: self.gossip_engine.clone(),
		};

		let mut shares = Vec::new();
		if share.is_some() {
			shares.push(share.unwrap())
		}

		(incoming, outgoing, shares)
	}

	fn get_keybox(&mut self, nonce: &Nonce) {
		let block_hash = <B as BlockT>::Hash::decode(&mut &nonce[..]).unwrap();

		use hyper::rt;
		use hyper::rt::Future;
		use jsonrpc_core_client::transports::http;
		use sc_rpc::offchain::OffchainClient;
		use sp_core::{offchain::StorageKind, Bytes};

		let (ix, verification_keys, master_key, t) = match self
			.dkg_api
			.runtime_api()
			.public_keybox_parts(&BlockId::Hash(block_hash))
		{
			Ok(Some((ix, vks, mvk, t))) => (ix, vks, mvk, t),
			Ok(None) | Err(_) => return,
		};
		let (tx, rx) = std::sync::mpsc::channel();
		let tx = Mutex::new(tx);
		let url = format!("http://localhost:{}", self.http_rpc_port);
		rt::run(rt::lazy(move || {
			http::connect(url.as_str())
				.and_then(move |client: OffchainClient| {
					client
						.get_local_storage(
							StorageKind::PERSISTENT,
							Bytes(b"dkw::threshold_secret_key".to_vec()),
						)
						.map(move |enc_key| {
							let raw_key = <[u64; 4]>::decode(&mut &enc_key.unwrap()[..]).unwrap();
							if let Err(e) = tx.lock().send(raw_key) {
								info!("Error while sending raw_key {:?}", e);
							}
						})
				})
				.map_err(|e| info!("didn't get key with err {:?}", e))
		}));
		let raw_key = rx.recv().unwrap();
		let share_provider = Pair::from_secret(Scalar::from_raw(raw_key));

		self.keybox = Some(KeyBox::new(
			ix as u64,
			Some(share_provider),
			verification_keys,
			master_key,
			t,
		));
	}
}

impl<B: BlockT, C> Future for RandomnessGossip<B, C>
where
	C: sp_api::ProvideRuntimeApi<B>,
	C::Api: DKGApi<B>,
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
		let new_nonce = match self.randomness_nonce_rx.poll_next_unpin(cx) {
			Poll::Pending => None,
			Poll::Ready(None) => return Poll::Ready(()),
			Poll::Ready(new_nonce) => new_nonce,
		};

		// TODO: add a mechanism for clearing old topics
		if new_nonce.is_none() && self.topics.is_empty() {
			return Poll::Pending;
		}

		if self.keybox.is_none() {
			// get the keybox from dkg
			// TODO maybe it would be better to start collecting shares after some specific block
			// number, but currently RandomnessGossip is not aware of block numbers
			// TODO error handling
			self.get_keybox(new_nonce.as_ref().unwrap());
			if self.keybox.is_none() {
				return Poll::Pending;
			}
		}

		if new_nonce.is_some() {
			let new_nonce = new_nonce.unwrap();

			let topic = nonce_to_topic::<B>(new_nonce.clone());
			// received new nonce, start collecting signatures for it
			if !self.topics.contains_key(&topic) {
				let (incoming, outgoing, shares) = self.initialize_nonce(new_nonce.clone());
				let periodic_sender = futures_timer::Delay::new(SEND_INTERVAL);
				self.topics
					.insert(topic, (incoming, outgoing, periodic_sender, shares));
			}
		}
		let randomness_tx = self.randomness_tx.clone();
		let keybox = self.keybox.clone().unwrap();
		let threshold = self.threshold.clone();

		for (_, (incoming, outgoing, periodic_sender, shares)) in self.topics.iter_mut() {
			while let Poll::Ready(()) = periodic_sender.poll_unpin(cx) {
				periodic_sender.reset(SEND_INTERVAL);
				outgoing.send();
			}

			let poll = incoming.poll_next_unpin(cx);
			match poll {
				Poll::Ready(Some(notification)) => {
					let GossipMessage { message, .. } =
						GossipMessage::decode(&mut &notification.message[..]).unwrap();
					let share: Share = Decode::decode(&mut &*message.data).unwrap();
					if keybox.verify_share(&share) {
						shares.push(share);
						// TODO: the following needs an overhaul
						if shares.len() == threshold as usize {
							let randomness = keybox.combine_shares(shares);

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
				Poll::Ready(None) => info!(
					target: RB_PROTOCOL_NAME,
					"poll_next_unpin returned Ready(None) ==> investigate!"
				),
				Poll::Pending => {}
			}
		}

		if !self.topics.is_empty() {
			return Poll::Pending;
		}

		Poll::Ready(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	//use futures::channel::mpsc::channel;
	use futures::channel::mpsc::{unbounded, UnboundedSender};
	use sc_network::{Event, ReputationChange};
	use sc_network_gossip::Network;
	use sp_runtime::traits::Block as BlockT;
	use sp_runtime::ConsensusEngineId;
	use std::borrow::Cow;
	use std::sync::{Arc, Mutex};
	//use substrate_test_runtime_client::{runtime::Block, Backend, Client};

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

	// TODO fixme
	//#[test]
	//#[ignore]
	//fn starts_messaging_on_nonce_notification() {
	//	let (mut a_notify_nonce_tx, a_notify_nonce_rx) = channel(10);
	//	let (tx, _a_randomness_rx) = std::sync::mpsc::channel();
	//	let a_randomness_tx = Some(tx);

	//	let client = Arc::new(substrate_test_runtime_client::new());
	//	let network = TestNetwork::default();

	//	let threshold = 2;
	//	let rpc_port = 0;

	//	let mut alice_rg = RandomnessGossip::new(
	//		threshold,
	//		a_notify_nonce_rx,
	//		network.clone(),
	//		a_randomness_tx,
	//		client,
	//		rpc_port,
	//	);

	//	let nonce = H256::default();
	//	let enc_nonce = H256::default().encode();
	//	assert!(a_notify_nonce_tx.try_send(enc_nonce.clone()).is_ok());

	//	block_on(poll_fn(|cx| {
	//		for _ in 0..50 {
	//			let res = alice_rg.poll_unpin(cx);
	//			info!("res: {:?}", res);
	//			if let Poll::Ready(()) = res {
	//				unreachable!("As long as network is alive, RandomnessGossip should go on.");
	//			}
	//		}
	//		Poll::Ready(())
	//	}));
	//	assert!(alice_rg.topics.contains_key(&nonce));
	//}
}
