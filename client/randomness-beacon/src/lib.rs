use codec::{Decode, Encode};
use log::info;

use sc_network::{NetworkService, PeerId};
use sc_network_gossip::{
	GossipEngine, TopicNotification, ValidationResult, Validator, ValidatorContext,
};

use sp_core::{crypto::Pair, traits::BareCryptoStorePtr};
use sp_runtime::traits::Block as BlockT;

use sp_randomness_beacon::{
	inherents::InherentType, KeyBox, Nonce, RandomnessVerifier, Share, ShareProvider,
};

use futures::{channel::mpsc::Receiver, prelude::*};
use parking_lot::{Mutex, RwLock};
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

pub const KEY_TYPE: sp_core::crypto::KeyTypeId = sp_application_crypto::key_types::DUMMY;
mod app {
	use sp_application_crypto::{app_crypto, ed25519, key_types::DUMMY};
	app_crypto!(ed25519, DUMMY);
}

pub type AuthorityId = app::Public;
pub type AuthoritySignature = app::Signature;

pub struct LocalIdKeystore((AuthorityId, BareCryptoStorePtr));

impl LocalIdKeystore {
	fn _local_id(&self) -> &AuthorityId {
		&(self.0).0
	}

	fn keystore(&self) -> &BareCryptoStorePtr {
		&(self.0).1
	}
}

impl AsRef<BareCryptoStorePtr> for LocalIdKeystore {
	fn as_ref(&self) -> &BareCryptoStorePtr {
		self.keystore()
	}
}

impl From<(AuthorityId, BareCryptoStorePtr)> for LocalIdKeystore {
	fn from(inner: (AuthorityId, BareCryptoStorePtr)) -> LocalIdKeystore {
		LocalIdKeystore(inner)
	}
}

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

fn round_topic<B: BlockT>(nonce: Nonce) -> B::Hash {
	//B::Hash::decode(&mut nonce.to_vec()).unwrap()
	B::Hash::decode(&mut &*nonce).unwrap()
}

pub struct GossipValidator {
	round: RwLock<u8>,
}

impl GossipValidator {
	pub fn new() -> Self {
		GossipValidator {
			round: RwLock::new(0),
		}
	}

	pub fn note_round(&self, round: u8) {
		*self.round.write() = round;
	}
}

#[derive(Debug, Clone)]
pub enum Error {
	Network(String),
	Signing(String),
}

impl<B: BlockT> Validator<B> for GossipValidator {
	fn validate(
		&self,
		_context: &mut dyn ValidatorContext<B>,
		_sender: &PeerId,
		data: &[u8],
	) -> ValidationResult<B::Hash> {
		match GossipMessage::decode(&mut data.clone()) {
			Ok(gm) => {
				let topic = round_topic::<B>(gm.nonce);
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
		let topic = round_topic::<B>(self.nonce.clone());
		self.gossip_engine
			.lock()
			.gossip_message(topic, message.encode(), true);
	}
}

pub struct NetworkBridge<B: BlockT> {
	threshold: usize,
	topics: HashMap<
		B::Hash,
		(
			Receiver<TopicNotification>,
			OutgoingMessage<B>,
			futures_timer::Delay,
			Vec<Share>,
		),
	>,
	keybox: KeyBox,
	gossip_engine: Arc<Mutex<GossipEngine<B>>>,
	validator: Arc<GossipValidator>,
	randomness_nonce_rx: Receiver<Nonce>,
	randomness_ready_tx: Option<Sender<Nonce>>,
	random_bytes: Arc<Mutex<InherentType>>,
}

impl<B: BlockT> Unpin for NetworkBridge<B> {}

impl<B: BlockT> NetworkBridge<B> {
	pub fn new(
		id: String,
		n_members: usize,
		threshold: usize,
		randomness_nonce_rx: Receiver<Nonce>,
		network: Arc<NetworkService<B, <B as BlockT>::Hash>>,
		random_bytes: Arc<Mutex<InherentType>>,
		randomness_ready_tx: Option<Sender<Nonce>>,
	) -> Self {
		let validator = Arc::new(GossipValidator::new());
		let gossip_engine = Arc::new(Mutex::new(GossipEngine::new(
			network.clone(),
			RANDOMNESS_BEACON_ID,
			RB_PROTOCOL_NAME,
			validator.clone(),
		)));
		//let ids = ["alice", "bob", "charlie", "dave", "eve"];
		let seeds = [
			b"00000000000000000000000000000000",
			b"00000000000000000000000000000001",
			b"00000000000000000000000000000002",
			b"00000000000000000000000000000003",
			b"00000000000000000000000000000004",
		];

		assert!(n_members < seeds.len());
		let mut verify_keys = Vec::new();
		for i in 0..n_members {
			verify_keys.push(ShareProvider::from_seed(seeds[i]).public());
		}
		let id = if id == "Alice" { 0 } else { 1 };
		let share_provider = Pair::from_seed(seeds[id]);
		let master_key = ShareProvider::from_seed(sp_randomness_beacon::MASTER_SEED).public();
		// TODO: actually construct, milestone 2

		let keybox = KeyBox::new(
			id as u32,
			share_provider,
			verify_keys,
			RandomnessVerifier::new(master_key),
			threshold,
		);

		NetworkBridge {
			threshold,
			topics: HashMap::new(),
			keybox,
			gossip_engine,
			validator,
			randomness_nonce_rx,
			randomness_ready_tx,
			random_bytes,
		}
	}

	pub fn note_round(&self, round: u8) {
		self.validator.note_round(round);
	}

	fn round_communication(
		&self,
		nonce: Nonce,
	) -> (Receiver<TopicNotification>, OutgoingMessage<B>, Vec<Share>) {
		// TODO: how to choose rounds?
		let round = 0;
		self.note_round(round);
		let topic = round_topic::<B>(nonce.clone());

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

		let share = self.keybox.generate_share(&nonce);
		let msg = Message {
			data: Encode::encode(&share),
		};

		let outgoing = OutgoingMessage::<B> {
			msg,
			nonce: nonce,
			gossip_engine: self.gossip_engine.clone(),
		};

		(incoming, outgoing, vec![share])
	}
}

impl<B: BlockT> Future for NetworkBridge<B> {
	type Output = ();

	fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
		match self.gossip_engine.lock().poll_unpin(cx) {
			Poll::Ready(()) => {
				return Poll::Ready(info!(
					target: RB_PROTOCOL_NAME,
					"Gossip engine future finished."
				))
			}
			Poll::Pending => {}
		};

		let new_nonce = match self.randomness_nonce_rx.poll_next_unpin(cx) {
			Poll::Pending => None,
			Poll::Ready(None) => return Poll::Ready(()),
			Poll::Ready(new_nonce) => new_nonce, // probably sth else in final version
		};

		if !new_nonce.is_none() {
			let new_nonce = new_nonce.unwrap();
			let topic = round_topic::<B>(new_nonce.clone());
			// received new nonce, start collecting signatures for it
			// TODO: some throttling
			if !self.topics.contains_key(&topic) {
				let (incoming, outgoing, shares) = self.round_communication(new_nonce);
				let periodic_sender = futures_timer::Delay::new(SEND_INTERVAL);
				self.topics
					.insert(topic, (incoming, outgoing, periodic_sender, shares));
			}
		}

		// TODO: add a mechanism for clearing old topics
		if self.topics.is_empty() {
			return Poll::Pending;
		}

		// TODO: refactor this awful borrow checker hack
		let random_bytes = self.random_bytes.clone();
		let randomness_ready_tx = self.randomness_ready_tx.clone();
		let keybox = self.keybox.clone();
		let threshold = self.threshold.clone();

		// TODO: maybe parallelize
		for (_, (incoming, outgoing, periodic_sender, shares)) in self.topics.iter_mut() {
			while let Poll::Ready(()) = periodic_sender.poll_unpin(cx) {
				periodic_sender.reset(SEND_INTERVAL);
				outgoing.send();
			}

			let poll = incoming.poll_next_unpin(cx);
			match poll {
				Poll::Ready(Some(notification)) => {
					let GossipMessage { nonce, message } =
						GossipMessage::decode(&mut &notification.message[..]).unwrap();
					let share: Share = Decode::decode(&mut &*message.data).unwrap();
					if keybox.verify_share(&share) {
						shares.push(share);
						let mut randomness = None;
						// TODO: the following needs an overhaul
						if shares.len() == threshold {
							randomness = keybox.combine_shares(shares);
						}

						// combine shares and on succes put new random_bytes for InherentDataProvider
						if !randomness.is_none() {
							let randomness = randomness.unwrap();
							random_bytes
								.lock()
								.push((nonce.clone(), Encode::encode(&randomness)));
							if let Some(ref randomness_ready_tx) = randomness_ready_tx {
								assert!( randomness_ready_tx.send(nonce).is_ok(), "problem with sending a notification that a new randomness is available");
							}
							info!(
								target: RB_PROTOCOL_NAME,
								"Len of random_bytes: {:?}",
								random_bytes.lock().len()
							);
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
