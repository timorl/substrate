use codec::{Decode, Encode};
use log::info;

use sc_network::{NetworkService, PeerId};
use sc_network_gossip::{
	GossipEngine, TopicNotification, ValidationResult, Validator, ValidatorContext,
};

use sp_core::{crypto::Pair, traits::BareCryptoStorePtr};
use sp_runtime::traits::Block as BlockT;

use sp_randomness_beacon::{KeyBox, Nonce, Randomness, RandomnessVerifier, Share, ShareProvider};

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

pub struct RandomnessGossip<B: BlockT> {
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
	randomness_nonce_rx: Receiver<Nonce>,
	randomness_tx: Option<Sender<Randomness>>,
}

impl<B: BlockT> Unpin for RandomnessGossip<B> {}

impl<B: BlockT> RandomnessGossip<B> {
	pub fn new(
		id: String,
		n_members: usize,
		threshold: usize,
		randomness_nonce_rx: Receiver<Nonce>,
		network: Arc<NetworkService<B, <B as BlockT>::Hash>>,
		randomness_tx: Option<Sender<Randomness>>,
	) -> Self {
		let gossip_engine = Arc::new(Mutex::new(GossipEngine::new(
			network.clone(),
			RANDOMNESS_BEACON_ID,
			RB_PROTOCOL_NAME,
			Arc::new(GossipValidator::new()),
		)));


		// Here the keys are hardcoded in the absence of DKG.
		// This is temporary and will be removed in the 2nd Milestone.
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

		// Currently, for testing purposes, it only supports Alice and Bob.
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

		RandomnessGossip {
			threshold,
			topics: HashMap::new(),
			keybox,
			gossip_engine,
			randomness_nonce_rx,
			randomness_tx,
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

impl<B: BlockT> Future for RandomnessGossip<B> {
	type Output = ();

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

		if !new_nonce.is_none() {
			let new_nonce = new_nonce.unwrap();
			let topic = nonce_to_topic::<B>(new_nonce.clone());
			// received new nonce, start collecting signatures for it
			if !self.topics.contains_key(&topic) {
				let (incoming, outgoing, shares) = self.initialize_nonce(new_nonce);
				let periodic_sender = futures_timer::Delay::new(SEND_INTERVAL);
				self.topics
					.insert(topic, (incoming, outgoing, periodic_sender, shares));
			}
		}

		// TODO: add a mechanism for clearing old topics
		if self.topics.is_empty() {
			return Poll::Pending;
		}

		let randomness_tx = self.randomness_tx.clone();
		let keybox = self.keybox.clone();
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
						let mut randomness = None;
						// TODO: the following needs an overhaul
						if shares.len() >= threshold {
							randomness = keybox.combine_shares(shares);
						}

						// When randomness succesfully combined, notify block proposer
						if randomness.is_some() {
							let randomness = randomness.unwrap();
							if let Some(ref randomness_tx) = randomness_tx {
								assert!( randomness_tx.send(randomness).is_ok(), "problem with sending new randomness to the block proposer");
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
