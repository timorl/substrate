//use async_std::task::spawn;
//use futures::{channel::mpsc::{unbounded, UnboundedSender}, executor::{block_on, block_on_stream}, future::poll_fn};
//use quickcheck::{Arbitrary, Gen, QuickCheck};
//use rand::Rng;
//use sc_network::ObservedRole;
use sp_runtime::{traits::{Block as BlockT}, ConsensusEngineId};
//use std::convert::TryInto;
//use substrate_test_runtime_client::runtime::Block;
//use sc_network::{Event, ReputationChange};
use sc_network_gossip::{Network, Validator,ValidationResult, ValidatorContext, GossipEngine};
//use futures::prelude::*;
use libp2p::PeerId;
use log::info;
//use log::trace;
use std::{
	sync::Arc,
};

use parking_lot::Mutex;

use std::{pin::Pin, task::{Context, Poll}};
use std::time;
//use std::time::Duration;

use futures::{prelude::*};

//use super::*;


pub const DUMMY_ENGINE_ID: ConsensusEngineId = *b"DUMM";
pub const DUMMY_PROTOCOL_NAME: &[u8] = b"/dummy";
pub const SEND_INTERVAL: time::Duration = time::Duration::from_millis(2000);



struct DummyValidator;
impl<B: BlockT> Validator<B> for DummyValidator {
	fn validate(
		&self,
		_context: &mut dyn ValidatorContext<B>,
		_sender: &PeerId,
		data: &[u8],
	) -> ValidationResult<B::Hash> {
		info!("Do validatora doszedl message: {}", std::str::from_utf8(data).unwrap());
		ValidationResult::ProcessAndKeep(B::Hash::default())
	}
}



pub struct DummyGossiper<B: BlockT> {
	gossip_engine: Arc<Mutex<GossipEngine<B>>>,
	periodic_sender: futures_timer::Delay,
	my_name: String,
	round: u32,
}


impl<B: BlockT> DummyGossiper<B> {
	/// Create a new instance.
	pub fn new<N: Network<B> + Send + Clone + 'static>(
		network: N,
		name: String,
	) -> Self where B: 'static {
		let validator = Arc::new(DummyValidator{});
		let gossip_engine = Arc::new(Mutex::new(GossipEngine::new(
			network.clone(),
			DUMMY_ENGINE_ID,
			DUMMY_PROTOCOL_NAME,
			validator.clone()
		)));
		DummyGossiper {
			gossip_engine: gossip_engine.clone(),
			periodic_sender: futures_timer::Delay::new(SEND_INTERVAL),
			my_name: name.clone(),
			round: 0,
		}
	}
}

impl<B: BlockT> Future for DummyGossiper<B> {
	type Output = ();

	fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
		let this = &mut *self;
		match this.gossip_engine.lock().poll_unpin(cx) {
			//gossip_engine should never return Ready(), so it would be better to return an error
			Poll::Ready(()) => return Poll::Ready(()),
			Poll::Pending => {},
		}

		while let Poll::Ready(()) = this.periodic_sender.poll_unpin(cx) {
			this.periodic_sender.reset(SEND_INTERVAL);
			this.round = this.round+1;
			let message = format!("{} - r {}",this.my_name, this.round);
			info!("Gossiping a message from {}.", message.clone());
			let message_bytes = message.into_bytes();
			this.gossip_engine.lock().gossip_message(B::Hash::default(), message_bytes, false);
		}

		Poll::Pending
	}
}




