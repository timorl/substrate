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
use log::{info, trace};
use std::{
	sync::Arc,
	sync::Mutex,
};

use std::time::Duration;

use async_std::task;
use futures::{prelude::*};

//use super::*;


pub const DUMMY_ENGINE_ID: ConsensusEngineId = *b"DUMM";
pub const DUMMY_PROTOCOL_NAME: &[u8] = b"/dummy";



struct DummyValidator;
impl<B: BlockT> Validator<B> for DummyValidator {
	fn validate(
		&self,
		_context: &mut dyn ValidatorContext<B>,
		_sender: &PeerId,
		_data: &[u8],
	) -> ValidationResult<B::Hash> {
		ValidationResult::ProcessAndKeep(B::Hash::default())
	}
}



pub fn start_dummy_gossiper<B: BlockT, N>(network: N, name: String) -> impl Future<Output = ()>  where
	N: Network<B> + Send + Sync + Clone + 'static {
	let validator = Arc::new(DummyValidator{});
	let mut gossip_engine = GossipEngine::new(
		network.clone(),
		DUMMY_ENGINE_ID,
		DUMMY_PROTOCOL_NAME,
		validator.clone()
	);
	info!("Gossiping a message from {}.", name);
	trace!(target: "gossip","Gossiping a message from {}.", name);

	let f = async move {
		let message = name.into_bytes();
		task::sleep(Duration::from_secs(3)).await;
		gossip_engine.gossip_message(B::Hash::default(), message.clone(), true);
		task::sleep(Duration::from_secs(3)).await;
		gossip_engine.gossip_message(B::Hash::default(), message.clone(), true);
		task::sleep(Duration::from_secs(3)).await;
		gossip_engine.gossip_message(B::Hash::default(), message.clone(), true);
		gossip_engine.await;
	};

	future::select(gossip_engine, f)
}


