use codec::Encode;
use futures::future;
use log::info;
use parking_lot::Mutex;
use sc_block_builder::{BlockBuilderApi, BlockBuilderProvider};
use sc_client_api::backend;
use sp_api::{ApiExt, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_runtime::traits::{Block as BlockT, Header as HeaderT};
use sp_transaction_pool::TransactionPool;
use std::{collections::HashSet, sync::mpsc::Receiver, sync::Arc, time};

use prometheus_endpoint::Registry as PrometheusRegistry;

use super::Nonce;

/// Proposer factory.
pub struct ProposerFactory<A, B, C> {
	/// Inner proposer
	inner: sc_basic_authorship::ProposerFactory<A, B, C>,
	/// Receiver of notifications
	randomness_notifier: Arc<Mutex<Receiver<Nonce>>>,
	/// Set of available random bytes
	available_random_bytes: HashSet<Nonce>,
}

impl<A, B, C> ProposerFactory<A, B, C> {
	pub fn new(
		client: Arc<C>,
		transaction_pool: Arc<A>,
		prometheus: Option<&PrometheusRegistry>,
		randomness_notifier: Arc<Mutex<Receiver<Nonce>>>,
	) -> Self {
		ProposerFactory {
			inner: sc_basic_authorship::ProposerFactory::new(client, transaction_pool, prometheus),
			randomness_notifier,
			available_random_bytes: HashSet::new(),
		}
	}
}

impl<A, B, Block, C> sp_consensus::Environment<Block> for ProposerFactory<A, B, C>
where
	A: TransactionPool<Block = Block> + 'static,
	B: backend::Backend<Block> + Send + Sync + 'static,
	Block: BlockT,
	C: BlockBuilderProvider<B, Block, C>
		+ HeaderBackend<Block>
		+ ProvideRuntimeApi<Block>
		+ Send
		+ Sync
		+ 'static,
	C::Api: ApiExt<Block, StateBackend = backend::StateBackendFor<B, Block>>
		+ BlockBuilderApi<Block, Error = sp_blockchain::Error>,
{
	type CreateProposer = future::Ready<Result<Self::Proposer, Self::Error>>;
	type Proposer = sc_basic_authorship::Proposer<B, Block, C, A>;
	type Error = sp_blockchain::Error;

	fn init(&mut self, parent_header: &<Block as BlockT>::Header) -> Self::CreateProposer {
		let parent_number = *parent_header.number();
		// TODO should use global constant
		if parent_number > 1.into() {
			let parent_hash = parent_header.hash();
			let nonce = <Block as BlockT>::Hash::encode(&parent_hash);
			if !self.available_random_bytes.contains(&nonce) {
				loop {
					info!(
						target: "ProposerFactory",
						"unavailable random bytes for hash {:?} of block number {:?}",
						parent_hash,
						parent_header.number()
					);
					// TODO: handle error
					let new_nonce = self.randomness_notifier.lock().recv().unwrap();
					assert!(
						self.available_random_bytes.insert(new_nonce.clone()),
						"duplicated available_random_bytes notification"
					);
					if nonce == new_nonce {
						info!(
							target: "ProposerFactory",
							"got random bytes for hash {:?} of block number {:?}",
							parent_hash,
							parent_number
						);
						break;
					}
				}
			}
		}
		future::ready(Ok(self
			.inner
			.init_with_now(parent_header, Box::new(time::Instant::now))))
	}
}
