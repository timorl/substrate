use codec::Encode;
use log::info;
use parking_lot::Mutex;
use sc_client_api::backend;
use sp_api::{ApiExt, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_randomness_beacon::{inherents::INHERENT_IDENTIFIER, Randomness};
use sp_transaction_pool::TransactionPool;
use std::{collections::HashMap, sync::mpsc::Receiver, sync::Arc, time};

use futures::future;
use sc_block_builder::{BlockBuilderApi, BlockBuilderProvider};
use sp_consensus::{Proposal, RecordProof};
use sp_inherents::InherentData;
use sp_runtime::traits::{Block as BlockT, DigestFor, Header as HeaderT};

use prometheus_endpoint::Registry as PrometheusRegistry;

use super::Nonce;

/// Proposer factory.
pub struct ProposerFactory<A, B, C> {
	/// Inner propeser
	inner: sc_basic_authorship::ProposerFactory<A, B, C>,
	/// Receiver new randomness
	randomness_rx: Arc<Mutex<Receiver<Randomness>>>,
	/// Set of available random bytes
	available_randomness: Arc<Mutex<HashMap<Nonce, Randomness>>>,
}

impl<A, B, C> ProposerFactory<A, B, C> {
	pub fn new(
		client: Arc<C>,
		transaction_pool: Arc<A>,
		prometheus: Option<&PrometheusRegistry>,
		randomness_rx: Arc<Mutex<Receiver<Randomness>>>,
	) -> Self {
		ProposerFactory {
			inner: sc_basic_authorship::ProposerFactory::new(client, transaction_pool, prometheus),
			randomness_rx,
			available_randomness: Arc::new(Mutex::new(HashMap::new())),
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
	type Proposer = Proposer<B, Block, C, A>;
	type Error = sp_blockchain::Error;

	fn init(&mut self, parent_header: &<Block as BlockT>::Header) -> Self::CreateProposer {
		let parent_number = *parent_header.number();
		let mut proposer_nonce = None;
		// TODO should use global constant
		if parent_number >= 1.into() {
			let parent_hash = parent_header.hash();
			let nonce = <Block as BlockT>::Hash::encode(&parent_hash);
			proposer_nonce = Some(nonce);
		}
		future::ready(Ok(Proposer {
			inner: self
				.inner
				.init_with_now(parent_header, Box::new(time::Instant::now)),
			available_randomness: self.available_randomness.clone(),
			randomness_rx: self.randomness_rx.clone(),
			nonce: proposer_nonce,
		}))
	}
}

pub struct Proposer<B, Block: BlockT, C, A: TransactionPool> {
	inner: sc_basic_authorship::Proposer<B, Block, C, A>,
	available_randomness: Arc<Mutex<HashMap<Nonce, Randomness>>>,
	randomness_rx: Arc<Mutex<Receiver<Randomness>>>,
	nonce: Option<Nonce>,
}

impl<A, B, Block, C> sp_consensus::Proposer<Block> for Proposer<B, Block, C, A>
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
	type Transaction = backend::TransactionFor<B, Block>;
	type Proposal =
		tokio_executor::blocking::Blocking<Result<Proposal<Block, Self::Transaction>, Self::Error>>;
	type Error = sp_blockchain::Error;

	fn propose(
		self,
		inherent_data: InherentData,
		inherent_digests: DigestFor<Block>,
		max_duration: time::Duration,
		record_proof: RecordProof,
	) -> Self::Proposal {
		// we leave some time for actually preparing the block
		let now = time::Instant::now();
		let deadline = now + max_duration - max_duration / 3;

		let mut randomness = None;
		if let Some(nonce) = self.nonce.clone() {
			loop {
				randomness = self.available_randomness.lock().get(&nonce).cloned();
				if randomness.is_some() {
					// randomness for our nonce ready, no need to wait anymore
					break;
				}
				let time_left = deadline - time::Instant::now();
				let new_randomness = self.randomness_rx.lock().recv_timeout(time_left);

				match new_randomness {
					Ok(ref randomness) => {
						info!(
							"Adding new randomness {:?} to storage in proposer.",
							randomness
						);
						let nonce = randomness.nonce();
						self.available_randomness
							.lock()
							.insert(nonce, randomness.clone());
					}
					Err(_) => {
						info!(
							"Deadline passed, randomness still not available. Breaking the loop."
						);
						break;
					}
				}
			}
		}

		let mut id = inherent_data.clone();

		match self.nonce {
			Some(_) => match randomness {
				Some(bytes) => {
					info!("Including randomness in inherent_data.");
					let result = id.put_data(INHERENT_IDENTIFIER, &bytes);
					if result.is_err() {
						return tokio_executor::blocking::run(|| {
							Err(sp_blockchain::Error::Msg(
								"error while putting randomness inherent data".to_string(),
							))
						});
					}
				}
				None => {
					info!("Randomness not available in propose. Aborting proposal.");
					return tokio_executor::blocking::run(|| {
						Err(sp_blockchain::Error::Msg("no inherent data".to_string()))
					});
				}
			},
			None => {
				info!("Block Number too low. Not including randomness in inherent_data.");
			}
		}

		self.inner
			.propose(id, inherent_digests, max_duration, record_proof)
	}
}
