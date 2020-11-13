//! A wrapper for block proposer used by Randomness Beacon.
//! The block proposing mechanism needs to be synchronized with the Randomness Beacon,
//! because we must guarantee that randomness is included in every block. (Or perhaps
//! every k-th block, but that does not change much). This wrapper ensures that
//! we will always author blocks with randomness included, as during propose() it awaits
//! until suitable randomness arrives in a channel. It might happen that block proposing
//! times out for this reason, but this is necessary, as forcing block creation in the
//! absence of randomness would cause creating an incorrect block, so there is no point
//! in that.

use codec::{Decode, Encode};
use log::info;
use parking_lot::Mutex;
use sc_client_api::backend;
use sp_api::{ApiExt, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_core::traits::SpawnNamed;
use sp_randomness_beacon::{inherents::INHERENT_IDENTIFIER, Randomness};
use sp_transaction_pool::TransactionPool;
use std::{collections::HashMap, pin::Pin, sync::mpsc::Receiver, sync::Arc, time};

use futures::{
	future,
	future::{Future, FutureExt},
};
use sc_block_builder::{BlockBuilderApi, BlockBuilderProvider};
use sp_consensus::{Proposal, RecordProof};
use sp_inherents::InherentData;
use sp_runtime::traits::{Block as BlockT, DigestFor, Header as HeaderT, NumberFor};

use prometheus_endpoint::Registry as PrometheusRegistry;

use super::Nonce;

/// Proposer factory.
pub struct ProposerFactory<A, B, Block: BlockT, C> {
	/// Inner proposer.
	inner: sc_basic_authorship::ProposerFactory<A, B, C>,
	/// Randomness Beacon starting height.
	start_beacon_height: NumberFor<Block>,
	/// Receiver of new randomness.
	randomness_rx: Arc<Mutex<Receiver<Randomness>>>,
	/// The set of available random bytes.
	available_randomness: Arc<Mutex<HashMap<Nonce, Randomness>>>,
}

impl<A, B, Block: BlockT, C> ProposerFactory<A, B, Block, C> {
	pub fn new(
		spawn_handle: impl SpawnNamed + 'static,
		client: Arc<C>,
		transaction_pool: Arc<A>,
		prometheus: Option<&PrometheusRegistry>,
		start_beacon_height: NumberFor<Block>,
		randomness_rx: Arc<Mutex<Receiver<Randomness>>>,
	) -> Self {
		ProposerFactory {
			inner: sc_basic_authorship::ProposerFactory::new(
				spawn_handle,
				client.clone(),
				transaction_pool,
				prometheus,
			),
			start_beacon_height,
			randomness_rx,
			available_randomness: Arc::new(Mutex::new(HashMap::new())),
		}
	}
}

impl<A, B, Block, C> sp_consensus::Environment<Block> for ProposerFactory<A, B, Block, C>
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
		if parent_number + 1.into() >= self.start_beacon_height {
			let parent_hash = parent_header.hash();
			info!(
				"\n\nstart collectig for parent with bn {:?} and hash {:?}\n",
				parent_number, parent_hash
			);
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
	type Proposal = Pin<
		Box<dyn Future<Output = Result<Proposal<Block, Self::Transaction>, Self::Error>> + Send>,
	>;
	type Error = sp_blockchain::Error;

	/// The loop inside of propose makes keeps receiving randomness for various blocks.
	/// At the moment, randomness is ready for the current block, the loop is terminated
	/// and we proceed with block creation. If a deadline for block proposing is reached,
	/// the loop is broken as well and block proposal fails.
	fn propose(
		self,
		inherent_data: InherentData,
		inherent_digests: DigestFor<Block>,
		max_duration: time::Duration,
		record_proof: RecordProof,
	) -> Self::Proposal {
		//TODO: inner uses blocking spawn handle, consider using it for waiting for randomness
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
							"\n\nAdding new randomness {:?}\n for nonce {:?} to storage in proposer.\n",
							new_randomness, <Block as BlockT>::Hash::decode(&mut &randomness.nonce()[..])
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
						return async {
							Err(sp_blockchain::Error::Msg(
								"error while putting randomness inherent data".to_string(),
							))
						}
						.boxed();
					}
				}
				None => {
					info!("Randomness not available in propose. Aborting proposal.");
					return async {
						Err(sp_blockchain::Error::Msg("no inherent data".to_string()))
					}
					.boxed();
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

#[cfg(test)]
mod tests {
	use super::*;

	use parking_lot::Mutex;
	use sc_transaction_pool::BasicPool;
	use sp_consensus::Environment;
	use sp_consensus::{BlockOrigin, Proposer};
	use sp_runtime::generic::BlockId;
	use sp_runtime::traits::NumberFor;
	use sp_transaction_pool::{ChainEvent, MaintainedTransactionPool, TransactionSource};
	use substrate_test_runtime_client::{
		prelude::*,
		runtime::{Extrinsic, Transfer},
	};

	const SOURCE: TransactionSource = TransactionSource::External;

	fn extrinsic(nonce: u64) -> Extrinsic {
		Transfer {
			amount: Default::default(),
			nonce,
			from: AccountKeyring::Alice.into(),
			to: Default::default(),
		}
		.into_signed_tx()
	}

	fn chain_event<B: BlockT>(header: B::Header) -> ChainEvent<B>
	where
		NumberFor<B>: From<u64>,
	{
		ChainEvent::NewBestBlock {
			hash: header.hash(),
			tree_route: None,
		}
	}

	#[test]
	fn correctly_proposes_first_block_in_absence_of_random_bytes() {
		let client = Arc::new(substrate_test_runtime_client::new());
		let spawner = sp_core::testing::TaskExecutor::new();
		let txpool = BasicPool::new_full(Default::default(), None, spawner.clone(), client.clone());

		futures::executor::block_on(txpool.submit_at(
			&BlockId::number(0),
			SOURCE,
			vec![extrinsic(0), extrinsic(1)],
		))
		.unwrap();

		futures::executor::block_on(
			txpool.maintain(chain_event(
				client
					.header(&BlockId::Number(0u64))
					.expect("header get error")
					.expect("there should be header"),
			)),
		);

		let (_tx, rx) = std::sync::mpsc::channel();
		let wrapped_rx = Arc::new(Mutex::new(rx));
		let mut proposer_factory = ProposerFactory::new(
			spawner.clone(),
			client.clone(),
			txpool.clone(),
			None,
			2u64,
			wrapped_rx,
		);

		let proposer_future =
			proposer_factory.init(&client.header(&BlockId::number(0)).unwrap().unwrap());
		let proposer = futures::executor::block_on(proposer_future).unwrap();
		let deadline = time::Duration::from_secs(1);
		let proposal = futures::executor::block_on(proposer.propose(
			Default::default(),
			Default::default(),
			deadline,
			RecordProof::No,
		));
		assert!(proposal.is_ok());
	}

	#[test]
	fn fails_to_propose_second_block_when_random_bytes_not_there() {
		let mut client = Arc::new(substrate_test_runtime_client::new());
		let spawner = sp_core::testing::TaskExecutor::new();
		let txpool = BasicPool::new_full(Default::default(), None, spawner.clone(), client.clone());

		futures::executor::block_on(txpool.submit_at(
			&BlockId::number(0),
			SOURCE,
			vec![extrinsic(0), extrinsic(1)],
		))
		.unwrap();

		futures::executor::block_on(
			txpool.maintain(chain_event(
				client
					.header(&BlockId::Number(0u64))
					.expect("header get error")
					.expect("there should be header"),
			)),
		);

		let (_tx, rx) = std::sync::mpsc::channel();
		let wrapped_rx = Arc::new(Mutex::new(rx));
		let mut proposer_factory = ProposerFactory::new(
			spawner.clone(),
			client.clone(),
			txpool.clone(),
			None,
			2u64,
			wrapped_rx,
		);

		let proposer_future =
			proposer_factory.init(&client.header(&BlockId::number(0)).unwrap().unwrap());
		let proposer = futures::executor::block_on(proposer_future).unwrap();
		let deadline = time::Duration::from_secs(1);
		let proposal = futures::executor::block_on(proposer.propose(
			Default::default(),
			Default::default(),
			deadline,
			RecordProof::No,
		));
		assert!(proposal.is_ok());
		let block = proposal.unwrap().block;
		client.import(BlockOrigin::Own, block).unwrap();

		let proposer_future =
			proposer_factory.init(&client.header(&BlockId::number(1)).unwrap().unwrap());
		let proposer = futures::executor::block_on(proposer_future).unwrap();
		let deadline = time::Duration::from_secs(1);
		let proposal = futures::executor::block_on(proposer.propose(
			Default::default(),
			Default::default(),
			deadline,
			RecordProof::No,
		));
		assert!(proposal.is_err());
	}

	#[test]
	fn fails_to_proposes_second_block_given_randomness_for_different_nonce() {
		let mut client = Arc::new(substrate_test_runtime_client::new());
		let spawner = sp_core::testing::TaskExecutor::new();
		let txpool = BasicPool::new_full(Default::default(), None, spawner.clone(), client.clone());

		futures::executor::block_on(txpool.submit_at(
			&BlockId::number(0),
			SOURCE,
			vec![extrinsic(0), extrinsic(1)],
		))
		.unwrap();

		futures::executor::block_on(
			txpool.maintain(chain_event(
				client
					.header(&BlockId::Number(0u64))
					.expect("header get error")
					.expect("there should be header"),
			)),
		);

		let (tx, rx) = std::sync::mpsc::channel();
		let wrapped_rx = Arc::new(Mutex::new(rx));
		let mut proposer_factory = ProposerFactory::new(
			spawner.clone(),
			client.clone(),
			txpool.clone(),
			None,
			2u64,
			wrapped_rx,
		);

		let proposer_future =
			proposer_factory.init(&client.header(&BlockId::number(0)).unwrap().unwrap());
		let proposer = futures::executor::block_on(proposer_future).unwrap();
		let deadline = time::Duration::from_secs(1);
		let proposal = futures::executor::block_on(proposer.propose(
			Default::default(),
			Default::default(),
			deadline,
			RecordProof::No,
		));
		assert!(proposal.is_ok());
		let block = proposal.unwrap().block;
		client.import(BlockOrigin::Own, block).unwrap();

		//we send randomness for some default nonce -- certainly not the required one
		assert!(tx.send(Default::default()).is_ok());

		let proposer_future =
			proposer_factory.init(&client.header(&BlockId::number(1)).unwrap().unwrap());
		let proposer = futures::executor::block_on(proposer_future).unwrap();
		let deadline = time::Duration::from_secs(1);
		let proposal = futures::executor::block_on(proposer.propose(
			Default::default(),
			Default::default(),
			deadline,
			RecordProof::No,
		));
		assert!(proposal.is_err());
	}
}
