use codec::Encode;
use log::info;
use parking_lot::Mutex;
use sc_client_api::backend;
use sp_api::{ApiExt, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_transaction_pool::TransactionPool;
use std::{collections::HashMap, sync::mpsc::Receiver, sync::Arc, time};
use sp_randomness_beacon::inherents::{INHERENT_IDENTIFIER};

use sc_block_builder::{BlockBuilderApi, BlockBuilderProvider};
use sp_consensus::{Proposal, RecordProof};
use sp_inherents::InherentData;
use sp_runtime::traits::{Block as BlockT, DigestFor, Header as HeaderT};
use futures::future;

use prometheus_endpoint::Registry as PrometheusRegistry;

use super::Nonce;

/// Proposer factory.
pub struct ProposerFactory<A, B, C> {
	/// Inner propeser
	inner: sc_basic_authorship::ProposerFactory<A, B, C>,
	/// Receiver of pairs: (nonce, random_bytes)
	randomness_bytes_rx: Arc<Mutex<Receiver<(Nonce,Vec<u8>)>>>,
	/// Set of available random bytes
	available_random_bytes: Arc<Mutex<HashMap<Nonce, Vec<u8>>>>,
}

impl<A, B, C> ProposerFactory<A, B, C> {
	pub fn new(
		client: Arc<C>,
		transaction_pool: Arc<A>,
		prometheus: Option<&PrometheusRegistry>,
		randomness_bytes_rx: Arc<Mutex<Receiver<(Nonce,Vec<u8>)>>>,
	) -> Self {
		ProposerFactory {
			inner: sc_basic_authorship::ProposerFactory::new(client, transaction_pool, prometheus),
			randomness_bytes_rx,
			available_random_bytes: Arc::new(Mutex::new(HashMap::new())),
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
		//	if !self.available_random_bytes.contains(&nonce) {
		// 		loop {
		// 			info!(
		// 				target: "ProposerFactory",
		// 				"unavailable random bytes for hash {:?} of block number {:?}",
		// 				parent_hash,
		// 				parent_header.number()
		// 			);
		// 			// TODO: handle error
		// 			let new_nonce = self.randomness_notifier.lock().recv().unwrap();
		// 			assert!(
		// 				self.available_random_bytes.insert(new_nonce.clone()),
		// 				"duplicated available_random_bytes notification"
		// 			);
		// 			if nonce == new_nonce {
		// 				proposer_nonce = Some(nonce);
		// 				info!(
		// 					target: "ProposerFactory",
		// 					"got random bytes for hash {:?} of block number {:?}",
		// 					parent_hash,
		// 					parent_number
		// 				);
		// 				break;
		// 			}
		// 		}
		// 	}
		// }
		future::ready(Ok(Proposer {
			inner: self
				.inner
				.init_with_now(parent_header, Box::new(time::Instant::now)),
			available_random_bytes: self.available_random_bytes.clone(),
			randomness_bytes_rx: self.randomness_bytes_rx.clone(),
			nonce: proposer_nonce
		}))
	}
}

pub struct Proposer<B, Block: BlockT, C, A: TransactionPool> {
	inner: sc_basic_authorship::Proposer<B, Block, C, A>,
	available_random_bytes: Arc<Mutex<HashMap<Nonce, Vec<u8>>>>,
	randomness_bytes_rx: Arc<Mutex<Receiver<(Nonce,Vec<u8>)>>>,
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



		let mut random_bytes: Option<Nonce> = None;
		if let Some(nonce) = self.nonce.clone() {
			loop {
				random_bytes = self.available_random_bytes.lock().get(&nonce).cloned();
				if random_bytes.is_some() {
					// random_bytes for our nonce ready, no need to wait anymore
					break;
				}
				let time_left = deadline - time::Instant::now();
				let new_random_bytes = self.randomness_bytes_rx.lock().recv_timeout(time_left);

				match new_random_bytes {
					Ok((nonce, bytes)) => {
						info!("Adding new random_bytes {:?} {:?} to storage in proposer.", nonce, bytes);
						self.available_random_bytes.lock().insert(nonce, bytes);
					},
					Err(_) => {
						info!("Deadline passed, random_bytes still not available. Breaking the loop.");
						break;
					}
				}

			}
		}

		let mut id = inherent_data.clone();

		match self.nonce {
			Some(_) => {
				match random_bytes {
					Some(bytes) => {
						info!("Including random_bytes in inherent_data.");
						let result = id.put_data(INHERENT_IDENTIFIER, &bytes);
						if result.is_err() {
							return tokio_executor::blocking::run(|| {
								Err(sp_blockchain::Error::Msg("error while putting random_bytes inherent data".to_string()))
							});
						}
					},
					None => {
						info!("Random_bytes not available in propose. Aborting proposal.");
						return tokio_executor::blocking::run(|| {
							Err(sp_blockchain::Error::Msg("no inherent data".to_string()))
						});
					},
				}
			},
			None => {
				info!("Block Number too low. Not including random_bytes in inherent_data.");
			},
		}




		// if let Some(nonce) = self.nonce {
		// 	let list_nonce_random_bytes: Option<Vec<(Vec<u8>, Vec<u8>)>> = inherent_data
		// 		.get_data(&sp_randomness_beacon::inherents::INHERENT_IDENTIFIER)
		// 		.unwrap_or_default();
		// 	// safe as !self.nonce.is_none implies that we put sth into inherent_data
		// 	let mut not_found = true;
		// 	for (n, _) in list_nonce_random_bytes.unwrap() {
		// 		if n == nonce {
		// 			not_found = false;
		// 		}
		// 	}
		// 	if not_found {
		// 		return tokio_executor::blocking::run(|| {
		// 			Err(sp_blockchain::Error::Msg("no inherent data".to_string()))
		// 		});
		// 	}
		// }
		self.inner
			.propose(id, inherent_digests, max_duration, record_proof)
	}
}
