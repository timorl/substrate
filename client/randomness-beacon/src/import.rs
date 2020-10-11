use codec::Encode;
use futures::channel::mpsc::Sender;
use log::info;
use sc_client_api::{backend::AuxStore, BlockOf};
use sp_api::ProvideRuntimeApi;
use sp_block_builder::BlockBuilder as BlockBuilderApi;
use sp_blockchain::{well_known_cache_keys::Id as CacheKeyId, HeaderBackend, ProvideCache};
use sp_consensus::{
	BlockCheckParams, BlockImport, BlockImportParams, Error as ConsensusError, ImportResult,
};
use sp_randomness_beacon::Nonce;

use sp_runtime::{generic::BlockId, traits::Block as BlockT};
use std::{collections::HashMap, marker, sync::Arc};

#[derive(derive_more::Display, Debug)]
pub enum Error {
	TransmitErr,
	Client(sp_blockchain::Error),
	#[display(fmt = "Checking inherents failed: {}", _0)]
	CheckInherents(String),
	DataProvider(String),
}

impl std::convert::From<Error> for ConsensusError {
	fn from(error: Error) -> ConsensusError {
		ConsensusError::ClientImport(error.to_string())
	}
}

use super::ShareBytes;

pub struct RandomnessBeaconBlockImport<B: BlockT, I, C> {
	inner: I,
	client: Arc<C>,
	random_bytes_buf: HashMap<Nonce, Option<ShareBytes>>,
	randomness_nonce_tx: Sender<Nonce>,
	_marker: marker::PhantomData<B>,
}

impl<B: BlockT, I: Clone, C> Clone for RandomnessBeaconBlockImport<B, I, C> {
	fn clone(&self) -> Self {
		Self {
			inner: self.inner.clone(),
			client: self.client.clone(),
			random_bytes_buf: self.random_bytes_buf.clone(),
			randomness_nonce_tx: self.randomness_nonce_tx.clone(),
			_marker: marker::PhantomData,
		}
	}
}

impl<B, I, C> RandomnessBeaconBlockImport<B, I, C>
where
	B: BlockT,
	I: BlockImport<B, Transaction = sp_api::TransactionFor<C, B>> + Send + Sync,
	I::Error: Into<ConsensusError>,
	C: ProvideRuntimeApi<B> + Send + Sync + HeaderBackend<B> + AuxStore + ProvideCache<B> + BlockOf,
	C::Api: BlockBuilderApi<B, Error = sp_blockchain::Error>,
{
	pub fn new(inner: I, client: Arc<C>, randomness_nonce_tx: Sender<Nonce>) -> Self {
		Self {
			inner,
			client,
			random_bytes_buf: HashMap::new(),
			randomness_nonce_tx,
			_marker: marker::PhantomData,
		}
	}
	// Returns None is hash was already processed.
	fn hash_to_nonce(&mut self, hash: <B as BlockT>::Hash) -> Option<Nonce> {
		// Check if hash was already processed
		// TODO: is this check enough?
		match self.client.status(BlockId::Hash(hash)) {
			Ok(sp_blockchain::BlockStatus::InChain) => return None,
			_ => {}
		}
		let nonce = <B as BlockT>::Hash::encode(&hash);
		match self.random_bytes_buf.get(&nonce) {
			Some(_) => return None,
			None => return Some(nonce),
		}
	}
}

impl<B, I, C> BlockImport<B> for RandomnessBeaconBlockImport<B, I, C>
where
	B: BlockT,
	I: BlockImport<B, Transaction = sp_api::TransactionFor<C, B>> + Send + Sync,
	I::Error: Into<ConsensusError>,
	C: ProvideRuntimeApi<B> + Send + Sync + HeaderBackend<B> + AuxStore + ProvideCache<B> + BlockOf,
	C::Api: BlockBuilderApi<B, Error = sp_blockchain::Error>,
{
	type Error = ConsensusError;
	type Transaction = sp_api::TransactionFor<C, B>;

	fn check_block(&mut self, block: BlockCheckParams<B>) -> Result<ImportResult, Self::Error> {
		self.inner.check_block(block).map_err(Into::into)
	}

	fn import_block(
		&mut self,
		block: BlockImportParams<B, Self::Transaction>,
		new_cache: HashMap<CacheKeyId, Vec<u8>>,
	) -> Result<ImportResult, Self::Error> {
		if let Some(nonce) = self.hash_to_nonce(block.post_hash()) {
			if let Err(err) = self.randomness_nonce_tx.try_send(nonce.clone()) {
				info!(target: "import", "error when try_send topic through notifier {}", err);
				return Err(Error::TransmitErr.into());
			}
			self.random_bytes_buf.insert(nonce, None);
		}

		// TODO: maybe first check if we can import the block, and then start collecting shares
		self.inner
			.import_block(block, new_cache)
			.map_err(Into::into)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use sp_consensus::BlockOrigin;

	#[test]
	fn correctly_sends_nonce() {
		let client = std::sync::Arc::new(substrate_test_runtime_client::new());
		let (tx, mut rx) = futures::channel::mpsc::channel(1);
		let mut import = RandomnessBeaconBlockImport::new(client.clone(), client.clone(), tx);

		let header = sp_runtime::generic::Header::new_from_number(1);
		let block = BlockImportParams::new(BlockOrigin::Own, header);
		let target_nonce = codec::Encode::encode(&block.post_hash());
		let res = import.import_block(block, HashMap::new());
		assert!(res.is_ok());

		assert!(nonce[..] == target_nonce[..]);
	}
}
