//! A wrapper for block import used by Randomness Beacon.
//! This is used to provide notifications to a Randomness Beacon committee member
//! that a new block has been created, and thus it should initialize gossip for
//! randomness shares for this new block. These notifications happen via a channel
//! which has the transmitting end in block import (here) and the receiving end
//! in a RandomnessGossip component.

use futures::channel::mpsc::Sender;
use log::info;
use sc_client_api::{backend::AuxStore, BlockOf};
use sp_api::ProvideRuntimeApi;
use sp_block_builder::BlockBuilder as BlockBuilderApi;
use sp_blockchain::{well_known_cache_keys::Id as CacheKeyId, HeaderBackend, ProvideCache};
use sp_consensus::{
	BlockCheckParams, BlockImport, BlockImportParams, Error as ConsensusError, ImportResult,
};

use sp_runtime::traits::{Block as BlockT, Header};
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

use super::NonceInfo;

pub struct RandomnessBeaconBlockImport<B: BlockT, I, C> {
	inner: I,
	client: Arc<C>,
	randomness_nonce_tx: Sender<NonceInfo<B>>,
	_marker: marker::PhantomData<B>,
}

impl<B: BlockT, I: Clone, C> Clone for RandomnessBeaconBlockImport<B, I, C> {
	fn clone(&self) -> Self {
		Self {
			inner: self.inner.clone(),
			client: self.client.clone(),
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
	pub fn new(inner: I, client: Arc<C>, randomness_nonce_tx: Sender<NonceInfo<B>>) -> Self {
		Self {
			inner,
			client,
			randomness_nonce_tx,
			_marker: marker::PhantomData,
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

	/// Here we send a notification through self.randomness_nonce_tx that a new block
	/// have been imported.
	fn import_block(
		&mut self,
		block: BlockImportParams<B, Self::Transaction>,
		new_cache: HashMap<CacheKeyId, Vec<u8>>,
	) -> Result<ImportResult, Self::Error> {
		let nonce = block.post_hash();
		let num = block.header.number().clone();
		let res = self
			.inner
			.import_block(block, new_cache)
			.map_err(Into::into);

		if res.is_err() {
			info!(target: "import", "error when importing to inner {:?}", res);
			return res;
		}

		info!("We've got a block number {:?}", num);
		if let Err(err) = self
			.randomness_nonce_tx
			.try_send(NonceInfo::new(nonce, num))
		{
			info!(target: "import", "error when try_send topic through notifier {}", err);
			return Err(Error::TransmitErr.into());
		}

		res
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

		let ni = rx.try_next().unwrap().unwrap();
		assert!(ni.nonce()[..] == target_nonce[..]);
	}
}
