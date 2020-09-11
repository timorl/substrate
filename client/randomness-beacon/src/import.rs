use futures::channel::mpsc::Sender;
use log::info;
use sc_client_api::{backend::AuxStore, BlockOf};
use sp_api::ProvideRuntimeApi;
use sp_block_builder::BlockBuilder as BlockBuilderApi;
use sp_blockchain::{well_known_cache_keys::Id as CacheKeyId, HeaderBackend, ProvideCache};
use sp_consensus::{
    BlockCheckParams, BlockImport, BlockImportParams, Error as ConsensusError, ImportResult,
};
use sp_inherents::InherentData;
use sp_runtime::traits::{Block as BlockT, Header as HeaderT};
use std::{collections::HashMap, sync::Arc};

#[derive(derive_more::Display, Debug)]
pub enum Error {
    TransmitErr,
}

impl std::convert::From<Error> for ConsensusError {
    fn from(error: Error) -> ConsensusError {
        ConsensusError::ClientImport(error.to_string())
    }
}

use super::Nonce;

pub struct RandomnessBeaconBlockImport<B: BlockT, I, C> {
    inner: I,
    client: Arc<C>,
    randomness_nonce_tx: Sender<Nonce<B>>,
    check_inherents_after: <<B as BlockT>::Header as HeaderT>::Number,
}

impl<B: BlockT, I: Clone, C> Clone for RandomnessBeaconBlockImport<B, I, C> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            client: self.client.clone(),
            randomness_nonce_tx: self.randomness_nonce_tx.clone(),
            check_inherents_after: self.check_inherents_after.clone(),
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
    pub fn new(
        inner: I,
        client: Arc<C>,
        randomness_nonce_tx: Sender<Nonce<B>>,
        check_inherents_after: <<B as BlockT>::Header as HeaderT>::Number,
    ) -> Self {
        Self {
            inner,
            client,
            randomness_nonce_tx,
            check_inherents_after,
        }
    }

    fn check_inherents(&self, block: B, _inherent_data: Option<InherentData>) -> Result<(), Error> {
        if *block.header().number() < self.check_inherents_after {
            return Ok(());
        }

        // check if randomness is already block if not and if party is block authority then
        // wait for collecting random shares and combined randomness

        Ok(())
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
        mut block: BlockImportParams<B, Self::Transaction>,
        new_cache: HashMap<CacheKeyId, Vec<u8>>,
    ) -> Result<ImportResult, Self::Error> {
        let _parent_hash = *block.header.parent_hash();

        if let Some(inner_body) = block.body.take() {
            let check_block = B::new(block.header.clone(), inner_body);

            self.check_inherents(check_block.clone(), None)?;

            block.body = Some(check_block.deconstruct().1);
        }

        // add proper round number
        if let Err(err) = self
            .randomness_nonce_tx
            .try_send(Nonce(0, block.post_hash()))
        {
            info!("error when try_send topic through notifier {}", err);
            return Err(Error::TransmitErr.into());
        }

        self.inner
            .import_block(block, new_cache)
            .map_err(Into::into)
    }
}
