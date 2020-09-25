use codec::Encode;
use futures::channel::mpsc::{Sender};
use parking_lot::Mutex;
use log::info;
use sc_client_api::{backend::AuxStore, BlockOf};
use sp_api::ProvideRuntimeApi;
use sp_block_builder::BlockBuilder as BlockBuilderApi;
use sp_blockchain::{well_known_cache_keys::Id as CacheKeyId, HeaderBackend, ProvideCache};
use sp_consensus::{
    BlockCheckParams, BlockImport, BlockImportParams, Error as ConsensusError, ImportResult,
};
use sp_runtime::{traits::{Block as BlockT, Header as HeaderT}, generic::BlockId};
use std::{collections::HashMap, sync::Arc};
use sp_inherents::{InherentDataProviders, InherentData};

#[derive(derive_more::Display, Debug)]
pub enum Error {
    TransmitErr,
}

impl std::convert::From<Error> for ConsensusError {
    fn from(error: Error) -> ConsensusError {
        ConsensusError::ClientImport(error.to_string())
    }
}

use super::{Nonce, RandomBytes};
use super::inherents::{register_rb_inherent_data_provider, InherentType};


pub struct RandomnessBeaconBlockImport<B: BlockT, I, C> {
    inner: I,
    client: Arc<C>,
    random_bytes: Arc<Mutex<InherentType>>,
    random_bytes_buf: HashMap<Nonce, Option<RandomBytes>>,
    randomness_nonce_tx: Sender<Nonce>,
    check_inherents_after: <<B as BlockT>::Header as HeaderT>::Number,
}

impl<B: BlockT, I: Clone, C> Clone for RandomnessBeaconBlockImport<B, I, C> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            client: self.client.clone(),
            random_bytes: self.random_bytes.clone(),
            random_bytes_buf: self.random_bytes_buf.clone(),
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
        randomness_nonce_tx: Sender<Nonce>,
        check_inherents_after: <<B as BlockT>::Header as HeaderT>::Number,
        random_bytes: Arc<Mutex<InherentType>>,
	inherent_data_providers: InherentDataProviders,
    ) -> Self {

	register_rb_inherent_data_provider(&inherent_data_providers, random_bytes.clone());

        Self {
            inner,
            client,
            random_bytes,
            random_bytes_buf: HashMap::new(),
            randomness_nonce_tx,
            check_inherents_after,
        }
    }

    
    fn check_inherents(&self, block: B, _inherent_data: Option<InherentData>) -> Result<(), Error> {
        if *block.header().number() < self.check_inherents_after {
            return Ok(());
        }

        // TODO: check if randomness is already block if not and if party is block authority then
        // wait for collecting random shares and combined randomness

        Ok(())
    }

    fn clear_old_random_bytes(&mut self, block: B, _inherent_data: Option<InherentData>) -> Result<(), Error> {
        if *block.header().number() < self.check_inherents_after {
            return Ok(());
        }


        // TODO check if randomness for some nonce from self.random_bytes_buf is in inherent data of the block.
        // If so, remove the corresponding entry from self.random_bytes_buf and self.random_bytes.

        Ok(())
    }

    // TODO: Nonce should be a hash so that Randomness-Beacon Pallet may choose the right one, but we
    // cannot make InherentType generic over BlockT. Figureout how to do it optimally. Current
    // approximation uses Vec<u8>.
    // Returns None is hash was already processed.
    fn hash_to_nonce(&mut self, hash: <B as BlockT>::Hash) -> Option<Nonce> {
        // Check if hash was already processed
        // TODO: is this check enough?
        match self.client.status(BlockId::Hash(hash)) {
                Ok(sp_blockchain::BlockStatus::InChain) => return None,
                _ => {},
        }
        let nonce = <B as BlockT>::Hash::encode(&hash);
        match self.random_bytes_buf.get(&nonce) {
            Some(_) => return None,
            None => {
                return Some(nonce)
            }
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
        mut block: BlockImportParams<B, Self::Transaction>,
        new_cache: HashMap<CacheKeyId, Vec<u8>>,
    ) -> Result<ImportResult, Self::Error> {

        if let Some(inner_body) = block.body.take() {
            let check_block = B::new(block.header.clone(), inner_body);

            self.check_inherents(check_block.clone(), None)?;

            self.clear_old_random_bytes(check_block.clone(), None)?;

            block.body = Some(check_block.deconstruct().1);
        }

        if let Some(nonce) = self.hash_to_nonce(block.post_hash()) {
            if let Err(err) = self
                .randomness_nonce_tx
                .try_send(nonce.clone())
            {
                info!(target: "import", "error when try_send topic through notifier {}", err);
                return Err(Error::TransmitErr.into());
            }
            self.random_bytes_buf.insert(nonce, None);
        }


        self.inner
            .import_block(block, new_cache)
            .map_err(Into::into)
    }
}
