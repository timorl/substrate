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
use sp_runtime::traits::{Block as BlockT, Header as HeaderT};
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
use super::inherents::{register_rb_inherent_data_provider, InherentType, INHERENT_IDENTIFIER};


#[derive(Clone)]
pub struct RandomnessBeaconBlockImport<B: BlockT, I, C> {
    inner: I,
    client: Arc<C>,
    random_bytes: Arc<Mutex<InherentType>>,
    random_bytes_buf: Arc<Mutex<HashMap<Nonce, Option<RandomBytes>>>>,
    randomness_nonce_tx: Sender<Nonce>,
    check_inherents_after: <<B as BlockT>::Header as HeaderT>::Number,
    hash2Nonce: HashMap<<B as BlockT>::Hash, Nonce>,
    nextNonce: Nonce,
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
        random_bytes_buf: Arc<Mutex<HashMap<Nonce, Option<RandomBytes>>>>,
        check_inherents_after: <<B as BlockT>::Header as HeaderT>::Number,
        random_bytes: Arc<Mutex<InherentType>>,
	inherent_data_providers: InherentDataProviders,
    ) -> Self {

	register_rb_inherent_data_provider(&inherent_data_providers, random_bytes);

        Self {
            inner,
            client,
            random_bytes,
            random_bytes_buf,
            randomness_nonce_tx,
            check_inherents_after,
            hash2Nonce: HashMap::new(),
            nextNonce: 0,
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

    fn clear_old_random_bytes(&mut self, inherent_data: Option<InherentData>) {
        if inherent_data.is_none() {
            return
        }

        // check if randomness for some hash from self.random_bytes_buf is in inherent_data.
        // If so, remove the corresponding entry from self.random_bytes_buf.
        if let Ok(Some((nonce, _))) = inherent_data.unwrap().get_data::<(Nonce, RandomBytes)>(&INHERENT_IDENTIFIER) {
            if let Some((h, _)) = self.hash2Nonce.iter().find(|(_, &n)| n==nonce) {
                self.hash2Nonce.remove(h);
                self.random_bytes.lock().retain(|(n, _)| *n!=nonce);
                self.random_bytes_buf.lock().remove(&nonce);
            }
        }

    }

    // TODO: Nonce should be a hash so that Randomness-Beacon Pallet may choose the right one, but we
    // cannot make InherentType generic over BlockT. Figureout how to do it.
    fn hashToNonce(&mut self, h: <B as BlockT>::Hash) -> Option<Nonce> {
        // TODO: check if this hash is not a parent of some hash that already is in hash2Nonce
        match self.hash2Nonce.get(&h) {
            Some(_) => return None,
            None => {
                self.hash2Nonce.insert(h, self.nextNonce);
                self.nextNonce += 1;
                return Some(self.nextNonce)
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
        let parent_hash = *block.header.parent_hash();

        if let Some(inner_body) = block.body.take() {
            let check_block = B::new(block.header.clone(), inner_body);

            self.check_inherents(check_block.clone(), None)?;

            self.clear_old_random_bytes(check_block.clone());

            block.body = Some(check_block.deconstruct().1);
        }

        if let Some(nonce) = self.hashToNonce(block.post_hash()) {
            if let Err(err) = self
                .randomness_nonce_tx
                .try_send(nonce)
            {
                info!("error when try_send topic through notifier {}", err);
                return Err(Error::TransmitErr.into());
            }
            self.random_bytes_buf.lock().insert(nonce, None);
        }


        self.inner
            .import_block(block, new_cache)
            .map_err(Into::into)
    }
}
