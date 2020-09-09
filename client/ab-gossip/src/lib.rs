use codec::{Encode, Decode};
use log::info;

use sc_network::{NetworkService, PeerId};
use sc_network_gossip::{GossipEngine, Validator, ValidationResult, ValidatorContext};

use sp_runtime::traits::{Block as BlockT, Hash as HashT, Header as HeaderT};
use sp_core::traits::BareCryptoStorePtr;

use parking_lot::{Mutex, RwLock};
use std::{pin::Pin, sync::Arc, task::{Context, Poll}};
use futures::prelude::*;

const AB_GOSSIP_ID: [u8; 4] = *b"abgo";
const AB_PROTOCOL_NAME: &[u8] = b"/abgossip";

pub const KEY_TYPE: sp_core::crypto::KeyTypeId = sp_application_crypto::key_types::DUMMY;
mod app {
    use sp_application_crypto::{app_crypto, key_types::DUMMY, ed25519};
    app_crypto!(ed25519, DUMMY);
}

pub type AuthorityId = app::Public;
pub type AuthoritySignature = app::Signature;

pub struct LocalIdKeystore((AuthorityId, BareCryptoStorePtr));

impl LocalIdKeystore {
    fn local_id(&self) -> &AuthorityId {
        &(self.0).0
    }

    fn keystore(&self) -> &BareCryptoStorePtr {
        &(self.0).1
    }
}

impl AsRef<BareCryptoStorePtr> for LocalIdKeystore {
    fn as_ref(&self) -> &BareCryptoStorePtr {
        self.keystore()
    }
}

impl From<(AuthorityId, BareCryptoStorePtr)> for LocalIdKeystore {
	fn from(inner: (AuthorityId, BareCryptoStorePtr)) -> LocalIdKeystore {
		LocalIdKeystore(inner)
	}
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct Message{
    pub data: String
}

impl Message {
    pub fn sign(&self, public: AuthorityId, keystore: &BareCryptoStorePtr) -> Option<SignedMessage> {
        use sp_core::crypto::Public;        // to_public_crypto_pair
        use sp_application_crypto::AppKey;  // ID
        use sp_std::convert::TryInto;       // try_into

        let encoded = self.encode();
        let signature = keystore.read()
            .sign_with(AuthorityId::ID, &public.to_public_crypto_pair(), &encoded[..])
            .ok()?.try_into().ok()?;

        Some(SignedMessage{message: self.clone(), signature, id: public})
    } 
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct SignedMessage{
    pub message: Message,
    pub signature: AuthoritySignature,
    pub id: AuthorityId,
}

#[derive(Debug, Encode, Decode)]
pub struct GossipMessage {
    pub round: u8,
    pub message: SignedMessage,
}

fn round_topic<B: BlockT>(round: u8) -> B::Hash {
    <<B::Header as HeaderT>::Hashing as HashT>::hash(round.to_string().as_bytes())
}

pub struct GossipValidator {
    round: RwLock<u8>
}

impl GossipValidator {
    pub fn new() -> Self {
        GossipValidator {round: RwLock::new(0)}
    }
    
    pub fn note_round(&self, round: u8){
        *self.round.write() = round;
    }
}

#[derive(Debug, Clone)]
pub enum Error {
    Network(String),
    Signing(String),
}

impl<B: BlockT> Validator<B> for GossipValidator{
    fn validate(&self, _context: &mut dyn ValidatorContext<B>, _sender: &PeerId, data: &[u8]) -> ValidationResult<B::Hash> {
        match GossipMessage::decode(&mut data.clone()) {
            Ok(gm) => {
                let topic = round_topic::<B>(gm.round);
                ValidationResult::ProcessAndKeep(topic)
            }
            Err(e) => {
                info!(target: "ab-gossip", "Error decoding message: {}", e.what());
                ValidationResult::Discard
            }
        }
    }
}

pub struct OutgoingMessage<B: BlockT> {
    msg: SignedMessage,
    round: u8,
    gossip_engine: Arc<Mutex<GossipEngine<B>>>,
}

impl<B: BlockT> Unpin for OutgoingMessage<B> {}

impl<B: BlockT> Future for OutgoingMessage<B> {
    type Output = ();
    
    fn poll(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<Self::Output> {
        info!(target: "ab-gossip", "sending message");
        let message = GossipMessage{round: self.round, message: self.msg.clone()};
        let topic = round_topic::<B>(self.round);
        self.gossip_engine.lock().gossip_message(topic, message.encode(), true);
        info!(target: "ab-gossip", "sent message");
    
    	Poll::Ready(())
    }
}

pub struct NetworkBridge<B: BlockT> {
    gossip_engine: Arc<Mutex<GossipEngine<B>>>,
    validator: Arc<GossipValidator>,
}

impl<B: BlockT> Unpin for NetworkBridge<B> {}

impl<B: BlockT> NetworkBridge<B> {
    pub fn new(network: Arc<NetworkService<B, <B as BlockT>::Hash>>) -> Self {
        let validator = Arc::new(GossipValidator::new());
        let gossip_engine = Arc::new(Mutex::new(GossipEngine::new(network.clone(), AB_GOSSIP_ID, AB_PROTOCOL_NAME, validator.clone())));

        NetworkBridge{gossip_engine, validator}
    }

    pub fn note_round(&self, round: u8) {
        self.validator.note_round(round);
    }

    pub fn round_communication(&self, round: u8, keystore: LocalIdKeystore) -> (impl Stream<Item=SignedMessage> + Unpin, OutgoingMessage<B>) {
        self.note_round(round);

        let topic = round_topic::<B>(round);
        let incoming = self.gossip_engine.lock().messages_for(topic).
            filter_map(move |notification| {
                let decoded = GossipMessage::decode(&mut &notification.message[..]);
                match decoded {
                    Ok(gm) => {
                        info!(target: "ab-gossip", "received messege {:?}", gm.message.message);
                        future::ready(Some(gm.message))
                    }
                    Err(ref e) => {
                        info!(target: "ab-gossip", "Skipping malformed message {:?}: {}", notification, e);
                        future::ready(None)
                    }
                }
            });

        let msg = Message{data: round.to_string()}.sign(keystore.local_id().clone(), keystore.as_ref()).unwrap();

        let outgoing = OutgoingMessage::<B> {
            msg,
            round,
            gossip_engine: self.gossip_engine.clone(),
        };


        (incoming, outgoing)
    }
}

impl<B: BlockT> Future for NetworkBridge<B> {
	type Output = ();

	fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
		match self.gossip_engine.lock().poll_unpin(cx) {
			Poll::Ready(()) => return Poll::Ready(
				info!("Gossip engine future finished.")
			),
			Poll::Pending => {},
		}

		Poll::Pending
	}
}
