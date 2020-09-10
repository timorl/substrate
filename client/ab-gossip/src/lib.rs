use codec::{Encode, Decode};
use log::info;

use sc_network::{NetworkService, PeerId};
use sc_network_gossip::{GossipEngine, Validator, ValidationResult, ValidatorContext, TopicNotification};

use sp_runtime::traits::{Block as BlockT, Hash as HashT, Header as HeaderT};
use sp_core::traits::BareCryptoStorePtr;

use parking_lot::{Mutex, RwLock};
use std::{pin::Pin, sync::Arc, task::{Context, Poll}, time};
use futures::{prelude::*, channel::mpsc::Receiver};

const AB_GOSSIP_ID: [u8; 4] = *b"abgo";
const AB_PROTOCOL_NAME: &[u8] = b"/abgossip";
pub const SEND_INTERVAL: time::Duration = time::Duration::from_secs(1);

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

pub mod import;

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


#[derive(Debug, Clone, Copy)]
pub struct Nonce<B: BlockT>(u8, <B as BlockT>::Hash);

#[derive(Clone)]
pub struct OutgoingMessage<B: BlockT> {
    round: u8,
    msg: SignedMessage,
    gossip_engine: Arc<Mutex<GossipEngine<B>>>,
}

impl<B: BlockT>  OutgoingMessage<B> {
    fn send(&self) {
        let message = GossipMessage{round: self.round, message: self.msg.clone()};
        let topic = round_topic::<B>(self.round);
        self.gossip_engine.lock().gossip_message(topic, message.encode(), true);
        info!(target: "ab-gossip", "sent message");
    }
}

pub struct NetworkBridge<B: BlockT> {
    id: String,
    topic: Option<B::Hash>,
    nonce: Option<Nonce<B>>,
    keystore: LocalIdKeystore,
    gossip_engine: Arc<Mutex<GossipEngine<B>>>,
    validator: Arc<GossipValidator>,
    incoming: Option<Receiver<TopicNotification>>,
    outgoing: Option<OutgoingMessage<B>>,
    randomness_nonce_rx: Receiver<Nonce<B>>,
    periodic_sender: futures_timer::Delay,
}

impl<B: BlockT> Unpin for NetworkBridge<B> {}

impl<B: BlockT> NetworkBridge<B> {
    pub fn new(id: String, randomness_nonce_rx: Receiver<Nonce<B>>, network: Arc<NetworkService<B, <B as BlockT>::Hash>>, keystore: LocalIdKeystore) -> Self {
        let validator = Arc::new(GossipValidator::new());
        let gossip_engine = Arc::new(Mutex::new(GossipEngine::new(network.clone(), AB_GOSSIP_ID, AB_PROTOCOL_NAME, validator.clone())));

        NetworkBridge{
            id,
            topic: None,
            nonce: None,
            keystore,
            gossip_engine,
            validator,
            incoming: None,
            outgoing: None,
            randomness_nonce_rx,
            periodic_sender: futures_timer::Delay::new(SEND_INTERVAL),
        }
    }

    pub fn note_round(&self, round: u8) {
        self.validator.note_round(round);
    }

    fn round_communication(&self, nonce: &Nonce<B>) -> (Receiver<TopicNotification>, OutgoingMessage<B>) {
        let round = nonce.0;
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
            }).into_inner();

        let msg = Message{data: round.to_string()};
        let msg = msg.sign(self.keystore.local_id().clone(), self.keystore.as_ref()).unwrap();

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

	fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
		match self.gossip_engine.lock().poll_unpin(cx) {
			Poll::Ready(()) => return Poll::Ready(
				info!("Gossip engine future finished.")
			),
			Poll::Pending => {},
		};

                let new_nonce = match self.randomness_nonce_rx.poll_next_unpin(cx) {
                    Poll::Pending => None,
                    Poll::Ready(None) => return Poll::Ready(()),
                    Poll::Ready(new_nonce) => new_nonce, // probably sth else in final version
                };

                if self.topic.is_none() && new_nonce.is_none() {
                    info!("network bridge didn't receive a first topic");
                    return Poll::Pending;
                }

                let new_nonce = new_nonce.unwrap();

                if self.nonce.as_ref().unwrap().0 != new_nonce.0 {
                    info!("received new nonce {}", new_nonce.0);
                    self.topic = Some(round_topic::<B>(new_nonce.0));
                    self.nonce = Some(new_nonce);
                }

                if let None = self.incoming {
                    let (incoming, outgoing) = self.round_communication(self.nonce.as_ref().unwrap());
                    self.incoming = Some(incoming);
                    self.outgoing = Some(outgoing);
                }

                while let Poll::Ready(()) = self.periodic_sender.poll_unpin(cx) {
                    self.periodic_sender.reset(SEND_INTERVAL);
                    info!("trynig to send msg");
                    self.outgoing.as_ref().unwrap().send();
                }

                if let Some(mut incoming) = self.incoming.take() {
                    let poll = incoming.poll_next_unpin(cx);
                    self.incoming = Some(incoming);
                    match poll {
                        Poll::Ready(Some(signed)) => info!("{} received message {:?}", self.id, signed.message),
                        Poll::Ready(None) => info!("poll_next_unpin returned Ready(None) ==> investigate!"),
                        Poll::Pending => return Poll::Pending,
                    }
                }

                Poll::Ready(())
	}
}
