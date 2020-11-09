use futures::Future;
use hyper::rt;
use jsonrpc_core_client::transports::http;
use sc_rpc::offchain::OffchainClient;
use sp_core::{offchain::StorageKind, Bytes};

fn main() {
	sp_tracing::try_init_simple();

	rt::run(rt::lazy(|| {
		let uri = "http://localhost:9934";

		http::connect(uri)
			.and_then(|client: OffchainClient| {
				client.get_local_storage(StorageKind::PERSISTENT, Bytes(b"dkw::enc_key".to_vec()))
			})
			.map_err(|e| {
				println!("Error: {:?}", e);
			})
			.map(|enc_key| match enc_key {
				Some(key) => println!("we got key {:?}", key),
				None => println!("didn't get key"),
			})
	}))
}
