//! Service and ServiceFactory implementation. Specialized wrapper over substrate service.

use futures::channel::mpsc::{channel, Receiver};
use log::info;
use parking_lot::Mutex;
use rb_node_runtime::{self, opaque::Block, RuntimeApi};
use sc_client_api::{ExecutorProvider, RemoteBackend};
use sc_executor::native_executor_instance;
pub use sc_executor::NativeExecutor;
use sc_finality_grandpa::{
	FinalityProofProvider as GrandpaFinalityProofProvider, GrandpaBlockImport,
};
use sc_service::{error::Error as ServiceError, Configuration, TaskManager};
use sp_consensus_aura::sr25519::AuthorityPair as AuraPair;
use sp_core::crypto::key_types::DUMMY;
use sp_inherents::InherentDataProviders;
use std::sync::Arc;

use sc_randomness_beacon::{import::RandomnessBeaconBlockImport, NetworkBridge};
use sp_randomness_beacon::Nonce;

// Our native executor instance.
native_executor_instance!(
	pub Executor,
	rb_node_runtime::api::dispatch,
	rb_node_runtime::native_version,
);

type FullClient = sc_service::TFullClient<Block, RuntimeApi, Executor>;
type FullBackend = sc_service::TFullBackend<Block>;
type FullSelectChain = sc_consensus::LongestChain<FullBackend, Block>;

pub fn new_partial(
	config: &Configuration,
) -> Result<
	sc_service::PartialComponents<
		FullClient,
		FullBackend,
		FullSelectChain,
		sp_consensus::DefaultImportQueue<Block, FullClient>,
		sc_transaction_pool::FullPool<Block, FullClient>,
		(
			Receiver<Nonce>,
			RandomnessBeaconBlockImport<
				Block,
				GrandpaBlockImport<FullBackend, Block, FullClient, FullSelectChain>,
				FullClient,
			>,
			sc_finality_grandpa::LinkHalf<Block, FullClient, FullSelectChain>,
		),
	>,
	ServiceError,
> {
	let inherent_data_providers = sp_inherents::InherentDataProviders::new();

	let (client, backend, keystore, task_manager) =
		sc_service::new_full_parts::<Block, RuntimeApi, Executor>(&config)?;
	let client = Arc::new(client);

	let select_chain = sc_consensus::LongestChain::new(backend.clone());

	let transaction_pool = sc_transaction_pool::BasicPool::new_full(
		config.transaction_pool.clone(),
		config.prometheus_registry(),
		task_manager.spawn_handle(),
		client.clone(),
	);

	let (grandpa_block_import, grandpa_link) = sc_finality_grandpa::block_import(
		client.clone(),
		&(client.clone() as Arc<_>),
		select_chain.clone(),
	)?;

	let (tx, rx) = channel(10);
	let rb_gossip_block_import = RandomnessBeaconBlockImport::new(
		grandpa_block_import.clone(),
		client.clone(),
		tx,
		1,
		inherent_data_providers.clone(),
	);
	let aura_block_import = sc_consensus_aura::AuraBlockImport::<_, _, _, AuraPair>::new(
		rb_gossip_block_import.clone(),
		client.clone(),
	);

	let import_queue = sc_consensus_aura::import_queue::<_, _, _, AuraPair, _, _>(
		sc_consensus_aura::slot_duration(&*client)?,
		aura_block_import,
		Some(Box::new(grandpa_block_import.clone())),
		None,
		client.clone(),
		inherent_data_providers.clone(),
		&task_manager.spawn_handle(),
		config.prometheus_registry(),
		sp_consensus::CanAuthorWithNativeVersion::new(client.executor().clone()),
	)?;

	Ok(sc_service::PartialComponents {
		client,
		backend,
		task_manager,
		import_queue,
		keystore,
		select_chain,
		transaction_pool,
		inherent_data_providers,
		other: (rx, rb_gossip_block_import, grandpa_link),
	})
}

/// Builds a new service for a full client.
pub fn new_full(config: Configuration) -> Result<TaskManager, ServiceError> {
	let sc_service::PartialComponents {
		client,
		backend,
		mut task_manager,
		select_chain,
		import_queue,
		keystore,
		transaction_pool,
		inherent_data_providers,
		other: (randomness_nonce_rx, block_import, grandpa_link),
		..
	} = new_partial(&config)?;

	let keys = (keystore.clone() as sp_core::traits::BareCryptoStorePtr)
		.read()
		.ed25519_public_keys(DUMMY);
	let public = if keys.len() > 0 {
		keys[0]
	} else {
		(keystore.clone() as sp_core::traits::BareCryptoStorePtr)
			.write()
			.ed25519_generate_new(DUMMY, None)
			.unwrap()
	};

	let name = config.network.node_name.clone();
	info!("{} key is {}", name, public);

	let (network, network_status_sinks, system_rpc_tx, network_starter) =
		sc_service::build_network(sc_service::BuildNetworkParams {
			config: &config,
			client: client.clone(),
			transaction_pool: transaction_pool.clone(),
			spawn_handle: task_manager.spawn_handle(),
			import_queue,
			on_demand: None,
			block_announce_validator_builder: None,
			finality_proof_request_builder: None,
			finality_proof_provider: None,
		})?;
	let role = config.role.clone();
	let force_authoring = config.force_authoring;
	let name = config.network.node_name.clone();
	let prometheus_registry = config.prometheus_registry().cloned();
	let telemetry_connection_sinks = sc_service::TelemetryConnectionSinks::default();
	let enable_grandpa = !config.disable_grandpa;

	let rpc_extensions_builder = {
		let client = client.clone();
		let pool = transaction_pool.clone();

		Box::new(move |deny_unsafe, _| {
			let deps = crate::rpc::FullDeps {
				client: client.clone(),
				pool: pool.clone(),
				deny_unsafe,
			};

			crate::rpc::create_full(deps)
		})
	};

	sc_service::spawn_tasks(sc_service::SpawnTasksParams {
		network: network.clone(),
		client: client.clone(),
		keystore: keystore.clone(),
		task_manager: &mut task_manager,
		transaction_pool: transaction_pool.clone(),
		telemetry_connection_sinks: telemetry_connection_sinks.clone(),
		rpc_extensions_builder: rpc_extensions_builder,
		on_demand: None,
		remote_blockchain: None,
		backend,
		network_status_sinks,
		system_rpc_tx,
		config,
	})?;

	let mut randomness_tx = None;
	if role.is_authority() {
		let (tx, randomness_rx) = std::sync::mpsc::channel();
		randomness_tx = Some(tx);
		// the following var could be a plain randomness_notifier_rx if it implemented send Trait
		// as it does not, then we pack it in Arc<Mutex<_>>
		let randomness_rx = Arc::new(Mutex::new(randomness_rx));

		let proposer = sc_randomness_beacon::authorship::ProposerFactory::new(
			client.clone(),
			transaction_pool,
			prometheus_registry.as_ref(),
			randomness_rx,
		);

		let can_author_with =
			sp_consensus::CanAuthorWithNativeVersion::new(client.executor().clone());

		let aura = sc_consensus_aura::start_aura::<_, _, _, _, _, AuraPair, _, _, _>(
			sc_consensus_aura::slot_duration(&*client)?,
			client.clone(),
			select_chain,
			block_import,
			proposer,
			network.clone(),
			inherent_data_providers.clone(),
			force_authoring,
			keystore.clone(),
			can_author_with,
		)?;

		// the AURA authoring task is considered essential, i.e. if it
		// fails we take down the service with it.
		task_manager
			.spawn_essential_handle()
			.spawn_blocking("aura", aura);
	}

	// TODO: should be read from config
	let n_members = 2;
	let threshold = 2;
	let nb = NetworkBridge::new(
		name.clone(),
		n_members,
		threshold,
		randomness_nonce_rx,
		network.clone(),
		randomness_tx,
	);

	task_manager.spawn_handle().spawn("network bridge", nb);

	network_starter.start_network();

	let keystore = if role.is_authority() {
		Some(keystore as sp_core::traits::BareCryptoStorePtr)
	} else {
		None
	};

	use std::time::Duration;
	let grandpa_config = sc_finality_grandpa::Config {
		// FIXME #1578 make this available through chainspec
		gossip_duration: Duration::from_millis(333),
		justification_period: 512,
		name: Some(name),
		observer_enabled: false,
		keystore,
		is_authority: role.is_network_authority(),
	};

	if enable_grandpa {
		// start the full GRANDPA voter
		// NOTE: non-authorities could run the GRANDPA observer protocol, but at
		// this point the full voter should provide better guarantees of block
		// and vote data availability than the observer. The observer has not
		// been tested extensively yet and having most nodes in a network run it
		// could lead to finality stalls.
		use sc_finality_grandpa::SharedVoterState;
		let grandpa_config = sc_finality_grandpa::GrandpaParams {
			config: grandpa_config,
			link: grandpa_link,
			network,
			inherent_data_providers,
			telemetry_on_connect: Some(telemetry_connection_sinks.on_connect_stream()),
			voting_rule: sc_finality_grandpa::VotingRulesBuilder::default().build(),
			prometheus_registry,
			shared_voter_state: SharedVoterState::empty(),
		};

		// the GRANDPA voter task is considered infallible, i.e.
		// if it fails we take down the service with it.
		task_manager.spawn_essential_handle().spawn_blocking(
			"grandpa-voter",
			sc_finality_grandpa::run_grandpa_voter(grandpa_config)?,
		);
	} else {
		sc_finality_grandpa::setup_disabled_grandpa(client, &inherent_data_providers, network)?;
	}
	Ok(task_manager)
}

/// Builds a new service for a light client.
pub fn new_light(config: Configuration) -> Result<TaskManager, ServiceError> {
	let (client, backend, keystore, mut task_manager, on_demand) =
		sc_service::new_light_parts::<Block, RuntimeApi, Executor>(&config)?;

	let transaction_pool = Arc::new(sc_transaction_pool::BasicPool::new_light(
		config.transaction_pool.clone(),
		config.prometheus_registry(),
		task_manager.spawn_handle(),
		client.clone(),
		on_demand.clone(),
	));

	let grandpa_block_import = sc_finality_grandpa::light_block_import(
		client.clone(),
		backend.clone(),
		&(client.clone() as Arc<_>),
		Arc::new(on_demand.checker().clone()) as Arc<_>,
	)?;
	let finality_proof_import = grandpa_block_import.clone();
	let finality_proof_request_builder =
		finality_proof_import.create_finality_proof_request_builder();

	let import_queue = sc_consensus_aura::import_queue::<_, _, _, AuraPair, _, _>(
		sc_consensus_aura::slot_duration(&*client)?,
		grandpa_block_import,
		None,
		Some(Box::new(finality_proof_import)),
		client.clone(),
		InherentDataProviders::new(),
		&task_manager.spawn_handle(),
		config.prometheus_registry(),
		sp_consensus::NeverCanAuthor,
	)?;

	let finality_proof_provider =
		GrandpaFinalityProofProvider::new_for_service(backend.clone(), client.clone());

	let (network, network_status_sinks, system_rpc_tx, network_starter) =
		sc_service::build_network(sc_service::BuildNetworkParams {
			config: &config,
			client: client.clone(),
			transaction_pool: transaction_pool.clone(),
			spawn_handle: task_manager.spawn_handle(),
			import_queue,
			on_demand: Some(on_demand.clone()),
			block_announce_validator_builder: None,
			finality_proof_request_builder: Some(finality_proof_request_builder),
			finality_proof_provider: Some(finality_proof_provider),
		})?;

	if config.offchain_worker.enabled {
		sc_service::build_offchain_workers(
			&config,
			backend.clone(),
			task_manager.spawn_handle(),
			client.clone(),
			network.clone(),
		);
	}

	sc_service::spawn_tasks(sc_service::SpawnTasksParams {
		remote_blockchain: Some(backend.remote_blockchain()),
		transaction_pool,
		task_manager: &mut task_manager,
		on_demand: Some(on_demand),
		rpc_extensions_builder: Box::new(|_, _| ()),
		telemetry_connection_sinks: sc_service::TelemetryConnectionSinks::default(),
		config,
		client,
		keystore,
		backend,
		network,
		network_status_sinks,
		system_rpc_tx,
	})?;

	network_starter.start_network();

	Ok(task_manager)
}
