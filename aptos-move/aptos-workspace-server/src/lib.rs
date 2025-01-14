// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

//! This library runs and manages a set of services that makes up a local Aptos network.
//! - node
//!     - node API
//!     - indexer grpc
//! - faucet
//! - indexer
//!     - postgres db
//!     - processors
//!     - indexer API
//!
//! The services are bound to unique OS-assigned ports to allow for multiple local networks
//! to operate simultaneously, enabling testing and development in isolated environments.
//!
//! ## Key Features:
//! - Shared Futures
//!     - The code makes extensive use of shared futures across multiple services,
//!       ensuring orderly startup while maximizing parallel execution.
//! - Graceful Shutdown
//!     - When a `Ctrl-C` signal is received or if any of the services fail to start
//!       or exit unexpectedly, the system attempts to gracefully shut down all services,
//!       cleaning up resources like Docker containers, volumes and networks.

mod common;
mod services;

use anyhow::{anyhow, Context, Result};
use aptos_localnet::docker::get_docker;
use clap::Parser;
use common::make_shared;
use futures::TryFutureExt;
use services::{
    docker_common::create_docker_network_permanent, indexer_api::start_indexer_api,
    processors::start_all_processors,
};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

async fn run_all_services(timeout: u64) -> Result<()> {
    let test_dir = tempfile::tempdir()?;
    let test_dir = test_dir.path();
    println!("Created test directory: {}", test_dir.display());

    let instance_id = Uuid::new_v4();

    // Phase 0: Register the signal handler for ctrl-c.
    let shutdown = CancellationToken::new();
    {
        // TODO: Find a way to register the signal handler in a blocking manner without
        //       waiting for it to trigger.
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            tokio::select! {
                res = tokio::signal::ctrl_c() => {
                    res.unwrap();
                    println!("\nCtrl-C received. Shutting down services. This may take a while.\n");
                }
                _ = tokio::time::sleep(Duration::from_secs(timeout)) => {
                    println!("\nTimeout reached. Shutting down services. This may take a while.\n");
                }
            }

            shutdown.cancel();
        });
    }

    // Phase 1: Start all services.
    // Node
    let (fut_node_api, fut_indexer_grpc, fut_node_finish) = services::node::start_node(test_dir)?;

    let fut_node_api = make_shared(fut_node_api);
    let fut_indexer_grpc = make_shared(fut_indexer_grpc);

    // Faucet
    let (fut_faucet, fut_faucet_finish) = services::faucet::start_faucet(
        test_dir.to_owned(),
        fut_node_api.clone(),
        fut_indexer_grpc.clone(),
    );

    // Docker
    let fut_docker = make_shared(get_docker());

    // Docker Network
    let docker_network_name = "aptos-workspace".to_string();
    let fut_docker_network = make_shared(create_docker_network_permanent(
        shutdown.clone(),
        fut_docker.clone(),
        docker_network_name,
    ));

    // Indexer part 1: postgres db
    let (fut_postgres, fut_postgres_finish, fut_postgres_clean_up) =
        services::postgres::start_postgres(
            shutdown.clone(),
            fut_docker.clone(),
            fut_docker_network.clone(),
            instance_id,
        );
    let fut_postgres = make_shared(fut_postgres);

    // Indexer part 2: processors
    let (fut_all_processors_ready, fut_any_processor_finish) = start_all_processors(
        fut_node_api.clone(),
        fut_indexer_grpc.clone(),
        fut_postgres.clone(),
    );
    let fut_all_processors_ready = make_shared(fut_all_processors_ready);

    // Indexer part 3: indexer API
    let (fut_indexer_api, fut_indexer_api_finish, fut_indexer_api_clean_up) = start_indexer_api(
        instance_id,
        shutdown.clone(),
        fut_docker.clone(),
        fut_docker_network.clone(),
        fut_postgres.clone(),
        fut_all_processors_ready.clone(),
    );

    // Phase 2: Wait for all services to be up.
    let all_services_up = async move {
        tokio::try_join!(
            fut_node_api.map_err(|err| anyhow!(err)),
            fut_indexer_grpc.map_err(|err| anyhow!(err)),
            fut_faucet,
            fut_postgres.map_err(|err| anyhow!(err)),
            fut_all_processors_ready.map_err(|err| anyhow!(err)),
            fut_indexer_api,
        )
    };
    let clean_up_all = async move {
        eprintln!("Running shutdown steps");
        fut_indexer_api_clean_up.await;
        fut_postgres_clean_up.await;
    };
    tokio::select! {
        _ = shutdown.cancelled() => {
            clean_up_all.await;

            return Ok(())
        }
        res = all_services_up => {
            match res.context("one or more services failed to start") {
                Ok(_) => println!("ALL SERVICES UP"),
                Err(err) => {
                    eprintln!("\nOne or more services failed to start, will run shutdown steps\n");
                    clean_up_all.await;

                    return Err(err)
                }
            }
        }
    }

    // Phase 3: Wait for services to stop, which should only happen in case of an error, or
    //          the shutdown signal to be received.
    tokio::select! {
        _ = shutdown.cancelled() => (),
        res = fut_node_finish => {
            eprintln!("Node exited unexpectedly");
            if let Err(err) = res {
                eprintln!("Error: {}", err);
            }
        }
        res = fut_faucet_finish => {
            eprintln!("Faucet exited unexpectedly");
            if let Err(err) = res {
                eprintln!("Error: {}", err);
            }
        }
        res = fut_postgres_finish => {
            eprintln!("Postgres exited unexpectedly");
            if let Err(err) = res {
                eprintln!("Error: {}", err);
            }
        }
        res = fut_any_processor_finish => {
            eprintln!("One of the processors exited unexpectedly");
            if let Err(err) = res {
                eprintln!("Error: {}", err);
            }
        }
        res = fut_indexer_api_finish => {
            eprintln!("Indexer API exited unexpectedly");
            if let Err(err) = res {
                eprintln!("Error: {}", err);
            }
        }
    }

    clean_up_all.await;

    println!("Finished running all services");

    Ok(())
}

#[derive(Parser)]
pub enum WorkspaceCommand {
    Run {
        #[arg(long, default_value_t = 1800)]
        timeout: u64,
    },
}

impl WorkspaceCommand {
    pub async fn run(self) -> Result<()> {
        match self {
            WorkspaceCommand::Run { timeout } => run_all_services(timeout).await,
        }
    }
}