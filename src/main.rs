use crate::merkle_tree::tree::{ProofStep, build_merkle_root, merkle_proof};
use crate::models::{Batch, NewBatch, NewRecord, Record};
use anyhow::{Result, anyhow, bail};
use axum::http::StatusCode;
use axum::{Json, Router, extract::State, http, routing::post};
use chia_wallet_sdk::client::{PeerOptions, connect_peer, create_rustls_connector, load_ssl_cert};
use chrono::Utc;
use diesel::prelude::*;
use diesel::r2d2::Pool;
use diesel::r2d2::{ConnectionManager, PooledConnection};
use dotenvy::dotenv;
use log::{error, info, warn};
use rustls::crypto::aws_lc_rs;
use serde::{Deserialize, Serialize};
use std::{env, net::SocketAddr};
use tower_http::cors::{Any, CorsLayer};

use bip39::Mnemonic;
use chia::protocol::{Bytes, RequestBlockHeader, RespondBlockHeader};
use chia::{
    bls::{DerivableKey, SecretKey, Signature, master_to_wallet_unhardened_intermediate, sign},
    protocol::{Bytes32, CoinStateFilters, NewPeakWallet, ProtocolMessageTypes, SpendBundle},
    puzzles::{DeriveSynthetic, standard::StandardArgs},
    traits::Streamable,
};
use chia_wallet_sdk::utils::Address;
use chia_wallet_sdk::{
    driver::{Action, Id, Relation, SpendContext, Spends},
    signer::{AggSigConstants, RequiredSignature},
    types::MAINNET_CONSTANTS,
    types::TESTNET11_CONSTANTS,
};
use indexmap::indexmap;
use std::str::FromStr;

pub mod merkle_tree;
pub mod models;
mod schema;

#[derive(Serialize, Deserialize)]
pub struct StampRequest {
    pub hash: String,
}

#[derive(Serialize, Deserialize)]
pub struct ProofRequest {
    pub hash: String,
}

#[derive(Serialize, Deserialize)]
pub struct ProofResponse {
    pub confirmed: bool,
    pub header_hash: Option<String>,
    pub coin_id: Option<String>,
    pub root_hash: String,
    pub leaf_hash: String,
    pub proof: Vec<ProofStep>,
}

pub type DbPool = Pool<ConnectionManager<MysqlConnection>>;
pub type DbConnection = PooledConnection<ConnectionManager<MysqlConnection>>;
#[derive(Clone)]
pub struct AppState {
    pub db_pool: DbPool,
    pub network: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("Start");
    dotenv().ok();
    println!("dotenv");
    env_logger::init();
    println!("logger");
    aws_lc_rs::default_provider()
        .install_default()
        .expect("installing AWS-LC provider failed");
    println!("aws-lc");
    let network = env::var("NETWORK")?;
    if !matches!(network.as_str(), "mainnet" | "testnet11") {
        bail!("Unsupported network: {network}")
    }
    info!("Configured network: {network}");
    println!("network");

    let pool = get_connection_pool()?;
    let background_pool = pool.clone();
    let state = AppState {
        db_pool: pool,
        network: network.clone(),
    };

    // Spawn wallet task with restart logic
    tokio::spawn(async move {
        loop {
            info!("Starting wallet task...");
            let wallet_result = wallet_task(background_pool.clone(), &network).await;

            match wallet_result {
                Ok(()) => {
                    // Peer disconnected - this is expected and should trigger a reconnect
                    warn!("Wallet task ended (peer disconnected). Restarting in 5 seconds...");
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                }
                Err(e) => {
                    error!("Wallet task failed: {e:?}");
                    info!("Restarting wallet task in 5 seconds...");

                    // Wait 5 seconds before restarting to avoid rapid restart loops
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                }
            }
        }
    });

    let port: u16 = env::var("PORT")
        .expect("PORT must be defined")
        .parse()
        .expect("PORT must be a valid u16");
    let cors = CorsLayer::new()
        .allow_methods([http::Method::POST])
        .allow_origin(Any)
        .allow_headers(Any);
    let app = Router::new()
        .route("/stamp", post(stamp))
        .route("/proof", post(proof))
        .with_state(state)
        .layer(cors);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Listening on {addr}");
    axum::serve(tokio::net::TcpListener::bind(addr).await.unwrap(), app).await?;
    Ok(())
}

pub fn get_connection_pool() -> Result<Pool<ConnectionManager<MysqlConnection>>> {
    let database_url =
        env::var("DATABASE_URL").map_err(|_e| anyhow!("DATABASE_URL must be set"))?;
    let manager = ConnectionManager::<MysqlConnection>::new(database_url);
    Pool::builder()
        .test_on_check_out(true)
        .build(manager)
        .map_err(|_e| anyhow!("Failed to create pool"))
}

async fn stamp(
    State(state): State<AppState>,
    Json(payload): Json<StampRequest>,
) -> Result<Json<ProofResponse>, (StatusCode, String)> {
    let hash_bytes =
        hex::decode(payload.hash.as_str()).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    if hash_bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid hash length. Expected 32 bytes.".to_string(),
        ));
    }
    let hash_array: [u8; 32] = hash_bytes.try_into().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Failed to convert hash".to_string(),
        )
    })?;

    // Check if record with same hash already exists
    let mut conn = state.db_pool.get().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("DB connection error: {e}"),
        )
    })?;

    let mut existing_record: Option<Record> = schema::records::table
        .filter(schema::records::hash.eq(hash_array.as_slice()))
        .first::<Record>(&mut conn)
        .optional()
        .map_err(|_e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error checking for existing records".to_string(),
            )
        })?;

    if existing_record.is_none() {
        let new_record = NewRecord {
            hash: hash_array.as_slice(),
        };
        conn.transaction(|conn| {
            diesel::insert_into(schema::records::table)
                .values(&new_record)
                .execute(conn)
        })
        .map_err(|_e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database insert failed".to_string(),
            )
        })?;

        // Get the newly inserted record
        existing_record = Some(
            schema::records::table
                .filter(schema::records::hash.eq(hash_array.as_slice()))
                .first::<Record>(&mut conn)
                .map_err(|_e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Error loading record after insert".to_string(),
                    )
                })?,
        );
    }

    // Now we need to get all pending records, in order, prior to the one we just inserted
    let current_record = existing_record.ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "Record not found after insert".to_string(),
    ))?;

    let records = records_up_to_record(conn, &current_record);
    let leaves = records_to_leaves(&records).map_err(|_e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to load leaves".to_string(),
        )
    })?;
    let root = build_merkle_root(&leaves);
    let index = leaves.iter().position(|&leaf| leaf == hash_array).ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "Hash not found in leaves".to_string(),
    ))?;
    let proof = merkle_proof(&leaves, index);

    Ok(Json(ProofResponse {
        confirmed: false,
        header_hash: None,
        coin_id: None,
        root_hash: hex::encode(root),
        leaf_hash: hex::encode(hash_array),
        proof,
    }))
}

async fn proof(
    State(state): State<AppState>,
    Json(payload): Json<ProofRequest>,
) -> Result<Json<ProofResponse>, (StatusCode, String)> {
    let hash_bytes =
        hex::decode(payload.hash.as_str()).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    if hash_bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid hash length. Expected 32 bytes.".to_string(),
        ));
    }
    let hash_array: [u8; 32] = hash_bytes.try_into().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Failed to convert hash".to_string(),
        )
    })?;

    // Check if record with same hash already exists
    let mut conn = state.db_pool.get().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("DB connection error: {e}"),
        )
    })?;

    let existing_record: Option<Record> = schema::records::table
        .filter(schema::records::hash.eq(hash_array.as_slice()))
        .first::<Record>(&mut conn)
        .optional()
        .map_err(|_e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error checking for existing records".to_string(),
            )
        })?;

    let Some(record) = existing_record else {
        return Err((StatusCode::NOT_FOUND, "Hash not found".to_string()));
    };

    let existing_batch: Option<Batch> = schema::batches::table
        .filter(schema::batches::id.eq(record.batch_id.unwrap_or(0)))
        .first::<Batch>(&mut conn)
        .optional()
        .map_err(|_e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error locating batch for provided hash".to_string(),
            )
        })?;

    let mut proof_response = ProofResponse {
        confirmed: false,
        header_hash: None,
        coin_id: None,
        root_hash: String::new(),
        leaf_hash: hex::encode(hash_array),
        proof: vec![],
    };
    let records: Vec<Record>;
    if let Some(batch) = existing_batch {
        proof_response.coin_id = Some(hex::encode(batch.spent_coin));
        if let Some(header_hash) = batch.block_hash {
            proof_response.confirmed = true;
            proof_response.header_hash = Some(hex::encode(header_hash));
        }
        records = records_for_batch(conn, batch.id);
    } else {
        records = records_up_to_record(conn, &record);
    }
    let leaves = records_to_leaves(&records).map_err(|_e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to process leaves for batch".to_string(),
        )
    })?;

    let root_hash = build_merkle_root(&leaves);
    let index = leaves.iter().position(|&leaf| leaf == hash_array).ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "Hash not found in leaves".to_string(),
    ))?;
    let proof = merkle_proof(&leaves, index);
    proof_response.root_hash = hex::encode(root_hash);
    proof_response.proof = proof;

    Ok(Json(proof_response))
}

/// Wallet task that runs concurrently with the web server
/// This function will return Ok(()) when the peer disconnects, which should trigger a reconnect
async fn wallet_task(pool: DbPool, network: &str) -> Result<()> {
    info!("Starting Wallet Service");
    let minimum_records_str = env::var("MINIMUM_COMMIT").unwrap_or(1.to_string());
    let minimum_records: u16 = minimum_records_str.parse()?;
    info!("Minimum record count: {minimum_records}");

    let max_age_str = env::var("MAX_AGE").unwrap_or(300.to_string());
    let max_age_seconds: u64 = max_age_str.parse()?;
    info!("Max age for oldest record: {max_age_seconds} seconds");
    let ssl = load_ssl_cert("wallet.crt", "wallet.key")?;
    let connector = create_rustls_connector(&ssl)?;
    let constants = if network == "testnet11" {
        &TESTNET11_CONSTANTS
    } else {
        &MAINNET_CONSTANTS
    };

    let (peer, mut receiver) = connect_peer(
        network.to_string(),
        connector,
        format!("{}:{}", env::var("PEER_ADDRESS")?, env::var("PEER_PORT")?).parse()?,
        PeerOptions::default(),
    )
    .await?;
    info!("Connected to peer {}", peer.socket_addr());

    let mnemonic = env::var("MNEMONIC")?;
    let sk = get_key(&mnemonic, 0)?;
    let pk = sk.public_key();
    let p2_puzzle_hash: Bytes32 = StandardArgs::curry_tree_hash(pk).into();
    let prefix = if network == "testnet11" {
        "txch"
    } else {
        "xch"
    };
    let address = Address::new(p2_puzzle_hash, String::from_str(prefix)?);
    info!("Address is {}", address.encode()?);

    // Sit around and wait for new messages from the connected peer
    // Ignore unless NewPeakWallet
    // When receiver.recv() returns None, the peer has disconnected
    while let Some(message) = receiver.recv().await {
        if message.msg_type != ProtocolMessageTypes::NewPeakWallet {
            continue;
        }

        // When we receive a new peak, we want to get our balance and then make a spend
        let peak = NewPeakWallet::from_bytes(&message.data)?;
        info!("Received new peak {peak:?}");

        // Get a fresh database connection for this iteration
        let mut conn = match pool.get() {
            Ok(conn) => conn,
            Err(e) => {
                error!("Failed to get database connection: {e:?}");
                continue;
            }
        };

        // If we have a pending batch, check if it has been confirmed
        // Check if we have a pending batch - if so, don't try and make a new one
        let pending_batch = match schema::batches::table
            .filter(schema::batches::block_hash.is_null())
            .get_result::<Batch>(&mut conn)
            .optional()
        {
            Ok(batch) => batch,
            Err(e) => {
                error!("Failed to query pending batch: {e:?}");
                continue;
            }
        };

        if let Some(pending_batch_u) = pending_batch {
            info!(
                "Have pending batch for coin ID {}",
                hex::encode(&pending_batch_u.spent_coin)
            );

            // Retry coin state request with error handling
            let coin_state_result = retry_peer_operation(|| async {
                peer.request_coin_state(
                    vec![Bytes32::try_from(&pending_batch_u.spent_coin)?],
                    None,
                    constants.genesis_challenge,
                    false,
                )
                .await
                .map_err(|e| anyhow::anyhow!("ClientError: {e:?}"))
            })
            .await;

            let coin_state = match coin_state_result {
                Ok(Ok(state)) => state,
                Ok(Err(e)) => {
                    warn!("Unable to check coin state: {e:?}. Waiting for confirmation");
                    continue;
                }
                Err(e) => {
                    error!("Failed to check coin state after retries: {e:?}");
                    continue;
                }
            };

            if coin_state.coin_states.is_empty() || coin_state.coin_states[0].spent_height.is_none()
            {
                info!("Still pending. Waiting for confirmation...");
                continue;
            }

            let confirmed_height = coin_state.coin_states[0].spent_height.unwrap();
            info!("Coin was confirmed at height {confirmed_height}");

            let block_header_result: Result<RespondBlockHeader> = retry_peer_operation(|| async {
                peer.request_infallible(RequestBlockHeader::new(confirmed_height))
                    .await
                    .map_err(|e| anyhow::anyhow!("ClientError: {e:?}"))
            })
            .await;

            let block_header = match block_header_result {
                Ok(header) => header,
                Err(e) => {
                    error!("Failed to get block header after retries: {e:?}");
                    continue;
                }
            };

            let header_hash = block_header.header_block.header_hash();
            info!("Block header hash is {}", hex::encode(header_hash));

            // Update the batch record in the database with the block hash
            if let Err(e) = diesel::update(
                schema::batches::table.filter(schema::batches::id.eq(pending_batch_u.id)),
            )
            .set(schema::batches::block_hash.eq(Some(header_hash.as_slice())))
            .execute(&mut conn)
            {
                error!("Failed to update batch with block hash: {e:?}");
                continue;
            }

            info!(
                "Updated batch {} with block hash {}",
                pending_batch_u.id,
                hex::encode(header_hash)
            );
            // @TODO probably need to deal with reorgs
            // @TODO probably store "how buried" this particular batch is?
        }

        // Request unspent coin states from the full node for our p2_puzzle_hash
        // request_puzzle_state returns Result<Result<RespondPuzzleState, RejectPuzzleState>, ClientError>
        let coin_states_result = retry_peer_operation(|| async {
            peer.request_puzzle_state(
                vec![p2_puzzle_hash],
                None,
                constants.genesis_challenge,
                CoinStateFilters::new(false, true, false, 0),
                false,
            )
            .await
            .map_err(|e| anyhow::anyhow!("ClientError: {e:?}"))
            .and_then(|inner_result| {
                inner_result.map_err(|e| anyhow::anyhow!("RejectPuzzleState: {e:?}"))
            })
        })
        .await;

        let coin_states = match coin_states_result {
            Ok(state) => state.coin_states,
            Err(e) => {
                error!("Failed to request puzzle state after retries: {e:?}");
                continue;
            }
        };

        // Calculate and print the balance
        let balance: u64 = coin_states.iter().map(|cs| cs.coin.amount).sum();
        info!("Balance: {balance} mojos");

        if balance == 0 {
            continue;
        }

        info!("Attempting to create new batch");
        let pending_records = schema::records::table
            .filter(schema::records::batch_id.is_null())
            .order(schema::records::id.asc())
            .get_results::<Record>(&mut conn)?;

        // Check if we have enough records OR if the oldest record is too old
        let should_create_batch = if pending_records.is_empty() {
            false
        } else if pending_records.len() >= minimum_records.into() {
            true
        } else {
            // Check if the oldest pending record is older than MAX_AGE
            let oldest_record = &pending_records[0];
            let now = Utc::now().naive_utc();
            let age_seconds =
                u64::try_from((now - oldest_record.created_at).num_seconds().max(0)).unwrap_or(0);

            if age_seconds >= max_age_seconds {
                info!(
                    "Oldest pending record is {} seconds old (>= {}), creating batch despite only having {} records",
                    age_seconds,
                    max_age_seconds,
                    pending_records.len()
                );
                true
            } else {
                false
            }
        };

        if !should_create_batch {
            if pending_records.is_empty() {
                info!("No pending records, not creating new batch");
            } else {
                let oldest_record = &pending_records[0];
                let now = Utc::now().naive_utc();
                let age_seconds =
                    u64::try_from((now - oldest_record.created_at).num_seconds().max(0))
                        .unwrap_or(0);
                info!(
                    "Not enough pending records ({}/{}) and oldest record is only {} seconds old (< {}), not creating new batch",
                    pending_records.len(),
                    minimum_records,
                    age_seconds,
                    max_age_seconds
                );
            }
            continue;
        }
        let leaves: Vec<[u8; 32]> = pending_records
            .iter()
            .map(|x| {
                x.hash
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Invalid hash format in database"))
            })
            .collect::<Result<Vec<[u8; 32]>, anyhow::Error>>()?;
        let root = build_merkle_root(&leaves);
        info!("Merkle root is {}", hex::encode(root));

        let new_batch = NewBatch {
            root_hash: &root,
            spent_coin: &coin_states[0].coin.coin_id(),
        };
        let batch_id = conn.transaction::<_, anyhow::Error, _>(|conn| {
            // Insert the new batch
            diesel::insert_into(schema::batches::table)
                .values(&new_batch)
                .execute(conn)
                .map_err(|_e| anyhow::anyhow!("Database insert failed"))?;

            // Get the last inserted ID (MySQL specific)
            let batch_id: u32 = diesel::select(diesel::dsl::sql::<
                diesel::sql_types::Unsigned<diesel::sql_types::Integer>,
            >("LAST_INSERT_ID()"))
            .get_result(conn)
            .map_err(|_e| anyhow::anyhow!("Failed to get last insert ID"))?;

            // Update only the specific records that were included in the Merkle root
            let record_ids: Vec<u32> = pending_records.iter().map(|r| r.id).collect();
            diesel::update(schema::records::table.filter(schema::records::id.eq_any(record_ids)))
                .set(schema::records::batch_id.eq(batch_id))
                .execute(conn)
                .map_err(|_e| anyhow::anyhow!("Failed to update pending records"))?;

            Ok(batch_id)
        })?;

        info!(
            "Created batch {} and updated {} pending records. Generating spend...",
            batch_id,
            pending_records.len()
        );

        // Create a new SpendContext, which helps create spendbundles in a simple manner
        let mut ctx = SpendContext::new();
        // Specify our p2_puzzle_hash as the address for change
        let mut spends = Spends::new(p2_puzzle_hash);
        spends.add(coin_states[0].coin);

        let memos = vec![ctx.alloc(&Bytes::from(root.as_slice()))?];
        let actions = vec![Action::send(
            Id::Xch,
            p2_puzzle_hash,
            coin_states[0].coin.amount,
            ctx.memos(&memos)?,
        )];

        // Apply the actions to the spend context and get the deltas (changes)
        let deltas = spends.apply(&mut ctx, &actions)?;

        let _outputs = spends.finish_with_keys(
            &mut ctx,
            &deltas,
            Relation::AssertConcurrent,
            &indexmap! {
                p2_puzzle_hash => pk,
            },
        )?;

        let coin_spends = ctx.take();

        let required_signatures = RequiredSignature::from_coin_spends(
            &mut ctx,
            &coin_spends,
            &AggSigConstants::new(constants.agg_sig_me_additional_data),
        )?;

        // Start with an empty signature that we'll aggregate individual signatures into
        let mut signature = Signature::default();

        // Go through each required signature and sign the message
        for required in required_signatures {
            // We only handle BLS signatures (skip other types)
            let RequiredSignature::Bls(required) = required else {
                continue;
            };

            // Make sure we have the right public key for this signature
            if required.public_key != pk {
                bail!("Missing public key for spend");
            }

            // Sign the required message with our secret key and add it to the aggregated signature
            // The += operator combines signatures using BLS signature aggregation
            signature += &sign(&sk, required.message());
        }

        // Create a spendbundle with the final coin spends and signature
        let spend_bundle = SpendBundle::new(coin_spends, signature);

        // Send the resulting spendbundle to the network via the connected peer
        // Note: send_transaction consumes the spend_bundle, so we can't easily retry it
        // If it fails, we'll log the error but continue - the transaction might have been sent
        match peer.send_transaction(spend_bundle).await {
            Ok(ack) => {
                info!("Transaction ack {ack:?}");
            }
            Err(e) => {
                error!("Failed to send transaction: {e:?}");
                // Continue processing - the transaction might have been sent but ack failed
                // The peer will reconnect and we can check the coin state later
            }
        }
    }

    // When receiver.recv() returns None, the peer has disconnected
    info!("Peer disconnected (receiver closed)");
    Err(anyhow::anyhow!("Peer disconnected"))
}

/// Helper function to retry peer operations that might fail due to transient network issues
async fn retry_peer_operation<F, Fut, T>(operation: F) -> Result<T>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    const MAX_RETRIES: u32 = 3;
    const RETRY_DELAY_SECS: u64 = 2;

    let mut last_error = None;

    for attempt in 1..=MAX_RETRIES {
        match operation().await {
            Ok(result) => {
                if attempt > 1 {
                    info!("Peer operation succeeded on attempt {attempt}");
                }
                return Ok(result);
            }
            Err(e) => {
                let error_msg = format!("{e:?}");
                last_error = Some(e);
                if attempt < MAX_RETRIES {
                    warn!(
                        "Peer operation failed (attempt {attempt}/{MAX_RETRIES}): {error_msg}. Retrying in {RETRY_DELAY_SECS} seconds..."
                    );
                    tokio::time::sleep(tokio::time::Duration::from_secs(RETRY_DELAY_SECS)).await;
                }
            }
        }
    }

    Err(last_error
        .unwrap_or_else(|| anyhow::anyhow!("Operation failed after {MAX_RETRIES} attempts")))
}

fn get_key(mnemonic: &str, index: u32) -> Result<SecretKey> {
    let mnemonic = Mnemonic::from_str(mnemonic)?;
    let seed = mnemonic.to_seed("");
    Ok(
        master_to_wallet_unhardened_intermediate(&SecretKey::from_seed(&seed))
            .derive_unhardened(index)
            .derive_synthetic(),
    )
}

/// Fetches all records, in order, up to the given record
/// Will either restrict to pending records (if the given record is pending)
/// or else records from the same batch
/// Used to construct a partial proof up to and including the given record
fn records_up_to_record(mut conn: DbConnection, record: &Record) -> Vec<Record> {
    let mut query = schema::records::table
        .filter(schema::records::id.le(record.id))
        .into_boxed();

    if let Some(batch_id) = record.batch_id {
        query = query.filter(schema::records::batch_id.eq(batch_id));
    } else {
        query = query.filter(schema::records::batch_id.is_null());
    }

    query
        .order(schema::records::id.asc())
        .get_results::<Record>(&mut conn)
        .map_err(|_e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error loading other records to compute partial proof".to_string(),
            )
        })
        .unwrap_or(vec![])
}

fn records_for_batch(mut conn: DbConnection, batch_id: u32) -> Vec<Record> {
    schema::records::table
        .filter(schema::records::batch_id.eq(batch_id))
        .order(schema::records::id.asc())
        .get_results::<Record>(&mut conn)
        .map_err(|_e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error loading other records to compute partial proof".to_string(),
            )
        })
        .unwrap_or(vec![])
}

fn records_to_leaves(records: &[Record]) -> Result<Vec<[u8; 32]>> {
    records
        .iter()
        .map(|x| {
            x.hash
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("Invalid hash format in database"))
        })
        .collect::<Result<Vec<[u8; 32]>, anyhow::Error>>()
}
