use crate::merkle_tree::tree::{ProofStep, build_merkle_root, merkle_proof};
use crate::models::{Batch, NewBatch, NewRecord, Record};
use anyhow::{Result, bail};
use axum::http::StatusCode;
use axum::{Json, Router, extract::State, http, routing::post};
use chia_wallet_sdk::client::{
    ClientError, PeerOptions, connect_peer, create_rustls_connector, load_ssl_cert,
};
use diesel::prelude::*;
use diesel::r2d2::ConnectionManager;
use diesel::r2d2::Pool;
use dotenvy::dotenv;
use log::info;
use rustls::crypto::aws_lc_rs;
use serde::{Deserialize, Serialize};
use std::{env, net::SocketAddr};
use tower_http::cors::{Any, CorsLayer};

use bip39::Mnemonic;
use chia::protocol::{RequestBlockHeader, RespondBlockHeader};
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

// @TODO we'll have to return some info about when this happened, so that once its in a block, we can look it up
// and provide a full proof including block hash, coin ID, etc that it was included in
#[derive(Serialize, Deserialize)]
pub struct StampResponse {
    pub root_hash: String,
    pub leaf_hash: String,
    pub proof: Vec<ProofStep>,
}

pub type DbPool = Pool<ConnectionManager<MysqlConnection>>;
#[derive(Clone)]
pub struct AppState {
    pub db_pool: DbPool,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    env_logger::init();
    aws_lc_rs::default_provider()
        .install_default()
        .expect("installing AWS-LC provider failed");

    let pool = get_connection_pool();
    let background_pool = pool.clone();
    let state = AppState { db_pool: pool };

    // Spawn background task
    tokio::spawn(async move {
        let _ = background_task(background_pool).await;
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
        .with_state(state)
        .layer(cors);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Listening on {addr}");
    axum::serve(tokio::net::TcpListener::bind(addr).await.unwrap(), app).await?;
    Ok(())
}

pub fn get_connection_pool() -> Pool<ConnectionManager<MysqlConnection>> {
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let manager = ConnectionManager::<MysqlConnection>::new(database_url);
    Pool::builder()
        .test_on_check_out(true)
        .build(manager)
        .expect("Could not build connection pool")
}

async fn stamp(
    State(state): State<AppState>,
    Json(payload): Json<StampRequest>,
) -> Result<Json<StampResponse>, (StatusCode, String)> {
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

    // @TODO if the hash was for an old already included record, return the full proof
    // Now we need to get all pending records, in order, prior to the one we just inserted
    let current_record = existing_record.ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "Record not found after insert".to_string(),
    ))?;

    let other_records = schema::records::table
        .filter(schema::records::batch_id.is_null())
        .filter(schema::records::id.lt(current_record.id))
        .order(schema::records::id.asc())
        .get_results::<Record>(&mut conn)
        .map_err(|_e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error loading other records to compute partial proof".to_string(),
            )
        })?;

    // Get all the existing pending records into the tree
    let mut current_leaves: Vec<[u8; 32]> = other_records
        .iter()
        .map(|x| {
            x.hash.as_slice().try_into().map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Invalid hash format in database".to_string(),
                )
            })
        })
        .collect::<Result<Vec<[u8; 32]>, (StatusCode, String)>>()?;
    // Add the new one
    // This is current safe to do even if it's an old pending record, since
    // we only fetch "current" leaves older than this hash
    current_leaves.push(hash_array);

    let root = build_merkle_root(&current_leaves);
    let proof = merkle_proof(&current_leaves, current_leaves.len() - 1);

    Ok(Json(StampResponse {
        root_hash: hex::encode(root),
        leaf_hash: hex::encode(hash_array),
        proof,
    }))
}

/// Background task that runs concurrently with the web server
async fn background_task(pool: DbPool) -> Result<()> {
    info!("Starting Wallet Service");
    let ssl = load_ssl_cert("wallet.crt", "wallet.key")?;
    let connector = create_rustls_connector(&ssl)?;

    let (peer, mut receiver) = connect_peer(
        "testnet11".to_string(),
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
    let address = Address::new(p2_puzzle_hash, String::from_str("txch")?);
    info!("Address is {}", address.encode()?);

    let mut conn = pool.get()?;

    // Sit around and wait for new messages from the connected peer
    // Ignore unless NewPeakWallet
    while let Some(message) = receiver.recv().await {
        if message.msg_type != ProtocolMessageTypes::NewPeakWallet {
            continue;
        }

        // When we receive a new peak, we want to get our balance and then make a spend
        let peak = NewPeakWallet::from_bytes(&message.data)?;
        info!("Received new peak {peak:?}");

        // If we have a pending batch, check if it has been confirmed
        // Check if we have a pending batch - if so, don't try and make a new one
        let pending_batch = schema::batches::table
            .filter(schema::batches::block_hash.is_null())
            .get_result::<Batch>(&mut conn)
            .optional()?;

        if let Some(pending_batch_u) = pending_batch {
            info!(
                "Have pending batch for coin ID {}",
                hex::encode(&pending_batch_u.spent_coin)
            );
            let coin_state = peer
                .request_coin_state(
                    vec![Bytes32::try_from(&pending_batch_u.spent_coin)?],
                    None,
                    TESTNET11_CONSTANTS.genesis_challenge,
                    false,
                )
                .await?;
            if coin_state.is_err() {
                info!("Unable to check coin state. Waiting for confirmation");
                continue;
            }
            let state_u = coin_state.unwrap();
            if state_u.coin_states.is_empty() || state_u.coin_states[0].spent_height.is_none() {
                info!("Still pending. Waiting for confirmation...");
                continue;
            }

            let confirmed_height = state_u.coin_states[0].spent_height.unwrap();
            info!("Coin was confirmed at height {confirmed_height}");

            let block_header: std::result::Result<RespondBlockHeader, ClientError> = peer
                .request_infallible(RequestBlockHeader::new(confirmed_height))
                .await;
            let header_hash = block_header?.header_block.header_hash();
            info!("Block header hash is {}", hex::encode(header_hash));

            // Update the batch record in the database with the block hash
            diesel::update(
                schema::batches::table.filter(schema::batches::id.eq(pending_batch_u.id)),
            )
            .set(schema::batches::block_hash.eq(Some(header_hash.as_slice())))
            .execute(&mut conn)
            .map_err(|e| anyhow::anyhow!("Failed to update batch with block hash: {}", e))?;

            info!(
                "Updated batch {} with block hash {}",
                pending_batch_u.id,
                hex::encode(header_hash)
            );
            // @TODO probably need to deal with reorgs
            // @TODO probably store "how buried" this particular batch is?
        }

        // Request unspent coin states from the full node for our p2_puzzle_hash
        let coin_states = peer
            .request_puzzle_state(
                vec![p2_puzzle_hash],
                None,
                TESTNET11_CONSTANTS.genesis_challenge,
                CoinStateFilters::new(false, true, false, 0),
                false,
            )
            .await?
            .unwrap()
            .coin_states;

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
        if pending_records.is_empty() {
            info!("No pending records, not creating new batch");
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

        // Set up a Vec<Action> to track the specific actions we want to perform in this spend
        // Actions are a simple way to compose numerous types of outputs into a single spend
        let actions = vec![Action::send(
            Id::Xch,
            p2_puzzle_hash,
            coin_states[0].coin.amount,
            ctx.memos(&root)?,
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
            &AggSigConstants::new(TESTNET11_CONSTANTS.agg_sig_me_additional_data),
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
        let ack = peer.send_transaction(spend_bundle).await?;

        info!("Transaction ack {ack:?}");
    }

    info!("Disconnected from peer {}", peer.socket_addr());

    Ok(())
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
