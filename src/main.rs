use crate::merkle_tree::tree::{ProofStep, build_merkle_root, merkle_proof};
use crate::models::{NewRecord};
use axum::http::StatusCode;
use axum::{Json, Router, extract::State, http, routing::post};
use diesel::prelude::*;
use diesel::r2d2::ConnectionManager;
use diesel::r2d2::Pool;
use dotenvy::dotenv;
use log::info;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{env, net::SocketAddr};
use tower_http::cors::{Any, CorsLayer};

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
async fn main() {
    dotenv().ok();
    env_logger::init();

    let pool = get_connection_pool();
    let state = AppState { db_pool: pool };

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
    axum::serve(tokio::net::TcpListener::bind(addr).await.unwrap(), app)
        .await
        .unwrap();
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

    // Insert into the DB
    let mut conn = state.db_pool.get().expect("Unable to get db connection");
    let new_record = NewRecord {
        hash: hash_array.as_slice(),
    };
    conn.transaction(|conn| {
        diesel::insert_into(schema::records::table)
            .values(&new_record)
            .execute(conn)
    })
    .expect("error saving record");

    // @TODO get all other pending leaves from the database, in order
    // Or perhaps, that doesn't even matter, and what we need to return with a stamp is just a confirmation
    // and perhaps an internal identifier to make it easier to look up later?
    // Order will have to be determined when we make the spend, and we can record order then
    // and encode that in the final proof once a block is made
    //let current_leaves: Vec<[u8; 32]> = vec![];

    let leaf_values = ["a", "b", "c", "d", "e", "f"];
    let mut current_leaves: Vec<[u8; 32]> = leaf_values
        .iter()
        .map(|x| {
            let mut hasher = Sha256::new();
            hasher.update(x.as_bytes());
            hasher.finalize().into()
        })
        .collect();
    current_leaves.push(hash_array);

    let root = build_merkle_root(&current_leaves);
    let proof = merkle_proof(&current_leaves, current_leaves.len());

    Ok(Json(StampResponse {
        root_hash: hex::encode(root),
        leaf_hash: hex::encode(hash_array),
        proof,
    }))
}
