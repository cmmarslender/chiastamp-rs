use crate::merkle_tree::tree::{ProofStep, build_merkle_root, merkle_proof, verify_proof};
use axum::http::StatusCode;
use axum::serve::Listener;
use axum::{Json, Router, extract::State, http, routing::post};
use log::info;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tower_http::cors::{Any, CorsLayer};

mod merkle_tree;

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

#[tokio::main]
async fn main() {
    env_logger::init();
    let port: u16 = 8080;

    let cors = CorsLayer::new()
        .allow_methods([http::Method::POST])
        .allow_origin(Any)
        .allow_headers(Any);

    let app = Router::new().route("/stamp", post(stamp)).layer(cors);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Listening on {addr}");
    axum::serve(tokio::net::TcpListener::bind(addr).await.unwrap(), app)
        .await
        .unwrap();
}

async fn stamp(
    //State(state): State<AppState>,
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
