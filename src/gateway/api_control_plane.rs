//! Control plane REST API handlers.

use super::control_plane::{NodeCapability, NodeInfo, NodeStatus};
use super::AppState;
use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Json},
};
use chrono::Utc;
use serde::Deserialize;
use std::collections::HashMap;

fn require_auth(state: &AppState, headers: &HeaderMap) -> Result<(), (StatusCode, &'static str)> {
    if state.pairing.require_pairing() {
        let token = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|auth| auth.strip_prefix("Bearer "))
            .unwrap_or("");
        if !state.pairing.is_authenticated(token) {
            return Err((StatusCode::UNAUTHORIZED, "Unauthorized"));
        }
    }
    Ok(())
}

/// GET /api/control-plane/nodes — list all registered nodes
pub async fn list_nodes(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    match &state.control_plane {
        Some(cp) => {
            let nodes = cp.list_nodes();
            let count = nodes.len();
            Json(serde_json::json!({
                "nodes": nodes,
                "count": count
            }))
            .into_response()
        }
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Control plane not enabled",
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct RegisterNodeRequest {
    pub id: String,
    pub name: Option<String>,
    pub address: Option<String>,
    pub version: Option<String>,
    #[serde(default)]
    pub capabilities: Vec<NodeCapability>,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

/// POST /api/control-plane/nodes — register a new node
pub async fn register_node(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RegisterNodeRequest>,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    match &state.control_plane {
        Some(cp) => {
            let node_id = body.id.clone();
            let info = NodeInfo {
                id: body.id,
                name: body.name,
                address: body.address,
                version: body.version,
                capabilities: body.capabilities,
                status: NodeStatus::Healthy,
                registered_at: Utc::now(),
                last_heartbeat: Utc::now(),
                missed_heartbeats: 0,
                metadata: body.metadata,
            };

            if cp.register(info) {
                (
                    StatusCode::CREATED,
                    Json(serde_json::json!({
                        "message": "Node registered",
                        "node_id": node_id
                    })),
                )
                    .into_response()
            } else {
                (StatusCode::CONFLICT, "Node capacity reached").into_response()
            }
        }
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Control plane not enabled",
        )
            .into_response(),
    }
}

/// POST /api/control-plane/nodes/{id}/heartbeat — record a heartbeat
pub async fn node_heartbeat(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(node_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    match &state.control_plane {
        Some(cp) => {
            if cp.heartbeat(&node_id) {
                Json(serde_json::json!({
                    "message": "Heartbeat recorded",
                    "node_id": node_id
                }))
                .into_response()
            } else {
                (StatusCode::NOT_FOUND, "Node not found").into_response()
            }
        }
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Control plane not enabled",
        )
            .into_response(),
    }
}

/// DELETE /api/control-plane/nodes/{id} — deregister a node
pub async fn deregister_node(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(node_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    match &state.control_plane {
        Some(cp) => {
            if cp.deregister(&node_id) {
                Json(serde_json::json!({
                    "message": "Node deregistered",
                    "node_id": node_id
                }))
                .into_response()
            } else {
                (StatusCode::NOT_FOUND, "Node not found").into_response()
            }
        }
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Control plane not enabled",
        )
            .into_response(),
    }
}
