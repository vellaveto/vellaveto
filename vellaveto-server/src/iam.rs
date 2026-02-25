use axum::{
    extract::{Form, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use flate2::read::DeflateDecoder;
use jsonwebtoken::{
    decode, decode_header,
    jwk::{JwkSet, KeyAlgorithm},
    Algorithm, DecodingKey, Validation,
};
use rand::rngs::OsRng;
use rand::RngCore;
use reqwest::{header as reqwest_header, Client};
use roxmltree::Document;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    env,
    io::{Cursor, Read},
    sync::Arc,
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::{sync::RwLock, task::JoinHandle, time::sleep};
use tracing::{info, warn};
use url::Url;
use uuid::Uuid;
use vellaveto_types::has_dangerous_chars;

use crate::rbac::{Role, RoleClaims};
use crate::routes::ErrorResponse;
use crate::AppState;
use vellaveto_config::{
    iam::{OidcConfig as VellavetoOidcConfig, ScimConfig},
    IamConfig,
};

const FLOW_TTL_SECS: u64 = 300;
const MAX_NEXT_LEN: usize = 512;

#[derive(Debug, Default)]
struct ScimStatus {
    last_sync: Option<DateTime<Utc>>,
    last_error: Option<String>,
    last_user_count: Option<usize>,
    last_sync_duration_ms: Option<u128>,
}

/// Shared IAM state (OIDC + SAML + session management) for Phase 46.
#[derive(Debug)]
pub struct IamState {
    config: IamConfig,
    discovery: OidcDiscovery,
    http: Client,
    flow_states: DashMap<String, FlowState>,
    sessions: DashMap<String, IamSession>,
    jwks_cache: RwLock<Option<CachedJwks>>,
    saml_state: Option<SamlState>,
    scim_status: Arc<RwLock<ScimStatus>>,
    scim_task: Option<JoinHandle<()>>,
}

impl IamState {
    /// Build IAM state from configuration, fetching OIDC discovery metadata.
    pub async fn new(config: IamConfig) -> Result<Self, IamError> {
        if !config.enabled {
            return Err(IamError::Disabled);
        }
        if !config.oidc.enabled {
            return Err(IamError::OidcDisabled);
        }
        let discovery = OidcDiscovery::fetch(&config.oidc, config.oidc.allow_insecure_issuer)
            .await
            .map_err(IamError::Discovery)?;
        let http = Client::builder()
            .user_agent("Vellaveto IAM/1.0")
            .build()
            .map_err(|e| IamError::Client(e.to_string()))?;
        let saml_state = if config.saml.enabled {
            Some(SamlState::new(&config.saml, &http).await?)
        } else {
            None
        };
        let scim_status = Arc::new(RwLock::new(ScimStatus::default()));
        let scim_task = if config.scim.enabled {
            let endpoint = config
                .scim
                .endpoint
                .clone()
                .ok_or_else(|| IamError::Scim("iam.scim.endpoint missing".to_string()))?;
            let token = resolve_scim_token(&config.scim)?;
            Some(spawn_scim_sync(
                http.clone(),
                endpoint,
                token,
                config.scim.sync_interval_secs,
                scim_status.clone(),
            ))
        } else {
            None
        };
        Ok(Self {
            config,
            discovery,
            http,
            flow_states: DashMap::new(),
            sessions: DashMap::new(),
            jwks_cache: RwLock::new(None),
            saml_state,
            scim_status,
            scim_task,
        })
    }

    /// Name of the session cookie.
    pub fn session_cookie_name(&self) -> &str {
        &self.config.session.cookie_name
    }

    /// Begin a login flow and return (state_id, flow_state, authorization URL).
    fn begin_login_flow(&self, next: Option<String>) -> (String, FlowState, String) {
        self.cleanup_flows();
        let state_id = Uuid::new_v4().to_string();
        let code_verifier = generate_code_verifier();
        let code_challenge = pkce_code_challenge(&code_verifier);
        let nonce = Uuid::new_v4().to_string();
        let next_path = sanitize_next(next);
        let flow = FlowState::new(next_path.clone(), code_verifier.clone(), nonce.clone());
        let authorize_url =
            self.build_authorize_url(&state_id, &code_challenge, &nonce, &self.config.oidc.scopes);
        (state_id, flow, authorize_url)
    }

    /// Insert a login flow state. Returns the inserted state_id.
    fn store_flow(&self, state_id: String, flow: FlowState) {
        self.flow_states.insert(state_id, flow);
    }

    /// Consume a login flow if present and not expired.
    fn consume_flow(&self, state_id: &str) -> Option<FlowState> {
        let now = Instant::now();
        if let Some((_, flow)) = self.flow_states.remove(state_id) {
            if flow.is_expired_at(now) {
                return None;
            }
            Some(flow)
        } else {
            None
        }
    }

    /// Exchange the authorization code for tokens.
    async fn exchange_code(&self, code: &str, flow: &FlowState) -> Result<TokenResponse, IamError> {
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            (
                "redirect_uri",
                self.config.oidc.redirect_uri.as_deref().unwrap_or_default(),
            ),
            (
                "client_id",
                self.config.oidc.client_id.as_deref().unwrap_or_default(),
            ),
            ("code_verifier", &flow.code_verifier),
        ];
        if let Some(secret) = &self.config.oidc.client_secret {
            form.push(("client_secret", secret));
        }
        let response = self
            .http
            .post(&self.discovery.token_endpoint)
            .form(&form)
            .send()
            .await
            .map_err(|e| IamError::TokenExchange(e.to_string()))?
            .error_for_status()
            .map_err(|e| IamError::TokenExchange(e.to_string()))?;
        let tokens = response
            .json::<TokenResponse>()
            .await
            .map_err(|e| IamError::TokenExchange(e.to_string()))?;
        Ok(tokens)
    }

    /// Verify the ID token signature and nonce.
    pub async fn verify_id_token(
        &self,
        id_token: &str,
        flow_nonce: &str,
    ) -> Result<RoleClaims, IamError> {
        let header = decode_header(id_token).map_err(|e| IamError::InvalidToken(e.to_string()))?;
        let decoding_key = self.decoding_key(header.kid.as_deref(), header.alg).await?;
        let mut validation = Validation::new(header.alg);
        if let Some(issuer) = &self.config.oidc.issuer_url {
            validation.set_issuer(&[issuer]);
        }
        if let Some(client_id) = &self.config.oidc.client_id {
            validation.set_audience(&[client_id]);
        }
        validation.leeway = 60;
        let token_data = decode::<RoleClaims>(id_token, &decoding_key, &validation)
            .map_err(|e| IamError::InvalidToken(e.to_string()))?;
        let claims = token_data.claims;
        if claims.nonce.as_deref() != Some(flow_nonce) {
            return Err(IamError::NonceMismatch);
        }
        Ok(claims)
    }

    fn cleanup_flows(&self) {
        let now = Instant::now();
        let expired: Vec<_> = self
            .flow_states
            .iter()
            .filter_map(|entry| {
                if entry.value().is_expired_at(now) {
                    Some(entry.key().clone())
                } else {
                    None
                }
            })
            .collect();
        for key in expired {
            self.flow_states.remove(&key);
        }
    }

    fn build_authorize_url(
        &self,
        state: &str,
        code_challenge: &str,
        nonce: &str,
        scopes: &[String],
    ) -> String {
        let mut url = Url::parse(&self.discovery.authorization_endpoint).unwrap_or_else(|_| {
            Url::parse("http://invalid").expect("authorization endpoint is valid URL by validation")
        });
        let scope = scopes.join(" ");
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("response_type", "code");
            if let Some(client_id) = &self.config.oidc.client_id {
                query.append_pair("client_id", client_id);
            }
            if let Some(redirect) = &self.config.oidc.redirect_uri {
                query.append_pair("redirect_uri", redirect);
            }
            query.append_pair("scope", &scope);
            query.append_pair("state", state);
            query.append_pair("nonce", nonce);
            query.append_pair("code_challenge", code_challenge);
            query.append_pair("code_challenge_method", "S256");
        }
        url.into()
    }

    async fn decoding_key(
        &self,
        kid: Option<&str>,
        alg: Algorithm,
    ) -> Result<DecodingKey, IamError> {
        let kid_value = kid.unwrap_or("");
        let jwks = self.ensure_jwks().await?;
        find_key_in_jwks(&jwks, kid_value, &alg).ok_or_else(|| {
            IamError::Jwks(format!(
                "No matching key for kid='{}' alg='{:?}'",
                kid_value, alg
            ))
        })
    }

    async fn ensure_jwks(&self) -> Result<Arc<JwkSet>, IamError> {
        let ttl = Duration::from_secs(self.config.oidc.jwks_cache_secs);
        let now = Instant::now();
        let mut guard = self.jwks_cache.write().await;
        let needs_refresh = guard
            .as_ref()
            .map(|cached| now.duration_since(cached.fetched_at) >= ttl)
            .unwrap_or(true);
        if needs_refresh {
            let jwks = self
                .fetch_jwks()
                .await
                .map_err(|e| IamError::Jwks(format!("Failed to fetch JWKS: {}", e)))?;
            *guard = Some(CachedJwks {
                keys: Arc::new(jwks),
                fetched_at: now,
            });
        }
        Ok(Arc::clone(
            &guard.as_ref().expect("JWKS cache just populated").keys,
        ))
    }

    async fn fetch_jwks(&self) -> Result<JwkSet, reqwest::Error> {
        let response = self
            .http
            .get(&self.discovery.jwks_uri)
            .send()
            .await?
            .error_for_status()?;
        response.json::<JwkSet>().await
    }

    pub fn create_session(&self, claims: RoleClaims, scopes: Vec<String>) -> IamSession {
        let role = claims.effective_role().unwrap_or(Role::Viewer);
        let now = Instant::now();
        let session = IamSession {
            id: Uuid::new_v4().to_string(),
            subject: claims.sub.clone(),
            role,
            scopes,
            expires_at: now + Duration::from_secs(self.config.session.max_age_secs),
        };
        self.sessions.insert(session.id.clone(), session.clone());
        session
    }

    pub fn find_session(&self, id: &str) -> Option<IamSession> {
        let now = Instant::now();
        if let Some(session) = self.sessions.get(id) {
            if session.is_expired_at(now) {
                self.sessions.remove(id);
                return None;
            }
            return Some(session.clone());
        }
        None
    }

    pub fn remove_session(&self, id: &str) {
        self.sessions.remove(id);
    }

    pub fn session_cookie_header(
        &self,
        session_id: &str,
        max_age_secs: Option<u64>,
    ) -> Result<HeaderValue, IamError> {
        build_cookie_value(
            &self.config.session.cookie_name,
            session_id,
            max_age_secs,
            self.config.session.secure_cookie,
            self.config.session.http_only,
        )
    }

    pub fn expire_cookie_header(&self) -> Result<HeaderValue, IamError> {
        build_cookie_value(
            &self.config.session.cookie_name,
            "",
            Some(0),
            self.config.session.secure_cookie,
            self.config.session.http_only,
        )
    }
}

fn build_cookie_value(
    name: &str,
    value: &str,
    max_age_secs: Option<u64>,
    secure: bool,
    http_only: bool,
) -> Result<HeaderValue, IamError> {
    let mut parts = vec![format!("{}={}", name, value)];
    if let Some(max_age) = max_age_secs {
        parts.push(format!("Max-Age={}", max_age));
    }
    parts.push("Path=/".to_string());
    if http_only {
        parts.push("HttpOnly".to_string());
    }
    if secure {
        parts.push("Secure".to_string());
    }
    parts.push("SameSite=Strict".to_string());
    HeaderValue::from_str(&parts.join("; "))
        .map_err(|e| IamError::CookieEncode(format!("cookie header invalid: {}", e)))
}

/// Extract the session ID from the Cookie header using the configured name.
pub fn extract_session_cookie(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|raw| {
            raw.split(';').map(str::trim).find_map(|kv| {
                let prefix = format!("{}=", cookie_name);
                if kv.starts_with(&prefix) {
                    Some(kv[prefix.len()..].to_string())
                } else {
                    None
                }
            })
        })
}

/// Login query params.
#[derive(Deserialize)]
pub struct LoginParams {
    pub next: Option<String>,
}

/// Callback query params from the IdP.
#[derive(Deserialize)]
pub struct CallbackParams {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

/// Standard session info response.
#[derive(Serialize)]
pub struct SessionInfoResponse {
    pub session_id: String,
    pub subject: Option<String>,
    pub role: String,
    pub expires_in_secs: u64,
}

pub async fn login(
    State(state): State<AppState>,
    Query(params): Query<LoginParams>,
) -> Result<Redirect, (StatusCode, Json<ErrorResponse>)> {
    let iam = state.iam_state.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "IAM login is disabled".to_string(),
            }),
        )
    })?;
    let (state_id, flow, auth_url) = iam.begin_login_flow(params.next.clone());
    iam.store_flow(state_id.clone(), flow);
    Ok(Redirect::temporary(auth_url.as_str()))
}

pub async fn callback(
    State(state): State<AppState>,
    Query(params): Query<CallbackParams>,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    let iam = state.iam_state.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "IAM callback is disabled".to_string(),
            }),
        )
    })?;
    if let Some(ref err) = params.error {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("OIDC error: {}", err),
            }),
        ));
    }
    let code = params.code.as_ref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Missing authorization code".to_string(),
            }),
        )
    })?;
    let state_id = params.state.as_ref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Missing state parameter".to_string(),
            }),
        )
    })?;
    let flow = iam.consume_flow(state_id).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid or expired login state".to_string(),
            }),
        )
    })?;
    let tokens = iam.exchange_code(code, &flow).await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;
    let claims = iam
        .verify_id_token(&tokens.id_token, &flow.nonce)
        .await
        .map_err(|e| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
        })?;
    let scopes = parse_scope_list(tokens.scope.as_deref());
    let session = iam.create_session(claims, scopes);
    let cookie = iam
        .session_cookie_header(&session.id, Some(iam.config.session.max_age_secs))
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
        })?;
    let mut response = Redirect::temporary(&flow.next).into_response();
    response.headers_mut().append(header::SET_COOKIE, cookie);
    Ok(response)
}

pub async fn session_info(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SessionInfoResponse>, (StatusCode, Json<ErrorResponse>)> {
    let iam = state.iam_state.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "IAM is disabled".to_string(),
            }),
        )
    })?;
    let session_id =
        extract_session_cookie(&headers, iam.session_cookie_name()).ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Session cookie missing".to_string(),
                }),
            )
        })?;
    let session = iam.find_session(&session_id).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Session expired or invalid".to_string(),
            }),
        )
    })?;
    let expires_in = session.expires_in_secs();
    Ok(Json(SessionInfoResponse {
        session_id: session.id,
        subject: session.subject,
        role: session.role.to_string(),
        expires_in_secs: expires_in,
    }))
}

pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    let iam = state.iam_state.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "IAM is disabled".to_string(),
            }),
        )
    })?;
    if let Some(session_id) = extract_session_cookie(&headers, iam.session_cookie_name()) {
        iam.remove_session(&session_id);
    }
    let cookie = iam.expire_cookie_header().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;
    let mut response = (
        StatusCode::OK,
        Json(serde_json::json!({ "message": "logged out" })),
    )
        .into_response();
    response.headers_mut().append(header::SET_COOKIE, cookie);
    Ok(response)
}

pub async fn scim_status(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let iam = state.iam_state.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "IAM is disabled".to_string(),
            }),
        )
    })?;
    let status = iam.scim_status.read().await;
    Ok(Json(serde_json::json!({
        "scim_enabled": iam.config.scim.enabled,
        "sync_interval_secs": iam.config.scim.sync_interval_secs,
        "last_sync": status.last_sync.map(|ts| ts.to_rfc3339()),
        "last_sync_duration_ms": status.last_sync_duration_ms,
        "last_user_count": status.last_user_count,
        "last_error": status.last_error.clone(),
    })))
}

pub async fn saml_placeholder() -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(serde_json::json!({
            "error": "SAML SP support is coming soon"
        })),
    )
        .into_response()
}

#[derive(Clone, Debug)]
struct FlowState {
    next: String,
    code_verifier: String,
    nonce: String,
    expires_at: Instant,
}

impl FlowState {
    fn new(next: String, code_verifier: String, nonce: String) -> Self {
        Self {
            next,
            code_verifier,
            nonce,
            expires_at: Instant::now() + Duration::from_secs(FLOW_TTL_SECS),
        }
    }

    fn is_expired_at(&self, at: Instant) -> bool {
        at >= self.expires_at
    }
}

#[derive(Clone, Debug)]
pub struct IamSession {
    pub id: String,
    pub subject: Option<String>,
    pub role: Role,
    pub scopes: Vec<String>,
    expires_at: Instant,
}

impl IamSession {
    fn is_expired_at(&self, at: Instant) -> bool {
        at >= self.expires_at
    }

    fn expires_in_secs(&self) -> u64 {
        let now = Instant::now();
        if self.expires_at <= now {
            0
        } else {
            (self.expires_at - now).as_secs()
        }
    }
}

#[derive(Debug)]
struct CachedJwks {
    keys: Arc<JwkSet>,
    fetched_at: Instant,
}

#[derive(Debug)]
struct OidcDiscovery {
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

impl OidcDiscovery {
    async fn fetch(config: &VellavetoOidcConfig, allow_insecure: bool) -> Result<Self, String> {
        let issuer = config
            .issuer_url
            .as_ref()
            .ok_or_else(|| "issuer_url missing".to_string())?;
        let mut issuer_url = Url::parse(issuer).map_err(|e| e.to_string())?;
        if !allow_insecure && issuer_url.scheme() != "https" {
            return Err("OIDC issuer must use https".to_string());
        }
        issuer_url.set_path("/.well-known/openid-configuration");
        let client = Client::new();
        let response = client
            .get(issuer_url.as_str())
            .send()
            .await
            .map_err(|e| e.to_string())?
            .error_for_status()
            .map_err(|e| e.to_string())?;
        let metadata: OidcDiscoveryMetadata = response.json().await.map_err(|e| e.to_string())?;
        Ok(Self {
            authorization_endpoint: metadata.authorization_endpoint,
            token_endpoint: metadata.token_endpoint,
            jwks_uri: metadata.jwks_uri,
        })
    }
}

#[derive(Deserialize)]
struct OidcDiscoveryMetadata {
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

#[derive(Error, Debug)]
pub enum IamError {
    #[error("IAM is disabled")]
    Disabled,
    #[error("OIDC is disabled")]
    OidcDisabled,
    #[error("OIDC discovery failed: {0}")]
    Discovery(String),
    #[error("HTTP client error: {0}")]
    Client(String),
    #[error("Token exchange failed: {0}")]
    TokenExchange(String),
    #[error("Invalid ID token: {0}")]
    InvalidToken(String),
    #[error("Missing or expired login state")]
    MissingFlow,
    #[error("Nonce mismatch")]
    NonceMismatch,
    #[error("JWKS key error: {0}")]
    Jwks(String),
    #[error("Failed to encode cookie: {0}")]
    CookieEncode(String),
    #[error("SCIM sync failed: {0}")]
    Scim(String),
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
    scope: Option<String>,
}

fn generate_code_verifier() -> String {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

fn pkce_code_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

fn sanitize_next(value: Option<String>) -> String {
    let default = "/".to_string();
    let value = value.unwrap_or_else(|| default.clone());
    if value.len() > MAX_NEXT_LEN || value.contains("://") || has_dangerous_chars(&value) {
        return default;
    }
    if !value.starts_with('/') {
        let mut normalized = String::from("/");
        normalized.push_str(&value);
        normalized
    } else {
        value
    }
}

fn parse_scope_list(scope: Option<&str>) -> Vec<String> {
    scope
        .map(|s| {
            s.split_whitespace()
                .map(|scope| scope.to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn resolve_scim_token(config: &ScimConfig) -> Result<String, IamError> {
    if let Some(token) = &config.bearer_token {
        return Ok(token.clone());
    }
    if let Some(env_var) = &config.bearer_token_env {
        return env::var(env_var).map_err(|e| {
            IamError::Scim(format!(
                "Failed to read iam.scim.bearer_token_env '{}': {}",
                env_var, e
            ))
        });
    }
    Err(IamError::Scim(
        "iam.scim.bearer_token or iam.scim.bearer_token_env is required".to_string(),
    ))
}

fn spawn_scim_sync(
    client: Client,
    endpoint: String,
    token: String,
    interval_secs: u64,
    status: Arc<RwLock<ScimStatus>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let period = Duration::from_secs(interval_secs);
        loop {
            let sync_start = Instant::now();
            let now = Utc::now();
            let sync_result = fetch_scim_user_count(&client, &endpoint, &token).await;
            let duration_ms = sync_start.elapsed().as_millis();
            match &sync_result {
                Ok(count) => info!(
                    target: "iam",
                    endpoint = endpoint.as_str(),
                    count = count,
                    "SCIM sync recorded users"
                ),
                Err(err) => warn!(
                    target: "iam",
                    endpoint = endpoint.as_str(),
                    err = err,
                    "SCIM sync failed"
                ),
            }
            {
                let mut guard = status.write().await;
                guard.last_sync = Some(now);
                guard.last_sync_duration_ms = Some(duration_ms);
                match sync_result {
                    Ok(count) => {
                        guard.last_user_count = Some(count);
                        guard.last_error = None;
                    }
                    Err(err) => {
                        guard.last_error = Some(err);
                    }
                }
            }
            sleep(period).await;
        }
    })
}

async fn fetch_scim_user_count(
    client: &Client,
    endpoint: &str,
    token: &str,
) -> Result<usize, String> {
    let response = client
        .get(endpoint)
        .header(reqwest_header::AUTHORIZATION, format!("Bearer {}", token))
        .header(
            reqwest_header::ACCEPT,
            "application/scim+json, application/json",
        )
        .send()
        .await
        .map_err(|e| format!("SCIM request failed: {}", e))?
        .error_for_status()
        .map_err(|e| format!("SCIM endpoint error: {}", e))?;
    let payload = response
        .json::<Value>()
        .await
        .map_err(|e| format!("SCIM response decode failed: {}", e))?;
    Ok(extract_scim_user_count(&payload))
}

fn extract_scim_user_count(payload: &Value) -> usize {
    payload
        .get("totalResults")
        .and_then(|value| value_to_usize(value))
        .or_else(|| payload.get("total").and_then(|value| value_to_usize(value)))
        .or_else(|| {
            payload
                .get("Resources")
                .and_then(|value| value.as_array().map(|arr| arr.len()))
        })
        .or_else(|| {
            payload
                .get("resources")
                .and_then(|value| value.as_array().map(|arr| arr.len()))
        })
        .unwrap_or_default()
}

fn value_to_usize(value: &Value) -> Option<usize> {
    value.as_u64().map(|num| num as usize).or_else(|| {
        value
            .as_str()
            .and_then(|text| text.parse::<u64>().ok())
            .map(|num| num as usize)
    })
}

fn find_key_in_jwks(jwks: &JwkSet, kid: &str, alg: &Algorithm) -> Option<DecodingKey> {
    for key in &jwks.keys {
        if !kid.is_empty() {
            match &key.common.key_id {
                Some(key_kid) if key_kid == kid => {}
                _ => continue,
            }
        }
        if let Some(ref key_alg) = key.common.key_algorithm {
            if key_algorithm_to_algorithm(key_alg).as_ref() != Some(alg) {
                continue;
            }
        }
        if let Ok(decoding_key) = DecodingKey::from_jwk(key) {
            return Some(decoding_key);
        }
    }
    None
}

fn key_algorithm_to_algorithm(ka: &KeyAlgorithm) -> Option<Algorithm> {
    match ka {
        KeyAlgorithm::HS256 => Some(Algorithm::HS256),
        KeyAlgorithm::HS384 => Some(Algorithm::HS384),
        KeyAlgorithm::HS512 => Some(Algorithm::HS512),
        KeyAlgorithm::ES256 => Some(Algorithm::ES256),
        KeyAlgorithm::ES384 => Some(Algorithm::ES384),
        KeyAlgorithm::RS256 => Some(Algorithm::RS256),
        KeyAlgorithm::RS384 => Some(Algorithm::RS384),
        KeyAlgorithm::RS512 => Some(Algorithm::RS512),
        KeyAlgorithm::PS256 => Some(Algorithm::PS256),
        KeyAlgorithm::PS384 => Some(Algorithm::PS384),
        KeyAlgorithm::PS512 => Some(Algorithm::PS512),
        KeyAlgorithm::EdDSA => Some(Algorithm::EdDSA),
        _ => None,
    }
}
