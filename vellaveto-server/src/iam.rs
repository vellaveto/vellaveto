use axum::{
    extract::{Form, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use flate2::read::{DeflateDecoder, ZlibDecoder};
use jsonwebtoken::{
    decode, decode_header,
    jwk::{JwkSet, KeyAlgorithm},
    Algorithm, DecodingKey, Validation,
};
use rand::rngs::OsRng;
use rand::RngCore;
use reqwest::{header as reqwest_header, Client};
use ring::{digest, signature};
use roxmltree::{Document, Node, NodeType};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
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
use x509_parser::prelude::*;

use crate::rbac::{AudienceClaim, Role, RoleClaims};
use crate::routes::ErrorResponse;
use crate::AppState;
use vellaveto_config::{
    iam::{OidcConfig as VellavetoOidcConfig, SamlConfig, ScimConfig},
    IamConfig,
};

const FLOW_TTL_SECS: u64 = 300;
const MAX_NEXT_LEN: usize = 512;
const SAML_PROTOCOL_NS: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const SAML_METADATA_NS: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
const SAML_ASSERTION_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const XMLDSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
const SAML_STATUS_SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";

#[derive(Debug, Default)]
struct ScimStatus {
    last_sync: Option<DateTime<Utc>>,
    last_error: Option<String>,
    last_user_count: Option<usize>,
    last_sync_duration_ms: Option<u128>,
}

#[derive(Debug)]
struct SamlState {
    entity_id: String,
    acs_url: String,
    idp_entity_id: String,
    certificates: Vec<Vec<u8>>,
    role_attribute: String,
}

impl SamlState {
    async fn new(config: &SamlConfig, client: &Client) -> Result<Self, IamError> {
        let metadata_url = config
            .idp_metadata_url
            .as_ref()
            .ok_or_else(|| IamError::Saml("iam.saml.idp_metadata_url is required".to_string()))?;
        let body = client
            .get(metadata_url)
            .send()
            .await
            .map_err(|e| IamError::Saml(format!("Failed to fetch SAML metadata: {}", e)))?
            .error_for_status()
            .map_err(|e| IamError::Saml(format!("Failed to fetch SAML metadata: {}", e)))?
            .text()
            .await
            .map_err(|e| IamError::Saml(format!("Failed to read SAML metadata: {}", e)))?;
        let document = Document::parse(&body)
            .map_err(|e| IamError::Saml(format!("Invalid SAML metadata XML: {}", e)))?;
        Self::from_document(document, config)
    }

    fn from_document(document: Document, config: &SamlConfig) -> Result<Self, IamError> {
        let entity_node = document
            .descendants()
            .find(|node| node.has_tag_name((SAML_METADATA_NS, "EntityDescriptor")))
            .ok_or_else(|| IamError::Saml("SAML metadata missing EntityDescriptor".to_string()))?;
        let idp_entity_id = entity_node
            .attribute("entityID")
            .ok_or_else(|| IamError::Saml("EntityDescriptor missing entityID".to_string()))?
            .to_string();
        let sso_location = document
            .descendants()
            .filter(|node| node.has_tag_name((SAML_METADATA_NS, "SingleSignOnService")))
            .find(|node| {
                matches!(
                    node.attribute("Binding"),
                    Some("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
                )
            })
            .or_else(|| {
                document
                    .descendants()
                    .find(|node| node.has_tag_name((SAML_METADATA_NS, "SingleSignOnService")))
            })
            .and_then(|node| node.attribute("Location"));
        sso_location.ok_or_else(|| {
            IamError::Saml("SAML metadata missing SingleSignOnService or Location".to_string())
        })?;
        let mut certificates = Vec::new();
        for node in document
            .descendants()
            .filter(|node| node.has_tag_name((XMLDSIG_NS, "X509Certificate")))
        {
            if let Some(text) = node.text() {
                certificates.push(decode_base64(text.trim(), "SAML metadata certificate")?);
            }
        }
        if certificates.is_empty() {
            return Err(IamError::Saml(
                "SAML metadata includes no signing certificates".to_string(),
            ));
        }
        let entity_id = config
            .entity_id
            .clone()
            .ok_or_else(|| IamError::Saml("iam.saml.entity_id must be configured".to_string()))?;
        let acs_url = config
            .acs_url
            .clone()
            .ok_or_else(|| IamError::Saml("iam.saml.acs_url must be configured".to_string()))?;
        let role_attribute = config
            .role_attribute
            .clone()
            .unwrap_or_else(|| "Role".to_string());
        Ok(Self {
            entity_id,
            acs_url,
            idp_entity_id,
            certificates,
            role_attribute,
        })
    }
}

impl SamlState {
    fn extract_claims(&self, document: &Document) -> Result<RoleClaims, IamError> {
        let response = document
            .descendants()
            .find(|node| node.has_tag_name((SAML_PROTOCOL_NS, "Response")))
            .ok_or_else(|| IamError::Saml("SAML Response element missing".to_string()))?;
        self.ensure_status_success(response)?;
        self.ensure_destination(response)?;
        let assertion = response
            .descendants()
            .find(|node| node.has_tag_name((SAML_ASSERTION_NS, "Assertion")))
            .ok_or_else(|| IamError::Saml("SAML Assertion element missing".to_string()))?;
        self.verify_assertion(assertion)?;
        self.ensure_issuer(response, assertion)?;
        self.ensure_conditions(assertion)?;
        self.ensure_audience(assertion)?;
        Ok(self.claims_from_assertion(assertion))
    }

    fn ensure_status_success(&self, response: Node) -> Result<(), IamError> {
        let status_value = response
            .descendants()
            .find(|node| node.has_tag_name((SAML_PROTOCOL_NS, "StatusCode")))
            .and_then(|node| node.attribute("Value"))
            .ok_or_else(|| IamError::Saml("SAML StatusCode missing".to_string()))?;
        if status_value != SAML_STATUS_SUCCESS {
            return Err(IamError::Saml(format!(
                "SAML response status is not Success: {}",
                status_value
            )));
        }
        Ok(())
    }

    fn ensure_destination(&self, response: Node) -> Result<(), IamError> {
        if let Some(destination) = response.attribute("Destination") {
            if destination != self.acs_url {
                return Err(IamError::Saml(format!(
                    "SAML response destination {} does not match ACS {}",
                    destination, self.acs_url
                )));
            }
        }
        Ok(())
    }

    fn ensure_issuer(&self, response: Node, assertion: Node) -> Result<(), IamError> {
        let issuer = response
            .descendants()
            .find(|node| node.has_tag_name((SAML_ASSERTION_NS, "Issuer")))
            .or_else(|| {
                assertion
                    .descendants()
                    .find(|node| node.has_tag_name((SAML_ASSERTION_NS, "Issuer")))
            })
            .and_then(|node| node.text())
            .ok_or_else(|| IamError::Saml("SAML issuer missing".to_string()))?;
        if issuer != self.idp_entity_id {
            return Err(IamError::Saml(format!(
                "SAML issuer mismatch (expected {}, got {})",
                self.idp_entity_id, issuer
            )));
        }
        Ok(())
    }

    fn ensure_conditions(&self, assertion: Node) -> Result<(), IamError> {
        if let Some(conditions) = assertion
            .descendants()
            .find(|node| node.has_tag_name((SAML_ASSERTION_NS, "Conditions")))
        {
            let now = Utc::now();
            if let Some(not_before) = conditions.attribute("NotBefore") {
                let timestamp = parse_saml_timestamp(not_before)?;
                if now < timestamp {
                    return Err(IamError::Saml(
                        "SAML Conditions NotBefore is in the future".to_string(),
                    ));
                }
            }
            if let Some(not_on_or_after) = conditions.attribute("NotOnOrAfter") {
                let timestamp = parse_saml_timestamp(not_on_or_after)?;
                if now >= timestamp {
                    return Err(IamError::Saml(
                        "SAML Conditions NotOnOrAfter has passed".to_string(),
                    ));
                }
            }
        }
        Ok(())
    }

    fn ensure_audience(&self, assertion: Node) -> Result<(), IamError> {
        let audience_found = assertion
            .descendants()
            .filter(|node| node.has_tag_name((SAML_ASSERTION_NS, "Audience")))
            .filter_map(|node| node.text())
            .any(|value| value == self.entity_id);
        if !audience_found {
            return Err(IamError::Saml(format!(
                "SAML AudienceRestriction does not include {}",
                self.entity_id
            )));
        }
        Ok(())
    }

    fn claims_from_assertion(&self, assertion: Node) -> RoleClaims {
        let subject = assertion
            .descendants()
            .find(|node| node.has_tag_name((SAML_ASSERTION_NS, "NameID")))
            .and_then(|node| node.text())
            .map(|text| text.to_string());
        let mut roles = Vec::new();
        for attribute in assertion
            .descendants()
            .filter(|node| node.has_tag_name((SAML_ASSERTION_NS, "Attribute")))
        {
            if attribute
                .attribute("Name")
                .map(|name| name == self.role_attribute)
                .unwrap_or(false)
            {
                for value_node in attribute
                    .descendants()
                    .filter(|node| node.has_tag_name((SAML_ASSERTION_NS, "AttributeValue")))
                {
                    if let Some(value) = value_node.text() {
                        roles.push(value.to_string());
                    }
                }
            }
        }
        RoleClaims {
            sub: subject,
            role: roles.first().cloned(),
            vellaveto_role: None,
            roles: if roles.is_empty() { None } else { Some(roles) },
            aud: Some(AudienceClaim::Single(self.entity_id.clone())),
            nonce: None,
        }
    }

    fn verify_assertion(&self, assertion: Node) -> Result<(), IamError> {
        let signature = assertion
            .children()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "Signature")))
            .ok_or_else(|| IamError::Saml("SAML Assertion missing Signature".to_string()))?;
        let signed_info = signature
            .children()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "SignedInfo")))
            .ok_or_else(|| IamError::Saml("SAML SignedInfo missing".to_string()))?;
        let reference = signed_info
            .children()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "Reference")))
            .ok_or_else(|| IamError::Saml("SAML Reference missing".to_string()))?;
        let digest_method = reference
            .children()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "DigestMethod")))
            .and_then(|node| node.attribute("Algorithm"))
            .ok_or_else(|| IamError::Saml("DigestMethod algorithm missing".to_string()))?;
        let digest_algorithm = map_digest_algorithm(digest_method)?;
        let digest_value = reference
            .children()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "DigestValue")))
            .and_then(|node| node.text())
            .ok_or_else(|| IamError::Saml("DigestValue missing".to_string()))?;
        let digest_bytes = decode_base64(digest_value.trim(), "C14n digest value")?;
        let canonical_assertion = canonicalize_node(assertion, true);
        let computed = digest::digest(digest_algorithm, canonical_assertion.as_bytes());
        if computed.as_ref() != digest_bytes.as_slice() {
            return Err(IamError::Saml(
                "SAML assertion digest does not match".to_string(),
            ));
        }
        let signature_method = signed_info
            .children()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "SignatureMethod")))
            .and_then(|node| node.attribute("Algorithm"))
            .ok_or_else(|| IamError::Saml("SignatureMethod algorithm missing".to_string()))?;
        let signature_alg = map_signature_algorithm(signature_method)?;
        let signature_value = signature
            .children()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "SignatureValue")))
            .and_then(|node| node.text())
            .ok_or_else(|| IamError::Saml("SignatureValue missing".to_string()))?;
        let signature_bytes = decode_base64(signature_value.trim(), "Signature value")?;
        let canonical_signed_info = canonicalize_node(signed_info, false);
        for cert in &self.certificates {
            let (_, parsed) = X509Certificate::from_der(cert)
                .map_err(|e| IamError::Saml(format!("Invalid metadata certificate: {}", e)))?;
            let spki = parsed.tbs_certificate.subject_pki;
            let verifier =
                signature::UnparsedPublicKey::new(signature_alg, spki.subject_public_key.data);
            if verifier
                .verify(canonical_signed_info.as_bytes(), signature_bytes.as_slice())
                .is_ok()
            {
                return Ok(());
            }
        }
        Err(IamError::Saml(
            "SAML signature verification failed".to_string(),
        ))
    }
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
    _scim_task: Option<JoinHandle<()>>,
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
            _scim_task: scim_task,
        })
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(config: IamConfig) -> Self {
        let discovery = OidcDiscovery {
            authorization_endpoint: "https://example.com/authorize".to_string(),
            token_endpoint: "https://example.com/token".to_string(),
            jwks_uri: "https://example.com/jwks".to_string(),
        };
        let http = Client::new();
        IamState {
            config,
            discovery,
            http,
            flow_states: DashMap::new(),
            sessions: DashMap::new(),
            jwks_cache: RwLock::new(None),
            saml_state: None,
            scim_status: Arc::new(RwLock::new(ScimStatus::default())),
            _scim_task: None,
        }
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
            last_activity: now,
        };
        self.sessions.insert(session.id.clone(), session.clone());
        self.trim_sessions_for_subject(session.subject.as_deref());
        session
    }

    fn trim_sessions_for_subject(&self, subject: Option<&str>) {
        let subject = match subject {
            Some(value) => value,
            None => return,
        };
        let limit = self.config.session.max_sessions_per_principal as usize;
        if limit == 0 {
            return;
        }
        let mut entries: Vec<(Instant, String)> = self
            .sessions
            .iter()
            .filter_map(|entry| {
                let value = entry.value();
                value
                    .subject
                    .as_deref()
                    .filter(|s| *s == subject)
                    .map(|_| (value.last_activity, entry.key().clone()))
            })
            .collect();
        if entries.len() <= limit {
            return;
        }
        entries.sort_by_key(|(activity, _)| *activity);
        let remove_count = entries.len() - limit;
        for (_, id) in entries.into_iter().take(remove_count) {
            self.sessions.remove(&id);
        }
    }

    pub fn find_session(&self, id: &str) -> Option<IamSession> {
        let now = Instant::now();
        let idle_timeout = Duration::from_secs(self.config.session.idle_timeout_secs);
        if let Some(mut entry) = self.sessions.get_mut(id) {
            if entry.is_expired_at(now, idle_timeout) {
                let key = entry.key().clone();
                drop(entry);
                self.sessions.remove(&key);
                return None;
            }
            entry.touch();
            return Some(entry.clone());
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

#[derive(Deserialize)]
pub struct SamlAcsForm {
    #[serde(rename = "SAMLResponse")]
    pub saml_response: String,

    #[serde(rename = "RelayState")]
    pub relay_state: Option<String>,
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

pub async fn saml_acs(
    State(state): State<AppState>,
    Form(form): Form<SamlAcsForm>,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    let iam = state.iam_state.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "IAM is disabled".to_string(),
            }),
        )
    })?;
    let saml_state = iam.saml_state.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "SAML is disabled".to_string(),
            }),
        )
    })?;
    let xml = decode_saml_response(&form.saml_response).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;
    let document = Document::parse(&xml).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Invalid SAML XML: {}", e),
            }),
        )
    })?;
    let claims = saml_state.extract_claims(&document).map_err(|e| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;
    let session = iam.create_session(claims, vec![]);
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
    let next = sanitize_next(form.relay_state.clone());
    let mut response = Redirect::temporary(&next).into_response();
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

pub async fn saml_metadata(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let iam = state.iam_state.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "IAM is disabled".to_string(),
            }),
        )
    })?;
    if !iam.config.saml.enabled {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "SAML metadata is disabled".to_string(),
            }),
        ));
    }
    let metadata = build_saml_metadata(&iam.config.saml);
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/samlmetadata+xml")],
        metadata,
    ))
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
    last_activity: Instant,
}

impl IamSession {
    fn is_expired_at(&self, now: Instant, idle_timeout: Duration) -> bool {
        now >= self.expires_at || now.duration_since(self.last_activity) >= idle_timeout
    }

    fn touch(&mut self) {
        self.last_activity = Instant::now();
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
    #[error("SAML error: {0}")]
    Saml(String),
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

fn canonicalize_node(node: Node, skip_signature: bool) -> String {
    let mut output = String::new();
    output.push('<');
    output.push_str(&qualified_name(node));
    let mut attrs: Vec<_> = node.attributes().collect();
    attrs.sort_by(|a: &roxmltree::Attribute, b: &roxmltree::Attribute| {
        a.namespace()
            .unwrap_or("")
            .cmp(b.namespace().unwrap_or(""))
            .then_with(|| a.name().cmp(b.name()))
    });
    for attr in &attrs {
        output.push(' ');
        output.push_str(&attribute_name(attr));
        output.push('=');
        output.push('"');
        output.push_str(attr.value());
        output.push('"');
    }
    output.push('>');
    for child in node.children() {
        match child.node_type() {
            NodeType::Text => {
                if let Some(text) = child.text() {
                    output.push_str(text);
                }
            }
            NodeType::Element => {
                let is_signature = child.has_tag_name((XMLDSIG_NS, "Signature"))
                    || child.tag_name().name() == "Signature";
                if skip_signature && is_signature {
                    continue;
                }
                output.push_str(&canonicalize_node(child, skip_signature));
            }
            _ => {}
        }
    }
    output.push_str("</");
    output.push_str(&qualified_name(node));
    output.push('>');
    output
}

fn qualified_name(node: Node) -> String {
    if let Some(ns) = node.tag_name().namespace() {
        if let Some(prefix) = node.lookup_prefix(ns) {
            return format!("{}:{}", prefix, node.tag_name().name());
        }
    }
    node.tag_name().name().to_string()
}

fn attribute_name(attr: &roxmltree::Attribute) -> String {
    // roxmltree 0.21 does not expose attribute prefix directly;
    // for SAML canonicalization we use the local name only (sufficient
    // for namespace-unqualified attributes in SAML assertions).
    attr.name().to_string()
}

fn map_digest_algorithm(uri: &str) -> Result<&'static digest::Algorithm, IamError> {
    match uri {
        "http://www.w3.org/2000/09/xmldsig#sha1" => Ok(&digest::SHA1_FOR_LEGACY_USE_ONLY),
        "http://www.w3.org/2001/04/xmlenc#sha256" => Ok(&digest::SHA256),
        "http://www.w3.org/2001/04/xmlenc#sha384" => Ok(&digest::SHA384),
        "http://www.w3.org/2001/04/xmlenc#sha512" => Ok(&digest::SHA512),
        _ => Err(IamError::Saml(format!(
            "Unsupported SAML digest algorithm {}",
            uri
        ))),
    }
}

fn map_signature_algorithm(
    uri: &str,
) -> Result<&'static dyn signature::VerificationAlgorithm, IamError> {
    match uri {
        "http://www.w3.org/2000/09/xmldsig#rsa-sha1" => {
            Ok(&signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY)
        }
        "http://www.w3.org/2000/09/xmldsig#rsa-sha256"
        | "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => {
            Ok(&signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY)
        }
        "http://www.w3.org/2000/09/xmldsig#rsa-sha512"
        | "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" => {
            Ok(&signature::RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY)
        }
        _ => Err(IamError::Saml(format!(
            "Unsupported SAML signature algorithm {}",
            uri
        ))),
    }
}

fn parse_saml_timestamp(value: &str) -> Result<DateTime<Utc>, IamError> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| IamError::Saml(format!("Invalid SAML timestamp '{}': {}", value, e)))
}

fn decode_base64(value: &str, context: &str) -> Result<Vec<u8>, IamError> {
    STANDARD
        .decode(value)
        .map_err(|e| IamError::Saml(format!("{}: {}", context, e)))
}

fn decode_saml_response(encoded: &str) -> Result<String, IamError> {
    let decoded = STANDARD
        .decode(encoded)
        .map_err(|e| IamError::Saml(format!("Invalid SAML response encoding: {}", e)))?;
    if let Ok(text) = String::from_utf8(decoded.clone()) {
        return Ok(text);
    }
    let mut buffer = String::new();
    let mut zlib_decoder = ZlibDecoder::new(Cursor::new(decoded.clone()));
    if zlib_decoder.read_to_string(&mut buffer).is_ok() {
        return Ok(buffer);
    }
    buffer.clear();
    let mut deflate_decoder = DeflateDecoder::new(Cursor::new(decoded));
    deflate_decoder
        .read_to_string(&mut buffer)
        .map_err(|e| IamError::Saml(format!("Failed to decompress SAML response: {}", e)))?;
    Ok(buffer)
}

const SAML_SP_METADATA_TEMPLATE: &str = r#"<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity}">
  <SPSSODescriptor
    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
    AuthnRequestsSigned="false"
    WantAssertionsSigned="true">
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <AssertionConsumerService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      Location="{acs}"
      index="0"/>
  </SPSSODescriptor>
</EntityDescriptor>"#;

fn build_saml_metadata(config: &SamlConfig) -> String {
    SAML_SP_METADATA_TEMPLATE
        .replace("{entity}", config.entity_id.as_deref().unwrap_or_default())
        .replace("{acs}", config.acs_url.as_deref().unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use chrono::{Duration, Utc};
    use flate2::write::DeflateEncoder;
    use flate2::Compression;
    use ring::digest;
    use ring::rand::SystemRandom;
    use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};
    use std::io::Write;
    use std::time::{Duration as StdDuration, Instant as StdInstant};
    use vellaveto_config::iam::SamlConfig;
    use vellaveto_config::IamConfig;

    const TEST_CERT_BASE64: &str = "MIIDDTCCAfWgAwIBAgIUXFfuq4zQ2fx8g6c6OmSBI/yIhmYwDQYJKoZIhvcNAQELBQAwFjEUMBIGA1UEAwwLcGhhc2U0Ni1pZHAwHhcNMjYwMjI1MjI0MzQ1WhcNMjcwMjI1MjI0MzQ1WjAWMRQwEgYDVQQDDAtwaGFzZTQ2LWlkcDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALqJvn8K/WDkH3pjGevAAatWwodmNJqy7jUHTG/OzRBN8vjBLYN7Xdl1NGtjsVSJL4aUbam41CP++xn+NcwpZ0LHDBhyRmyV+Bl26PE4s3/0+UyJUl08PMkLugoDxmduJ2PbjIbBSGoMfYV7HsueMJjpWZt3btY90QCU3SH9jkylz424GHhziYsIqdfIDNxiO91rjojl/caWcLFjSH4l7Ve6v5nubzmPcpueL1pEGbXW+qXc7vZ6N/urC0j8KTX8KTxV9GQ61KatzoNjlHevhrW2gntPos8CRJd2hAUUovHG0ExZhmpMpPzz0J8iLxI7YXvwrPgm7r4a9rG8SXLvxB0CAwEAAaNTMFEwHQYDVR0OBBYEFJQs00ep7Zq0sY62RHT8X0izPzg7MB8GA1UdIwQYMBaAFJQs00ep7Zq0sY62RHT8X0izPzg7MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAJ3sXJJX3yqxsR2lzKFsGrsD2c/ih3GotqaNtkwC9GHiE0Sz9cYXZLIFXArISfEBTLyNn6WX5ZO+a0CeIKSLgSTAYYjwUkIB9OFTwzh5wDTCc5yXexJoN4oR1lqsxYtQ61to6PbIGXUJmFYtaJS96Wj0AXneNVZoItAvTPMKstCnYZOZ/vwT3t8tbRUM1JRtfkRYplroy0H3dKt3l31LD6NB4ergCOJHhqVbss+r8mZzNnhN222VIdQ2qjVq8kxmYJTO/itL8w2DVpufwwFFiWkinBOd2FeAwST7v4n+voeUIXj9zWnd6NiuVE8hymsu995U5xGrBuVGrweSoEelwoY=";
    const TEST_PRIVATE_KEY_BASE64: &str = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC6ib5/Cv1g5B96YxnrwAGrVsKHZjSasu41B0xvzs0QTfL4wS2De13ZdTRrY7FUiS+GlG2puNQj/vsZ/jXMKWdCxwwYckZslfgZdujxOLN/9PlMiVJdPDzJC7oKA8Znbidj24yGwUhqDH2Fex7LnjCY6Vmbd27WPdEAlN0h/Y5Mpc+NuBh4c4mLCKnXyAzcYjvda46I5f3GlnCxY0h+Je1Xur+Z7m85j3Kbni9aRBm11vql3O72ejf7qwtI/Ck1/Ck8VfRkOtSmrc6DY5R3r4a1toJ7T6LPAkSXdoQFFKLxxtBMWYZqTKT889CfIi8SO2F78Kz4Ju6+GvaxvEly78QdAgMBAAECggEAFXXscdRIrgGAx5qoLEcU9L/mCyAh6YcFaxoRsVlS8/nBJtz0CLOZlVTrziEUO+a5ONv8Y9ws9+PewrD27Sv5l9AA9Ge38h0s2SJ6OT+t6F49jOXNkTFxctXZC6GUjWi5umjTWYYvd8KZHFFmYRmsJfjOw4PxlKSxq3Cfokiiuu7e50rrAIU7wAg99drbfCGluYctc8FlayAO3tG+aweIOQjun6QbiSkLRwyFz5KCGqsHHTND1J0GF0/pqSKXUEJ+qMeUo+SnfdAPW+4/Xwlp5mR2eO+ffS14dIv7O+QMj+t3jk5SYChDw2JtZlwppCBdfs9368+s4lrdQfAjgi2CFwKBgQDnlex/juB+PQ27J2QF56EpVaj9s3tM77cbyS4mXGqA5tXEH3K47yWbISdTKG4ubRjic+JMsp8qKyx+qqQVHmxkDrLsE2NmFdMEXiktWnZwbXH2x2mHEx9O2IwK8jdJVInE/kJNZVtZtV4v82HZi+A4L1ZOI6lYBg56lDGyLpsvNwKBgQDONBFlCjqsGkl6LQ4tQWSYTgsRQeylSffc5Jw9lENRTfrXuqb5OE1uSe9tJeycVO7QKuGddv/f7UZoru1drc3zxm2004RDJBzcrDoxyXZrbRDvorFZEMPJXOmneY0zLjMnQY4NVXUUZp3hPtP0Bk1YDtC/50wZ7HPUCx0zp7AJSwKBgQC8KuMomezqZa08fjsVWSlnroRK74Sl9LixSPvIi5q19dmHK45JmXbS31NWjClKa7ameUZMz23oE4BpwzjjN/8WJaNXkkFXdzAoAmIuyawmmabZvxmNeQodRHI1iq1FVf1DJNy2ij55W5aWG4lL/A1JWZ0kjHFSZklpa/QdNSU+bQKBgHV92YN25qN1fvRsg61pm0XlAg1dQNeVY/OrFxNHTWwgQJN3OPi8CfKTkibg+wbApipapJ8yVO1kpz+ynHFKPRVvtMbZ1nzjMMbUI3yGzEC9rm68hsy27rfnhwL0EW5eHqt5gNU8Ii/zoHXddKuQg7VvC6asxgHnZsAlbQgnvfgtAoGAGuW5KPZlvFJ24jLnmDrpAOjNEdfdlQ3fcY4Dq4pdy0JojyzOvWcrAvQQzH+oJk7JlVJTpzmKKBM9pckZ7pXbTIhoPn4BIvKwkr1rpZAF1bbUhb5+N6zU7AUp7x6GB/fIV8KHzX3UReUuJfSobzSS6KrWkNTqnl7Gl9JpzsirwqU=";
    const TEST_IDP_ENTITY_ID: &str = "https://idp.example.com";
    const TEST_SSO_URL: &str = "https://idp.example.com/sso";
    const TEST_SP_ENTITY_ID: &str = "https://sp.example.com";
    const TEST_SP_ACS: &str = "https://sp.example.com/acs";
    const TEST_SUBJECT: &str = "alice@example.com";
    const TEST_ROLE_VALUE: &str = "Admin";
    const SIGNED_INFO_TEMPLATE: &str = r#"<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
  <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
  <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha256"/>
  <Reference URI="">
    <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
    <DigestValue>{digest}</DigestValue>
  </Reference>
</SignedInfo>"#;
    const ASSERTION_TEMPLATE: &str = r#"<Assertion Version="2.0" IssueInstant="{issue}" ID="_assertion" xmlns="urn:oasis:names:tc:SAML:2.0:assertion">
  <Issuer>{idp}</Issuer>
  <Subject>
    <NameID>{subject}</NameID>
  </Subject>
  <Conditions NotBefore="{not_before}" NotOnOrAfter="{not_on_or_after}">
    <AudienceRestriction>
      <Audience>{audience}</Audience>
    </AudienceRestriction>
  </Conditions>
  <AttributeStatement>
    <Attribute Name="{role_attr}">
      <AttributeValue>{role_value}</AttributeValue>
    </Attribute>
  </AttributeStatement>
  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    {signed_info}
    <SignatureValue>{signature}</SignatureValue>
  </Signature>
</Assertion>"#;
    const RESPONSE_TEMPLATE: &str = r#"<Response Version="2.0" IssueInstant="{issue}" Destination="{acs}" xmlns="urn:oasis:names:tc:SAML:2.0:protocol">
  <Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">{idp}</Issuer>
  <Status>
    <StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </Status>
  {assertion}
</Response>"#;
    const SAML_METADATA_TEMPLATE: &str = r#"<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{idp}">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{sso}"/>
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>{cert}</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
  </IDPSSODescriptor>
</EntityDescriptor>"#;
    const SIGNATURE_PLACEHOLDER: &str = "{signature}";

    #[test]
    fn canonicalize_node_filters_signature_when_requested() {
        let xml = r#"<root attr="value"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><dummy/></Signature><child id="1">text</child></root>"#;
        let doc = Document::parse(xml).unwrap();
        let root = doc.root_element();
        let canonical = canonicalize_node(root, true);
        assert!(canonical.contains("<child"));
        assert!(!canonical.contains("Signature"));
    }

    #[test]
    fn canonicalize_node_preserves_signature_when_not_skipped() {
        let xml = r#"<root><Signature><dummy/></Signature></root>"#;
        let doc = Document::parse(xml).unwrap();
        let root = doc.root_element();
        let canonical = canonicalize_node(root, false);
        assert!(canonical.contains("Signature"));
    }

    #[test]
    fn decode_saml_response_handles_plain_and_deflated() {
        let payload = "<Response></Response>";
        let plain = STANDARD.encode(payload);
        assert_eq!(decode_saml_response(&plain).unwrap(), payload);

        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(payload.as_bytes()).unwrap();
        let deflated = encoder.finish().unwrap();
        let encoded = STANDARD.encode(deflated);
        assert_eq!(decode_saml_response(&encoded).unwrap(), payload);
    }

    #[test]
    fn parse_saml_timestamp_accepts_and_rejects_values() {
        assert!(parse_saml_timestamp("2026-02-25T12:00:00Z").is_ok());
        assert!(parse_saml_timestamp("not-a-timestamp").is_err());
    }

    #[test]
    fn map_digest_algorithm_supports_known_uris() {
        let sha256 = map_digest_algorithm("http://www.w3.org/2001/04/xmlenc#sha256").unwrap();
        assert!(std::ptr::eq(sha256, &digest::SHA256));
        assert!(map_digest_algorithm("unsupported").is_err());
    }

    #[test]
    fn map_signature_algorithm_supports_known_uris() {
        assert!(map_signature_algorithm("http://www.w3.org/2000/09/xmldsig#rsa-sha256").is_ok());
        assert!(map_signature_algorithm("unsupported").is_err());
    }

    fn test_metadata_xml() -> String {
        SAML_METADATA_TEMPLATE
            .replace("{idp}", TEST_IDP_ENTITY_ID)
            .replace("{sso}", TEST_SSO_URL)
            .replace("{cert}", TEST_CERT_BASE64)
    }

    fn test_saml_config() -> SamlConfig {
        SamlConfig {
            enabled: true,
            entity_id: Some(TEST_SP_ENTITY_ID.to_string()),
            acs_url: Some(TEST_SP_ACS.to_string()),
            idp_metadata_url: Some("https://idp.example.com/metadata".to_string()),
            role_attribute: Some("Role".to_string()),
        }
    }

    fn private_key_pair() -> RsaKeyPair {
        let key_bytes = STANDARD.decode(TEST_PRIVATE_KEY_BASE64).unwrap();
        RsaKeyPair::from_pkcs8(&key_bytes).unwrap()
    }

    fn canonicalize_signed_info(xml: &str) -> String {
        let document = Document::parse(xml).unwrap();
        let root = document.root_element();
        canonicalize_node(root, false)
    }

    fn compute_assertion_digest(assertion_xml: &str) -> String {
        let document = Document::parse(assertion_xml).unwrap();
        let assertion_node = document
            .descendants()
            .find(|node| node.has_tag_name((SAML_ASSERTION_NS, "Assertion")))
            .unwrap();
        let canonical = canonicalize_node(assertion_node, true);
        let digest = digest::digest(&digest::SHA256, canonical.as_bytes());
        STANDARD.encode(digest.as_ref())
    }

    fn sign_canonicalized_signed_info(signed_info: &str) -> String {
        let key_pair = private_key_pair();
        let rng = SystemRandom::new();
        let canonical = canonicalize_signed_info(signed_info);
        let mut signature = vec![0; key_pair.public().modulus_len()];
        key_pair
            .sign(
                &RSA_PKCS1_SHA256,
                &rng,
                canonical.as_bytes(),
                &mut signature,
            )
            .unwrap();
        STANDARD.encode(signature)
    }

    fn build_signed_response(saml_state: &SamlState) -> String {
        let issue_instant = Utc::now().to_rfc3339();
        let not_before = (Utc::now() - Duration::seconds(30)).to_rfc3339();
        let not_on_or_after = (Utc::now() + Duration::minutes(5)).to_rfc3339();
        let assertion_template = ASSERTION_TEMPLATE
            .replace("{issue}", &issue_instant)
            .replace("{idp}", &saml_state.idp_entity_id)
            .replace("{subject}", TEST_SUBJECT)
            .replace("{not_before}", &not_before)
            .replace("{not_on_or_after}", &not_on_or_after)
            .replace("{audience}", &saml_state.entity_id)
            .replace("{role_attr}", &saml_state.role_attribute)
            .replace("{role_value}", TEST_ROLE_VALUE)
            .replace("{signed_info}", "{signed_info}")
            .replace("{signature}", SIGNATURE_PLACEHOLDER);
        let assertion_for_digest = assertion_template
            .replace("{signed_info}", SIGNED_INFO_TEMPLATE)
            .replace("{signature}", SIGNATURE_PLACEHOLDER);
        let digest_value = compute_assertion_digest(&assertion_for_digest);
        let signed_info = SIGNED_INFO_TEMPLATE.replace("{digest}", &digest_value);
        let signature_value = sign_canonicalized_signed_info(&signed_info);
        let final_assertion = assertion_template
            .replace("{signed_info}", &signed_info)
            .replace("{signature}", &signature_value);
        RESPONSE_TEMPLATE
            .replace("{issue}", &issue_instant)
            .replace("{acs}", &saml_state.acs_url)
            .replace("{idp}", &saml_state.idp_entity_id)
            .replace("{assertion}", &final_assertion)
    }

    #[test]
    fn saml_state_extracts_signed_response_claims() {
        let config = test_saml_config();
        let metadata_xml = test_metadata_xml();
        let document = Document::parse(&metadata_xml).unwrap();
        let saml_state = SamlState::from_document(document, &config).unwrap();
        let response = build_signed_response(&saml_state);
        let response_doc = Document::parse(&response).unwrap();
        let claims = saml_state.extract_claims(&response_doc).unwrap();
        assert_eq!(claims.sub.as_deref(), Some(TEST_SUBJECT));
        let roles = claims.roles.unwrap_or_default();
        assert!(roles.contains(&TEST_ROLE_VALUE.to_string()));
        assert_eq!(
            claims.aud,
            Some(AudienceClaim::Single(TEST_SP_ENTITY_ID.to_string()))
        );
    }

    #[test]
    fn build_saml_metadata_includes_entity_and_acs() {
        let config = test_saml_config();
        let metadata = build_saml_metadata(&config);
        assert!(metadata.contains(TEST_SP_ENTITY_ID));
        assert!(metadata.contains(TEST_SP_ACS));
        assert!(metadata.contains("AssertionConsumerService"));
    }

    #[test]
    fn ensure_destination_rejects_mismatched_values() {
        let config = test_saml_config();
        let metadata_xml = test_metadata_xml();
        let document = Document::parse(&metadata_xml).unwrap();
        let saml_state = SamlState::from_document(document, &config).unwrap();
        let xml = format!(
            "<Response xmlns=\"{}\" Destination=\"https://bad.example.com\"/>",
            SAML_PROTOCOL_NS
        );
        let response_doc = Document::parse(&xml).unwrap();
        let response = response_doc.root_element();
        assert!(matches!(
            saml_state.ensure_destination(response),
            Err(IamError::Saml(_))
        ));
    }

    fn role_claims(subject: &str, role: &str) -> RoleClaims {
        RoleClaims {
            sub: Some(subject.to_string()),
            role: Some(role.to_string()),
            vellaveto_role: None,
            roles: None,
            aud: None,
            nonce: None,
        }
    }

    #[test]
    fn session_expires_after_idle_timeout() {
        let mut config = IamConfig::default();
        config.oidc.enabled = true;
        config.session.idle_timeout_secs = 1;
        let iam = IamState::new_for_test(config);
        let session = iam.create_session(role_claims("alice", "admin"), vec![]);
        {
            let mut entry = iam.sessions.get_mut(&session.id).unwrap();
            entry.last_activity = StdInstant::now() - StdDuration::from_secs(2);
        }
        assert!(iam.find_session(&session.id).is_none());
    }

    #[test]
    fn create_session_prunes_oldest_when_limit_reached() {
        let mut config = IamConfig::default();
        config.oidc.enabled = true;
        config.session.max_sessions_per_principal = 2;
        let iam = IamState::new_for_test(config);
        let s1 = iam.create_session(role_claims("bob", "operator"), vec![]);
        let s2 = iam.create_session(role_claims("bob", "operator"), vec![]);
        let s3 = iam.create_session(role_claims("bob", "operator"), vec![]);
        assert!(iam.find_session(&s1.id).is_none());
        assert!(iam.find_session(&s2.id).is_some());
        assert!(iam.find_session(&s3.id).is_some());
    }
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
        .and_then(value_to_usize)
        .or_else(|| payload.get("total").and_then(value_to_usize))
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
