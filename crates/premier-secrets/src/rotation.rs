//! Signed dual-phase secret rotation (Iron Law of Revocation): `prepare` -> store the new
//! value -> `commit`, restoring the previous value and sending `rollback` on any failure.
//! Receipts never contain secret values.

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use http::Method;
use rand::RngCore;
use rustls::pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use url::Url;
use zeroize::Zeroizing;

use crate::SecretError;
use crate::backend::{SecretBackend, SecretCoord};
use crate::kms::{HttpRequest, HttpResponse, http_json_request};
use crate::schema::RotationSpec;

type HmacSha256 = Hmac<Sha256>;

/// `sha256=<hex HMAC-SHA256 of "{timestamp}.{body}">`.
pub fn sign_webhook_payload(
    secret: &[u8],
    timestamp: i64,
    body: &[u8],
) -> Result<String, SecretError> {
    if secret.is_empty() {
        return Err(SecretError::Crypto(
            "webhook signing secret must not be empty".to_owned(),
        ));
    }
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|_| SecretError::Crypto("invalid webhook signing secret".to_owned()))?;
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    Ok(format!(
        "sha256={}",
        hex::encode(mac.finalize().into_bytes())
    ))
}

/// Constant-time check of a `sha256=` signature (receivers should also bound timestamp skew).
pub fn verify_webhook_signature(
    secret: &[u8],
    timestamp: i64,
    body: &[u8],
    signature: &str,
) -> bool {
    sign_webhook_payload(secret, timestamp, body).is_ok_and(|expected| {
        expected
            .as_bytes()
            .ct_eq(signature.trim().as_bytes())
            .into()
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationPhase {
    Prepare,
    Commit,
    Rollback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationStatus {
    Committed,
    RolledBack,
    Failed,
    ManualRequired,
}

/// Audit record of one rotation attempt. Never holds secret values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationReceipt {
    pub id: String,
    pub var_name: String,
    pub env: String,
    pub provider: String,
    pub webhook_url: Option<String>,
    pub status: RotationStatus,
    /// Last phase dispatched to the webhook.
    pub phase_reached: RotationPhase,
    pub triggered_by_offboard: bool,
    pub actor: String,
    pub reason: String,
    pub timestamp: DateTime<Utc>,
    pub http_status: Option<u16>,
    /// A `rollback` webhook was acknowledged with 2xx.
    pub rollback_sent: bool,
    pub error: Option<String>,
}

#[derive(Serialize)]
struct WebhookPayload<'a> {
    phase: RotationPhase,
    rotation_id: &'a str,
    var_name: &'a str,
    env: &'a str,
    provider: &'a str,
    actor: &'a str,
    reason: &'a str,
    triggered_by_offboard: bool,
}

#[derive(Deserialize)]
struct PrepareResponse {
    #[serde(default)]
    new_value: Option<String>,
}

/// Sends signed rotation webhooks over verified TLS, refusing private/link-local IPs unless opted in.
#[derive(Debug, Clone, Default)]
pub struct RotationDispatcher {
    pub allow_insecure_loopback: bool,
    pub allow_private_webhooks: bool,
    pub allowed_hosts: Vec<String>,
    pub extra_root_certs: Vec<CertificateDer<'static>>,
}

impl RotationDispatcher {
    fn send(
        &self,
        spec: &RotationSpec,
        signing_secret: &[u8],
        receipt: &RotationReceipt,
        phase: RotationPhase,
    ) -> Result<HttpResponse, SecretError> {
        if !self.allowed_hosts.is_empty() {
            let parsed = Url::parse(&spec.webhook_url)
                .map_err(|e| SecretError::Backend(format!("invalid webhook URL: {e}")))?;
            let host = parsed
                .host_str()
                .unwrap_or_default()
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if !self.allowed_hosts.iter().any(|allowed| {
                allowed
                    .trim()
                    .trim_end_matches('.')
                    .eq_ignore_ascii_case(&host)
            }) {
                return Err(SecretError::Backend(format!(
                    "webhook host '{host}' is not in rotation allowed_hosts"
                )));
            }
        }
        let body = serde_json::to_vec(&WebhookPayload {
            phase,
            rotation_id: &receipt.id,
            var_name: &receipt.var_name,
            env: &receipt.env,
            provider: &receipt.provider,
            actor: &receipt.actor,
            reason: &receipt.reason,
            triggered_by_offboard: receipt.triggered_by_offboard,
        })
        .map_err(|e| SecretError::Backend(format!("encode webhook payload failed: {e}")))?;
        let timestamp = Utc::now().timestamp();
        let signature = sign_webhook_payload(signing_secret, timestamp, &body)?;
        http_json_request(HttpRequest {
            method: Method::POST,
            url: spec.webhook_url.clone(),
            headers: vec![
                ("X-Premier-Timestamp", Zeroizing::new(timestamp.to_string())),
                ("X-Premier-Signature-256", Zeroizing::new(signature)),
            ],
            body: Some(Zeroizing::new(body)),
            allow_insecure_loopback: self.allow_insecure_loopback,
            block_private_ips: !self.allow_private_webhooks,
            extra_root_certs: self.extra_root_certs.clone(),
        })
    }

    fn rollback(&self, spec: &RotationSpec, signing_secret: &[u8], receipt: &mut RotationReceipt) {
        receipt.phase_reached = RotationPhase::Rollback;
        receipt.rollback_sent = self
            .send(spec, signing_secret, receipt, RotationPhase::Rollback)
            .is_ok_and(|r| r.is_success());
    }

    fn abort(
        &self,
        spec: &RotationSpec,
        signing_secret: &[u8],
        mut receipt: RotationReceipt,
        status: RotationStatus,
        error: String,
    ) -> RotationReceipt {
        receipt.status = status;
        receipt.error = Some(error);
        self.rollback(spec, signing_secret, &mut receipt);
        receipt
    }

    /// Run `prepare` -> store -> `commit`. The new value comes from the `prepare` response's
    /// `new_value`, else `supplied_new_value`. A failed commit restores the previous value.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_dual_phase(
        &self,
        spec: &RotationSpec,
        signing_secret: &[u8],
        backend: &dyn SecretBackend,
        coord: &SecretCoord,
        actor: &str,
        reason: &str,
        triggered_by_offboard: bool,
        supplied_new_value: Option<&str>,
    ) -> RotationReceipt {
        let mut id = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut id);
        let mut receipt = RotationReceipt {
            id: hex::encode(id),
            var_name: coord.var_name.clone(),
            env: coord.scope.clone(),
            provider: spec
                .provider
                .clone()
                .unwrap_or_else(|| "webhook".to_owned()),
            webhook_url: Some(spec.webhook_url.clone()),
            status: RotationStatus::Failed,
            phase_reached: RotationPhase::Prepare,
            triggered_by_offboard,
            actor: actor.to_owned(),
            reason: reason.to_owned(),
            timestamp: Utc::now(),
            http_status: None,
            rollback_sent: false,
            error: None,
        };

        let previous = match backend.get(coord) {
            Ok(v) => v,
            Err(e) => {
                receipt.error = Some(format!("reading the current value failed: {e}"));
                return receipt;
            }
        };

        // Phase 1: prepare.
        let prepared = self.send(spec, signing_secret, &receipt, RotationPhase::Prepare);
        let new_value = match prepared {
            Ok(resp) if resp.is_success() => {
                receipt.http_status = Some(resp.status);
                let from_provider = serde_json::from_slice::<PrepareResponse>(&resp.body)
                    .ok()
                    .and_then(|r| r.new_value)
                    .map(Zeroizing::new)
                    .filter(|v| !v.is_empty());
                match from_provider
                    .or_else(|| supplied_new_value.map(|v| Zeroizing::new(v.to_owned())))
                {
                    Some(v) => v,
                    None => {
                        return self.abort(
                            spec,
                            signing_secret,
                            receipt,
                            RotationStatus::ManualRequired,
                            "prepare returned no new_value and none was supplied; rotate manually"
                                .to_owned(),
                        );
                    }
                }
            }
            Ok(resp) => {
                receipt.http_status = Some(resp.status);
                let error = format!("prepare phase failed with HTTP {}", resp.status);
                return self.abort(spec, signing_secret, receipt, RotationStatus::Failed, error);
            }
            Err(e) => {
                let error = format!("prepare phase failed: {e}");
                return self.abort(spec, signing_secret, receipt, RotationStatus::Failed, error);
            }
        };

        if let Err(e) = backend.set(coord, &new_value) {
            let error = format!("storing the new value failed: {e}");
            return self.abort(spec, signing_secret, receipt, RotationStatus::Failed, error);
        }

        // Phase 2: commit.
        receipt.phase_reached = RotationPhase::Commit;
        let commit_error = match self.send(spec, signing_secret, &receipt, RotationPhase::Commit) {
            Ok(resp) if resp.is_success() => {
                receipt.http_status = Some(resp.status);
                receipt.status = RotationStatus::Committed;
                return receipt;
            }
            Ok(resp) => {
                receipt.http_status = Some(resp.status);
                format!("commit phase failed with HTTP {}", resp.status)
            }
            Err(e) => format!("commit phase failed: {e}"),
        };

        let restored = match &previous {
            Some(prev) => backend.set(coord, prev),
            None => backend.delete(coord),
        };
        match restored {
            Ok(()) => self.abort(
                spec,
                signing_secret,
                receipt,
                RotationStatus::RolledBack,
                commit_error,
            ),
            Err(e) => self.abort(
                spec,
                signing_secret,
                receipt,
                RotationStatus::Failed,
                format!("{commit_error}; restoring the previous value failed: {e}"),
            ),
        }
    }
}
