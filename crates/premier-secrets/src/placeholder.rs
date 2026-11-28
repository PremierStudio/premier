//! Opaque placeholder token registry for the AI Agent Egress Capability Proxy.
//!
//! Agents only ever receive `premier_cap_v1_<var>_<hex>` tokens; the real secret remains
//! inside the host proxy's `Zeroizing<String>` memory and is injected on the wire
//! solely for schema-declared hosts.

use std::collections::HashMap;

use rand::RngCore;
use zeroize::Zeroizing;

use crate::schema::{EgressSpec, Sensitivity};

pub const PLACEHOLDER_PREFIX: &str = "premier_cap_v1_";

/// A capability bound to an opaque placeholder token.
#[derive(Clone)]
pub struct BoundCapability {
    pub var_name: String,
    pub placeholder: String,
    pub secret: Zeroizing<String>,
    pub egress: EgressSpec,
    pub zone: Option<String>,
    pub sensitivity: Sensitivity,
}

// Manual `Debug`: a derived one would print the raw secret into logs and panics.
impl std::fmt::Debug for BoundCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoundCapability")
            .field("var_name", &self.var_name)
            .field("placeholder", &self.placeholder)
            .field("secret", &"[REDACTED]")
            .field("egress", &self.egress)
            .field("zone", &self.zone)
            .field("sensitivity", &self.sensitivity)
            .finish()
    }
}

/// Host-side registry mapping opaque placeholders <-> real secrets + egress constraints.
#[derive(Debug, Default, Clone)]
pub struct PlaceholderRegistry {
    by_placeholder: HashMap<String, BoundCapability>,
    by_var_name: HashMap<String, String>,
}

impl PlaceholderRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mint a fresh opaque placeholder token for `var_name` (sensitivity `Secret`).
    pub fn register(
        &mut self,
        var_name: impl Into<String>,
        secret: Zeroizing<String>,
        egress: EgressSpec,
        zone: Option<String>,
    ) -> String {
        self.register_with_sensitivity(var_name, secret, egress, zone, Sensitivity::Secret)
    }

    /// Mint a fresh opaque placeholder token for `var_name` carrying its schema sensitivity.
    pub fn register_with_sensitivity(
        &mut self,
        var_name: impl Into<String>,
        secret: Zeroizing<String>,
        egress: EgressSpec,
        zone: Option<String>,
        sensitivity: Sensitivity,
    ) -> String {
        let var_name = var_name.into();
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let slug: String = var_name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_lowercase()
                } else {
                    '_'
                }
            })
            .collect();
        let placeholder = format!("{PLACEHOLDER_PREFIX}{slug}_{}", hex::encode(nonce));
        let bound = BoundCapability {
            var_name: var_name.clone(),
            placeholder: placeholder.clone(),
            secret,
            egress,
            zone,
            sensitivity,
        };
        if let Some(old_placeholder) = self.by_var_name.insert(var_name, placeholder.clone()) {
            self.by_placeholder.remove(&old_placeholder);
        }
        self.by_placeholder.insert(placeholder.clone(), bound);
        placeholder
    }

    pub fn get_by_placeholder(&self, placeholder: &str) -> Option<&BoundCapability> {
        self.by_placeholder.get(placeholder)
    }

    pub fn get_by_var(&self, var_name: &str) -> Option<&BoundCapability> {
        self.by_var_name
            .get(var_name)
            .and_then(|ph| self.by_placeholder.get(ph))
    }

    pub fn all(&self) -> impl Iterator<Item = &BoundCapability> {
        self.by_placeholder.values()
    }

    /// Return all registered capabilities whose placeholder appears anywhere in `haystack`.
    pub fn find_in_bytes(&self, haystack: &[u8]) -> Vec<&BoundCapability> {
        if !haystack
            .windows(PLACEHOLDER_PREFIX.len())
            .any(|w| w == PLACEHOLDER_PREFIX.as_bytes())
        {
            return Vec::new();
        }
        let text = String::from_utf8_lossy(haystack);
        self.by_placeholder
            .values()
            .filter(|cap| text.contains(&cap.placeholder))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{ApprovalMode, InjectSpec};

    #[test]
    fn debug_never_prints_the_raw_secret() {
        const RAW: &str = "sk_live_RAW_SECRET_VALUE_123";
        let mut reg = PlaceholderRegistry::new();
        let ph = reg.register(
            "STRIPE_API_KEY",
            Zeroizing::new(RAW.to_owned()),
            EgressSpec {
                hosts: vec!["api.stripe.com".to_owned()],
                methods: vec![],
                path_prefixes: vec![],
                upstream_base_url: None,
                inject: InjectSpec::PlaceholderReplace,
                rate_limit_per_min: None,
                approval: ApprovalMode::Auto,
                jit_ttl_secs: 60,
                auto_allow: vec![],
            },
            None,
        );
        let Some(cap) = reg.get_by_placeholder(&ph) else {
            panic!("capability registered");
        };
        for out in [
            format!("{cap:?}"),
            format!("{cap:#?}"),
            format!("{reg:?}"),
            format!("{reg:#?}"),
        ] {
            assert!(!out.contains(RAW), "{out}");
            assert!(out.contains("[REDACTED]"), "{out}");
            assert!(out.contains("STRIPE_API_KEY"), "{out}");
        }
    }
}
