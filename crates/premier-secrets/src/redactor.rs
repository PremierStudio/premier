//! High-speed streaming secret redactor (`aho-corasick`) catching raw, percent-, hex-, JSON-
//! and base64-encoded secret forms across arbitrary chunk boundaries.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};

/// Minimum secret byte length eligible for scrubbing to avoid false positives on `"1"`, `"dev"`, etc.
const MIN_REDACT_LEN: usize = 4;

/// Immutable compiled redactor over a set of `(var_name, secret_bytes)`.
#[derive(Debug, Clone)]
pub struct SecretRedactor {
    matcher: Option<AhoCorasick>,
    /// Populated only if `AhoCorasickBuilder::build` fails for a non-empty pattern set,
    /// guaranteeing redaction never silently disables itself.
    fallback_patterns: Vec<Vec<u8>>,
    replacements: Vec<String>,
    max_pattern_len: usize,
}

impl SecretRedactor {
    /// Build a redactor covering raw, URL-encoded, and Base64 encodings of each secret.
    pub fn build<'a, I>(secrets: I) -> Self
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        let mut patterns: Vec<Vec<u8>> = Vec::new();
        let mut replacements: Vec<String> = Vec::new();
        let mut max_pattern_len = 0usize;

        for (var_name, raw) in secrets {
            if raw.len() < MIN_REDACT_LEN {
                continue;
            }
            let tag = format!("[REDACTED:{var_name}]");

            for v in encoded_variants(raw) {
                let bytes = v.into_bytes();
                if bytes.len() >= MIN_REDACT_LEN && !patterns.contains(&bytes) {
                    max_pattern_len = max_pattern_len.max(bytes.len());
                    patterns.push(bytes);
                    replacements.push(tag.clone());
                }
            }
        }

        let (matcher, fallback_patterns) = if patterns.is_empty() {
            (None, Vec::new())
        } else {
            match AhoCorasickBuilder::new()
                .match_kind(MatchKind::LeftmostLongest)
                .build(&patterns)
            {
                Ok(ac) => (Some(ac), Vec::new()),
                Err(_) => (None, patterns),
            }
        };

        Self {
            matcher,
            fallback_patterns,
            replacements,
            max_pattern_len,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.matcher.is_none() && self.fallback_patterns.is_empty()
    }

    /// Leftmost-longest direct substring search used only when `AhoCorasick` build failed.
    fn find_next_fallback(&self, haystack: &[u8], start: usize) -> Option<(usize, usize, usize)> {
        for pos in start..haystack.len() {
            let tail = &haystack[pos..];
            let mut best: Option<(usize, usize)> = None;
            for (idx, pat) in self.fallback_patterns.iter().enumerate() {
                if !pat.is_empty() && tail.starts_with(pat) {
                    match best {
                        Some((_, best_len)) if pat.len() <= best_len => {}
                        _ => best = Some((idx, pat.len())),
                    }
                }
            }
            if let Some((idx, len)) = best {
                return Some((pos, pos + len, idx));
            }
        }
        None
    }

    /// Scrub a complete byte buffer, returning `(scrubbed_bytes, bytes_scrubbed)`.
    pub fn redact_bytes(&self, input: &[u8]) -> (Vec<u8>, usize) {
        if let Some(ref ac) = self.matcher {
            let mut out = Vec::with_capacity(input.len());
            let mut last = 0usize;
            let mut scrubbed = 0usize;
            for m in ac.find_iter(input) {
                out.extend_from_slice(&input[last..m.start()]);
                out.extend_from_slice(self.replacements[m.pattern().as_usize()].as_bytes());
                scrubbed += m.end() - m.start();
                last = m.end();
            }
            out.extend_from_slice(&input[last..]);
            return (out, scrubbed);
        }
        if self.fallback_patterns.is_empty() {
            return (input.to_vec(), 0);
        }
        let mut out = Vec::with_capacity(input.len());
        let mut last = 0usize;
        let mut scrubbed = 0usize;
        while let Some((start, end, pat_idx)) = self.find_next_fallback(input, last) {
            out.extend_from_slice(&input[last..start]);
            out.extend_from_slice(self.replacements[pat_idx].as_bytes());
            scrubbed += end - start;
            last = end;
        }
        out.extend_from_slice(&input[last..]);
        (out, scrubbed)
    }

    /// Scrub a UTF-8 string, returning `(scrubbed, bytes_scrubbed)`.
    pub fn redact_str(&self, input: &str) -> (String, usize) {
        let (bytes, count) = self.redact_bytes(input.as_bytes());
        (String::from_utf8_lossy(&bytes).into_owned(), count)
    }

    /// Create a chunk-boundary-safe streaming redactor.
    pub fn streaming(&self) -> StreamingRedactor<'_> {
        StreamingRedactor {
            redactor: self,
            pending: Vec::new(),
            total_scrubbed: 0,
        }
    }
}

/// Chunk-boundary-safe streaming wrapper retaining up to `max_pattern_len - 1` raw tail bytes.
pub struct StreamingRedactor<'a> {
    redactor: &'a SecretRedactor,
    pending: Vec<u8>,
    total_scrubbed: usize,
}

impl<'a> StreamingRedactor<'a> {
    /// Push a new chunk and return safe-to-emit scrubbed bytes.
    ///
    /// Bytes are only released once no pattern starting in them can still be completed (or
    /// lengthened) by a later chunk, so the output is identical to scrubbing the whole stream.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        if self.redactor.is_empty() {
            return chunk.to_vec();
        }
        self.pending.extend_from_slice(chunk);
        // A match starting before `safe` has every candidate pattern fully in the buffer.
        let safe = (self.pending.len() + 1).saturating_sub(self.redactor.max_pattern_len);
        let mut out = Vec::new();
        let mut cursor = 0usize;
        if let Some(ac) = &self.redactor.matcher {
            for m in ac.find_iter(&self.pending) {
                if m.start() >= safe {
                    break;
                }
                out.extend_from_slice(&self.pending[cursor..m.start()]);
                out.extend_from_slice(
                    self.redactor.replacements[m.pattern().as_usize()].as_bytes(),
                );
                self.total_scrubbed += m.end() - m.start();
                cursor = m.end();
            }
        } else {
            while let Some((start, end, pat_idx)) =
                self.redactor.find_next_fallback(&self.pending, cursor)
            {
                if start >= safe {
                    break;
                }
                out.extend_from_slice(&self.pending[cursor..start]);
                out.extend_from_slice(self.redactor.replacements[pat_idx].as_bytes());
                self.total_scrubbed += end - start;
                cursor = end;
            }
        }
        let keep_from = cursor.max(safe);
        out.extend_from_slice(&self.pending[cursor..keep_from]);
        self.pending.drain(..keep_from);
        out
    }

    /// Flush remaining buffered bytes at EOF.
    pub fn finish(&mut self) -> Vec<u8> {
        if self.pending.is_empty() {
            return Vec::new();
        }
        let (scrubbed, count) = self.redactor.redact_bytes(&self.pending);
        self.total_scrubbed += count;
        self.pending.clear();
        scrubbed
    }

    pub fn total_scrubbed(&self) -> usize {
        self.total_scrubbed
    }
}

/// Every form of `raw` an upstream might reflect: raw, percent-encoded (reserved-only and
/// every-byte, both hex cases, form `+`), hex, JSON-escaped, and base64 (standard and URL-safe,
/// padded or not) at all three byte alignments.
fn encoded_variants(raw: &str) -> Vec<String> {
    let bytes = raw.as_bytes();
    let mut out = vec![raw.to_owned(), hex::encode(bytes), hex::encode_upper(bytes)];

    for upper in [true, false] {
        out.push(percent_encode(bytes, false, upper));
        out.push(percent_encode(bytes, true, upper));
        out.push(percent_encode(bytes, false, upper).replace("%20", "+"));
    }

    if let Ok(quoted) = serde_json::to_string(raw) {
        let inner = &quoted[1..quoted.len() - 1];
        out.push(inner.replace('/', "\\/"));
        out.push(inner.to_owned());
    }

    out.push(STANDARD.encode(bytes));
    out.push(URL_SAFE.encode(bytes));
    for engine in [&STANDARD_NO_PAD, &URL_SAFE_NO_PAD] {
        out.push(engine.encode(bytes));
        // Embedded in a larger base64 document the secret starts at byte offset 0, 1 or 2 of a
        // 3-byte group. Match the characters the secret alone determines: drop the leading
        // ones shared with preceding bytes and the trailing one shared with the next byte.
        for (lead, skip) in [(0usize, 0usize), (1, 2), (2, 3)] {
            let mut padded = vec![0u8; lead];
            padded.extend_from_slice(bytes);
            let enc = engine.encode(&padded);
            let end = enc.len() - usize::from(padded.len() % 3 != 0);
            if skip < end {
                out.push(enc[skip..end].to_owned());
            }
        }
    }
    out
}

fn percent_encode(input: &[u8], every_byte: bool, upper: bool) -> String {
    let mut out = String::with_capacity(input.len() * 3);
    for &b in input {
        if !every_byte && (b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~')) {
            out.push(b as char);
        } else if upper {
            out.push_str(&format!("%{b:02X}"));
        } else {
            out.push_str(&format!("%{b:02x}"));
        }
    }
    out
}

/// Percent-encode everything outside the RFC 3986 unreserved set (for URI path/query values).
pub fn percent_encode_component(input: &str) -> String {
    percent_encode(input.as_bytes(), false, true)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn fallback_matcher_scrubs_bytes_and_streams_when_ac_absent() {
        let secret = "sk_live_fallback_999";
        let redactor = SecretRedactor {
            matcher: None,
            fallback_patterns: vec![b"sk_live".to_vec(), secret.as_bytes().to_vec()],
            replacements: vec!["[REDACTED:SHORT]".to_owned(), "[REDACTED:KEY]".to_owned()],
            max_pattern_len: secret.len(),
        };
        assert!(!redactor.is_empty());
        let input = format!("pre-{secret}-post");
        let (clean, scrubbed) = redactor.redact_str(&input);
        assert_eq!(clean, "pre-[REDACTED:KEY]-post");
        assert_eq!(scrubbed, secret.len());

        let mut stream = redactor.streaming();
        let mut out = Vec::new();
        for chunk in input.as_bytes().chunks(4) {
            out.extend(stream.push(chunk));
        }
        out.extend(stream.finish());
        assert_eq!(String::from_utf8(out).unwrap(), "pre-[REDACTED:KEY]-post");
        assert_eq!(stream.total_scrubbed(), secret.len());
    }
}
