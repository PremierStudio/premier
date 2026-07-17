//! Streaming UTF-8 decode that preserves multi-byte sequences across chunk boundaries.

/// Decode a chunk of bytes, retaining any incomplete trailing multi-byte sequence in `pending`.
///
/// Invalid UTF-8 sequences (with a known error length) are replaced with U+FFFD.
/// Incomplete sequences at the end of a chunk are held until more bytes arrive or
/// [`finish_utf8`] is called.
pub fn decode_utf8_chunk(pending: &mut Vec<u8>, chunk: &[u8]) -> String {
    pending.extend_from_slice(chunk);
    let mut output = String::new();
    // Consume via an offset and compact once at the end so a run of invalid
    // bytes stays linear instead of shifting the buffer per replacement.
    let mut offset = 0_usize;
    loop {
        match std::str::from_utf8(&pending[offset..]) {
            Ok(text) => {
                output.push_str(text);
                offset = pending.len();
                break;
            }
            Err(error) => {
                let valid_up_to = error.valid_up_to();
                if valid_up_to > 0 {
                    // SAFETY: valid_up_to marks a verified UTF-8 prefix.
                    let text = unsafe {
                        std::str::from_utf8_unchecked(&pending[offset..offset + valid_up_to])
                    };
                    output.push_str(text);
                    offset += valid_up_to;
                }
                match error.error_len() {
                    Some(len) => {
                        output.push('\u{FFFD}');
                        offset = offset.saturating_add(len).min(pending.len());
                    }
                    None => break,
                }
            }
        }
    }
    pending.drain(..offset);
    output
}

/// Flush any remaining bytes in `pending` after the stream ends.
///
/// Incomplete sequences become U+FFFD via lossy conversion.
pub fn finish_utf8(pending: &mut Vec<u8>) -> String {
    if pending.is_empty() {
        return String::new();
    }
    let text = String::from_utf8_lossy(pending).into_owned();
    pending.clear();
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_ascii_chunks() {
        let mut pending = Vec::new();
        assert_eq!(decode_utf8_chunk(&mut pending, b"hello"), "hello");
        assert!(pending.is_empty());
        assert_eq!(finish_utf8(&mut pending), "");
    }

    #[test]
    fn preserves_check_mark_split_across_chunks() {
        // U+2713 CHECK MARK is E2 9C 93 — the README-style npm test glyph.
        let check = "✓".as_bytes();
        assert_eq!(check, &[0xE2, 0x9C, 0x93]);

        let mut pending = Vec::new();
        let first = decode_utf8_chunk(&mut pending, &check[..1]);
        assert_eq!(first, "");
        assert_eq!(pending, vec![0xE2]);

        let second = decode_utf8_chunk(&mut pending, &check[1..2]);
        assert_eq!(second, "");
        assert_eq!(pending, vec![0xE2, 0x9C]);

        let third = decode_utf8_chunk(&mut pending, &check[2..]);
        assert_eq!(third, "✓");
        assert!(pending.is_empty());
    }

    #[test]
    fn preserves_many_check_marks_with_chunk_splits() {
        let mut pending = Vec::new();
        let mut reconstructed = String::new();
        let source: Vec<u8> = std::iter::repeat_n("✓".as_bytes(), 400)
            .flatten()
            .copied()
            .collect();
        // Split every 5 bytes so multi-byte sequences break mid-character often.
        for window in source.chunks(5) {
            reconstructed.push_str(&decode_utf8_chunk(&mut pending, window));
        }
        reconstructed.push_str(&finish_utf8(&mut pending));
        assert_eq!(reconstructed.chars().filter(|&c| c == '✓').count(), 400);
        assert!(!reconstructed.contains('\u{FFFD}'));
    }

    #[test]
    fn replaces_invalid_bytes_without_stalling() {
        let mut pending = Vec::new();
        // 0xFF is never valid as a UTF-8 lead byte.
        let text = decode_utf8_chunk(&mut pending, &[0xFF, b'a']);
        assert_eq!(text, "\u{FFFD}a");
        assert!(pending.is_empty());
    }

    #[test]
    fn finish_emits_replacement_for_incomplete_trailer() {
        let mut pending = vec![0xE2, 0x9C];
        assert_eq!(finish_utf8(&mut pending), "\u{FFFD}");
        assert!(pending.is_empty());
    }
}
