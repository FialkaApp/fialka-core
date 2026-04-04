/*
 * fialka-core — Cross-platform cryptographic core for Fialka
 * Copyright (C) 2024-2026 DevBot667 — GPL-3.0
 */

//! Fialka wire frame format.
//!
//! Every byte on the Tor socket is wrapped in a FialkaFrame:
//!
//! ```text
//! [ MAGIC_1 (1) | MAGIC_2 (1) | TYPE (1) | PAYLOAD_LEN (4, big-endian) | PAYLOAD (n) ]
//!   Total header: 7 bytes
//! ```
//!
//! Constants and encoding are byte-for-byte identical with:
//!   Android: FrameProtocol.kt
//!   Desktop: FrameProtocol.cs

// ── Magic bytes ──────────────────────────────────────────────────────────────

/// First magic byte — 0xF1 ("Fi" for Fialka).
pub const MAGIC_1: u8 = 0xF1;
/// Second magic byte — 0xA1 ("al" for Fialka).
pub const MAGIC_2: u8 = 0xA1;

// ── Frame type identifiers ────────────────────────────────────────────────────

/// PQXDH handshake — initiator → responder (first message in a new session).
pub const TYPE_HANDSHAKE_INIT:  u8 = 0x01;
/// PQXDH handshake — responder → initiator (completes the handshake).
pub const TYPE_HANDSHAKE_RESP:  u8 = 0x02;
/// Encrypted Double Ratchet message.
pub const TYPE_MESSAGE:         u8 = 0x03;
/// Delivery acknowledgement.
pub const TYPE_ACK:             u8 = 0x04;
/// Extended delivery status (read/delivered).
pub const TYPE_DELIVERY_STATUS: u8 = 0x05;
/// Presence / keep-alive ping.
pub const TYPE_PRESENCE:        u8 = 0x06;
/// Store a message in the mailbox (offline delivery).
pub const TYPE_MAILBOX_STORE:   u8 = 0x07;
/// Fetch messages from the mailbox.
pub const TYPE_MAILBOX_FETCH:   u8 = 0x08;

/// Frame header size in bytes: MAGIC(2) + TYPE(1) + LEN(4) = 7.
pub const HEADER_LEN: usize = 7;
/// Maximum allowed payload size (16 MiB — prevents memory exhaustion).
pub const MAX_PAYLOAD_LEN: u32 = 16 * 1024 * 1024;

// ── FialkaFrame ───────────────────────────────────────────────────────────────

/// A Fialka wire frame.
///
/// Serialize with [`FialkaFrame::to_bytes()`],
/// deserialize from a complete byte slice with [`FialkaFrame::from_bytes()`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FialkaFrame {
    /// Frame type (one of the `TYPE_*` constants).
    pub frame_type: u8,
    /// Raw payload bytes.
    pub payload: Vec<u8>,
}

/// Error type for frame serialization/deserialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// Slice is shorter than the 7-byte header.
    TooShort,
    /// Magic bytes do not match 0xF1 0xA1.
    BadMagic,
    /// Payload length in header exceeds MAX_PAYLOAD_LEN or the slice.
    BadLength,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::TooShort  => write!(f, "frame too short (< 7 header bytes)"),
            FrameError::BadMagic  => write!(f, "bad magic bytes (expected 0xF1 0xA1)"),
            FrameError::BadLength => write!(f, "payload length out of range"),
        }
    }
}

impl FialkaFrame {
    /// Create a new frame from a type byte and payload.
    pub fn new(frame_type: u8, payload: Vec<u8>) -> Self {
        Self { frame_type, payload }
    }

    /// Serialize to wire bytes: MAGIC(2) + TYPE(1) + LEN_BE(4) + PAYLOAD.
    pub fn to_bytes(&self) -> Vec<u8> {
        let len = self.payload.len() as u32;
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.push(MAGIC_1);
        out.push(MAGIC_2);
        out.push(self.frame_type);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Deserialize from a complete wire byte slice.
    ///
    /// Returns `Err(FrameError)` if the slice is malformed.
    /// Returns `Ok(frame)` on success — no leftover bytes are allowed;
    /// use [`FialkaFrame::from_bytes_prefix()`] if parsing a stream.
    pub fn from_bytes(data: &[u8]) -> Result<Self, FrameError> {
        if data.len() < HEADER_LEN {
            return Err(FrameError::TooShort);
        }
        if data[0] != MAGIC_1 || data[1] != MAGIC_2 {
            return Err(FrameError::BadMagic);
        }
        let frame_type = data[2];
        let payload_len = u32::from_be_bytes([data[3], data[4], data[5], data[6]]);
        if payload_len > MAX_PAYLOAD_LEN {
            return Err(FrameError::BadLength);
        }
        let total = HEADER_LEN + payload_len as usize;
        if data.len() < total {
            return Err(FrameError::BadLength);
        }
        let payload = data[HEADER_LEN..total].to_vec();
        Ok(Self { frame_type, payload })
    }

    /// Deserialize from a byte stream prefix.
    ///
    /// Returns `Ok((frame, consumed_bytes))` where `consumed_bytes` is the
    /// number of bytes consumed from `data`.  The caller should advance its
    /// read cursor by that amount.
    pub fn from_bytes_prefix(data: &[u8]) -> Result<(Self, usize), FrameError> {
        if data.len() < HEADER_LEN {
            return Err(FrameError::TooShort);
        }
        if data[0] != MAGIC_1 || data[1] != MAGIC_2 {
            return Err(FrameError::BadMagic);
        }
        let frame_type = data[2];
        let payload_len = u32::from_be_bytes([data[3], data[4], data[5], data[6]]);
        if payload_len > MAX_PAYLOAD_LEN {
            return Err(FrameError::BadLength);
        }
        let total = HEADER_LEN + payload_len as usize;
        if data.len() < total {
            return Err(FrameError::BadLength);
        }
        let payload = data[HEADER_LEN..total].to_vec();
        Ok((Self { frame_type, payload }, total))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_empty_payload() {
        let frame = FialkaFrame::new(TYPE_MESSAGE, vec![]);
        let bytes = frame.to_bytes();
        assert_eq!(bytes.len(), HEADER_LEN);
        assert_eq!(bytes[0], MAGIC_1);
        assert_eq!(bytes[1], MAGIC_2);
        assert_eq!(bytes[2], TYPE_MESSAGE);
        // payload_len = 0
        assert_eq!(&bytes[3..7], &[0, 0, 0, 0]);
        let parsed = FialkaFrame::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, frame);
    }

    #[test]
    fn test_roundtrip_with_payload() {
        let payload = b"Hello, Fialka!".to_vec();
        let frame = FialkaFrame::new(TYPE_HANDSHAKE_INIT, payload.clone());
        let bytes = frame.to_bytes();

        // Header check
        assert_eq!(bytes[0], MAGIC_1);
        assert_eq!(bytes[1], MAGIC_2);
        assert_eq!(bytes[2], TYPE_HANDSHAKE_INIT);
        let len = u32::from_be_bytes([bytes[3], bytes[4], bytes[5], bytes[6]]);
        assert_eq!(len, payload.len() as u32);
        assert_eq!(&bytes[7..], payload.as_slice());

        let parsed = FialkaFrame::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.frame_type, TYPE_HANDSHAKE_INIT);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn test_all_frame_types_roundtrip() {
        let types = [
            TYPE_HANDSHAKE_INIT, TYPE_HANDSHAKE_RESP, TYPE_MESSAGE,
            TYPE_ACK, TYPE_DELIVERY_STATUS, TYPE_PRESENCE,
            TYPE_MAILBOX_STORE, TYPE_MAILBOX_FETCH,
        ];
        for ft in types {
            let frame = FialkaFrame::new(ft, vec![0xDE, 0xAD, 0xBE, 0xEF]);
            let bytes = frame.to_bytes();
            let parsed = FialkaFrame::from_bytes(&bytes).unwrap();
            assert_eq!(parsed.frame_type, ft);
            assert_eq!(parsed.payload, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        }
    }

    #[test]
    fn test_bad_magic() {
        let mut bytes = FialkaFrame::new(TYPE_MESSAGE, b"test".to_vec()).to_bytes();
        bytes[0] = 0x00; // corrupt magic
        assert_eq!(FialkaFrame::from_bytes(&bytes), Err(FrameError::BadMagic));
    }

    #[test]
    fn test_too_short() {
        let bytes = [MAGIC_1, MAGIC_2, TYPE_MESSAGE]; // only 3 bytes, need 7
        assert_eq!(FialkaFrame::from_bytes(&bytes), Err(FrameError::TooShort));
    }

    #[test]
    fn test_bad_length_exceeds_max() {
        let mut bytes = FialkaFrame::new(TYPE_MESSAGE, b"x".to_vec()).to_bytes();
        // Set payload_len to MAX+1
        let bad_len = (MAX_PAYLOAD_LEN + 1).to_be_bytes();
        bytes[3] = bad_len[0];
        bytes[4] = bad_len[1];
        bytes[5] = bad_len[2];
        bytes[6] = bad_len[3];
        assert_eq!(FialkaFrame::from_bytes(&bytes), Err(FrameError::BadLength));
    }

    #[test]
    fn test_bad_length_truncated_payload() {
        let frame = FialkaFrame::new(TYPE_MESSAGE, b"hello world".to_vec());
        let bytes = frame.to_bytes();
        // Truncate by 3 bytes — header says 11 bytes payload but we only provide 8
        let truncated = &bytes[..bytes.len() - 3];
        assert_eq!(FialkaFrame::from_bytes(truncated), Err(FrameError::BadLength));
    }

    #[test]
    fn test_from_bytes_prefix_with_trailing() {
        let frame = FialkaFrame::new(TYPE_ACK, b"ack".to_vec());
        let mut bytes = frame.to_bytes();
        bytes.extend_from_slice(b"EXTRA_DATA");

        let (parsed, consumed) = FialkaFrame::from_bytes_prefix(&bytes).unwrap();
        assert_eq!(parsed, frame);
        assert_eq!(consumed, HEADER_LEN + 3); // 7 + 3
        assert_eq!(&bytes[consumed..], b"EXTRA_DATA");
    }

    #[test]
    fn test_wire_format_known_vector() {
        // Fixed vector: TYPE_MESSAGE, payload = [0x01, 0x02, 0x03]
        // Expected: [0xF1, 0xA1, 0x03, 0x00, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03]
        let frame = FialkaFrame::new(TYPE_MESSAGE, vec![0x01, 0x02, 0x03]);
        let bytes = frame.to_bytes();
        assert_eq!(bytes, vec![0xF1, 0xA1, 0x03, 0x00, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03]);
    }
}
