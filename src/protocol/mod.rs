//! Fialka message frame format.
//!
//! Every message on the wire is wrapped in a FialkaFrame:
//!
//! ```text
//! [ MAGIC_1 | MAGIC_2 | TYPE | PAYLOAD_LEN (4 bytes BE) | PAYLOAD ]
//! ```
//!
//! Constants must stay byte-for-byte identical with:
//!   Android: FrameProtocol.kt
//!   Desktop: FrameProtocol.cs

/// Frame magic bytes (identifies a Fialka frame)
pub const MAGIC_1: u8 = 0xF1;
pub const MAGIC_2: u8 = 0xA1;

/// Frame type identifiers
pub const TYPE_HANDSHAKE_INIT:  u8 = 0x01;
pub const TYPE_HANDSHAKE_RESP:  u8 = 0x02;
pub const TYPE_MESSAGE:         u8 = 0x03;
pub const TYPE_ACK:             u8 = 0x04;
pub const TYPE_DELIVERY_STATUS: u8 = 0x05;
pub const TYPE_PRESENCE:        u8 = 0x06;
pub const TYPE_MAILBOX_STORE:   u8 = 0x07;
pub const TYPE_MAILBOX_FETCH:   u8 = 0x08;

// TODO: implement FialkaFrame struct, serialize(), deserialize()
