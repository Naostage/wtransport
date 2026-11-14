use crate::bytes::BytesWriter;
use crate::capsule::capsule_types;
use crate::capsule::Capsule;
use crate::capsule::CapsuleKind;
use crate::error::ErrorCode;
use crate::frame::Frame;
use crate::varint::VarInt;
use std::borrow::Cow;

/// Maximum length (in bytes) of the reason of a [`CloseWebTransportSession`].
pub const MAX_REASON_LEN: usize = 1024;

/// Capsules for WebTransport session termination.
#[derive(Debug)]
pub struct CloseWebTransportSession {
    error_code: u32,
    reason: String,
}

impl CloseWebTransportSession {
    /// Creates a new capsule closing the session with `error_code` and `reason`.
    ///
    /// # Panics
    ///
    /// Panics if `reason` is longer than [`MAX_REASON_LEN`] bytes.
    pub fn new<R>(error_code: u32, reason: R) -> Self
    where
        R: Into<String>,
    {
        let reason = reason.into();
        assert!(reason.len() <= MAX_REASON_LEN);

        Self { error_code, reason }
    }

    /// Parses from [`Capsule`].
    ///
    /// # Panics
    ///
    /// Panics if `capsule` is not
    /// [`CloseWebTransportSession`](CapsuleKind::CloseWebtransportsession) type.
    pub fn with_capsule(capsule: &Capsule) -> Result<Self, ErrorCode> {
        assert!(matches!(
            capsule.kind(),
            CapsuleKind::CloseWebTransportSession
        ));

        let payload = capsule.payload();

        if payload.len() < 4 || payload.len() > 4 + MAX_REASON_LEN {
            return Err(ErrorCode::Datagram);
        }

        let error_code =
            u32::from_be_bytes(payload[..4].try_into().expect("4B to u32 should succeed"));
        let reason = std::str::from_utf8(&payload[4..])
            .map_err(|_| ErrorCode::Datagram)?
            .to_string();

        Ok(Self { error_code, reason })
    }

    /// Returns the error code sent over this capsule.
    pub fn error_code(&self) -> VarInt {
        VarInt::from_u32(self.error_code)
    }

    /// Returns the reason sent over this capsule.
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Generates a [`Data`](crate::frame::FrameKind::Data) [`Frame`] carrying this capsule.
    pub fn generate_frame(&self) -> Frame<'static> {
        let mut payload = Vec::new();

        payload
            .put_varint(capsule_types::CAPSULE_TYPE_CLOSE_WEBTRANSPORT_SESSION)
            .expect("Vec does not have EOF");

        payload
            .put_varint(VarInt::from_u32(4 + self.reason.len() as u32))
            .expect("Vec does not have EOF");

        payload
            .put_bytes(&self.error_code.to_be_bytes())
            .expect("Vec does not have EOF");

        payload
            .put_bytes(self.reason.as_bytes())
            .expect("Vec does not have EOF");

        Frame::new_data(Cow::Owned(payload))
    }
}
