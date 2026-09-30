//! Content addressing (ADR-3): artifacts are stored under their SHA-256.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// A SHA-256 digest, serialized as lowercase hex.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Digest(pub [u8; 32]);

impl Digest {
    pub fn of(bytes: &[u8]) -> Self {
        Digest(Sha256::digest(bytes).into())
    }

    /// Digest of several parts with unambiguous framing (length-prefixed), so
    /// `("ab","c")` and `("a","bc")` never collide.
    pub fn of_parts(parts: &[&[u8]]) -> Self {
        let mut h = Sha256::new();
        for p in parts {
            h.update((p.len() as u64).to_be_bytes());
            h.update(p);
        }
        Digest(h.finalize().into())
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Object-store key: `sha256/ab/cdef...`.
    pub fn object_key(&self) -> String {
        let h = self.to_hex();
        format!("sha256/{}/{}", &h[..2], &h[2..])
    }
}

impl std::fmt::Debug for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sha256:{}", self.to_hex())
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sha256:{}", self.to_hex())
    }
}

impl TryFrom<String> for Digest {
    type Error = String;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        let s = s.strip_prefix("sha256:").unwrap_or(&s);
        let bytes = hex::decode(s).map_err(|e| e.to_string())?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "digest must be 32 bytes".to_string())?;
        Ok(Digest(arr))
    }
}

impl From<Digest> for String {
    fn from(d: Digest) -> String {
        d.to_hex()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_prevents_concatenation_collisions() {
        assert_ne!(
            Digest::of_parts(&[b"ab", b"c"]),
            Digest::of_parts(&[b"a", b"bc"])
        );
    }

    #[test]
    fn hex_roundtrip() {
        let d = Digest::of(b"hello");
        let s: String = d.into();
        assert_eq!(Digest::try_from(s).unwrap(), d);
        assert_eq!(Digest::try_from(format!("{d}")).unwrap(), d);
    }
}
