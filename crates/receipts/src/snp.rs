//! AMD SEV-SNP attestation: report layout, policy checks and a report
//! provider. **The report signature is not verified yet**, so
//! [`SevSnpVerifier`] never accepts a report.
//!
//! Layout follows the `ATTESTATION_REPORT` structure of the SEV-SNP firmware
//! ABI specification (AMD #56860), versions 2 and 3. All integers are
//! little-endian.
//!
//! What a complete verifier must still do, in order, before trusting any field
//! parsed here:
//!
//! 1. obtain the VCEK certificate for `chip_id` and `reported_tcb` (from the
//!    host's certificate table or AMD KDS, `kdsintf.amd.com/vcek/v1/...`), or
//!    the VLEK when `signing_key` says so;
//! 2. verify ARK (self-signed, pinned per product: Milan, Genoa, ...) → ASK
//!    → VCEK, RSA-PSS with SHA-384, and check the ASK/VCEK against AMD's CRL;
//! 3. check the VCEK's TCB extensions equal `reported_tcb`;
//! 4. verify the ECDSA P-384 / SHA-384 signature over
//!    [`SevSnpReport::signed_bytes`] with the VCEK public key;
//! 5. apply a minimum-TCB policy.
//!
//! That needs X.509, RSA and P-384 implementations the workspace does not
//! depend on (e.g. the `x509-cert`, `rsa` and `p384` crates, or the `sev`
//! crate, which bundles all of it).

use std::path::PathBuf;

use sha2::{Digest as _, Sha384};

use crate::attest::{
    AttestationError, AttestationProvider, AttestationVerifier, ReportClaims, PLATFORM_AMD_SEV_SNP,
};

pub const REPORT_LEN: usize = 0x4A0;
const SIGNED_LEN: usize = 0x2A0;
/// `SIGNATURE_ALGO` value for ECDSA P-384 with SHA-384.
pub const SIG_ALGO_ECDSA_P384_SHA384: u32 = 1;
/// Guest policy bit that allows a debugger (the hypervisor can read and write
/// guest memory, including the signing key).
pub const POLICY_DEBUG: u64 = 1 << 19;

/// Fields of an SNP attestation report. Parsed, **not authenticated**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SevSnpReport {
    pub version: u32,
    pub guest_svn: u32,
    pub policy: u64,
    pub vmpl: u32,
    pub signature_algo: u32,
    pub current_tcb: u64,
    /// `MASK_CHIP_KEY` (bit 1 of the flags word).
    pub mask_chip_key: bool,
    /// `SIGNING_KEY`: 0 = VCEK, 1 = VLEK, 7 = none.
    pub signing_key: u8,
    pub report_data: [u8; 64],
    pub measurement: [u8; 48],
    pub host_data: [u8; 32],
    pub reported_tcb: u64,
    pub chip_id: [u8; 64],
    /// ECDSA `R` and `S`, little-endian, zero-padded to 72 bytes each.
    pub signature_r: [u8; 72],
    pub signature_s: [u8; 72],
    raw: Vec<u8>,
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().expect("4 bytes"))
}

fn u64_at(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().expect("8 bytes"))
}

fn arr<const N: usize>(b: &[u8], off: usize) -> [u8; N] {
    b[off..off + N].try_into().expect("in bounds")
}

impl SevSnpReport {
    pub fn parse_unverified(b: &[u8]) -> Result<Self, AttestationError> {
        if b.len() != REPORT_LEN {
            return Err(AttestationError::Malformed(format!(
                "SNP report is {} bytes, expected {REPORT_LEN}",
                b.len()
            )));
        }
        let flags = u32_at(b, 0x48);
        Ok(SevSnpReport {
            version: u32_at(b, 0x00),
            guest_svn: u32_at(b, 0x04),
            policy: u64_at(b, 0x08),
            vmpl: u32_at(b, 0x30),
            signature_algo: u32_at(b, 0x34),
            current_tcb: u64_at(b, 0x38),
            mask_chip_key: flags & 0b10 != 0,
            signing_key: ((flags >> 2) & 0b111) as u8,
            report_data: arr(b, 0x50),
            measurement: arr(b, 0x90),
            host_data: arr(b, 0xC0),
            reported_tcb: u64_at(b, 0x180),
            chip_id: arr(b, 0x1A0),
            signature_r: arr(b, SIGNED_LEN),
            signature_s: arr(b, SIGNED_LEN + 72),
            raw: b.to_vec(),
        })
    }

    /// The bytes the firmware signs.
    pub fn signed_bytes(&self) -> &[u8] {
        &self.raw[..SIGNED_LEN]
    }

    /// SHA-384 of [`SevSnpReport::signed_bytes`], the ECDSA message digest.
    pub fn signed_digest(&self) -> [u8; 48] {
        Sha384::digest(self.signed_bytes()).into()
    }

    /// Checks that do not depend on authenticity: a verifier rejects these
    /// reports even if the signature were valid.
    pub fn check_policy(&self) -> Result<(), AttestationError> {
        if self.version < 2 {
            return Err(AttestationError::Rejected(format!(
                "unsupported SNP report version {}",
                self.version
            )));
        }
        if self.signature_algo != SIG_ALGO_ECDSA_P384_SHA384 {
            return Err(AttestationError::Rejected(format!(
                "unsupported SNP signature algorithm {}",
                self.signature_algo
            )));
        }
        if self.policy & POLICY_DEBUG != 0 {
            return Err(AttestationError::Rejected(
                "guest policy allows debugging".into(),
            ));
        }
        if self.signing_key > 1 {
            return Err(AttestationError::Rejected(
                "report is not signed by a VCEK or VLEK".into(),
            ));
        }
        if self.mask_chip_key {
            return Err(AttestationError::Rejected(
                "chip id is masked; the VCEK cannot be identified".into(),
            ));
        }
        Ok(())
    }
}

/// Verifier for SEV-SNP reports. **Incomplete:** parses and applies
/// [`SevSnpReport::check_policy`], then refuses with
/// [`AttestationError::Unimplemented`] because it cannot check the signature
/// (see the module docs). It never returns `Ok`.
#[derive(Debug, Default)]
pub struct SevSnpVerifier;

impl SevSnpVerifier {
    pub fn new() -> Self {
        SevSnpVerifier
    }
}

impl AttestationVerifier for SevSnpVerifier {
    fn platform(&self) -> &str {
        PLATFORM_AMD_SEV_SNP
    }

    fn verify_report(&self, report: &[u8]) -> Result<ReportClaims, AttestationError> {
        let r = SevSnpReport::parse_unverified(report)?;
        r.check_policy()?;
        // Once the VCEK chain and ECDSA signature are verified (module docs),
        // this becomes:
        //   Ok(ReportClaims { measurement: Measurement(r.measurement.to_vec()),
        //                     report_data: r.report_data.to_vec() })
        Err(AttestationError::Unimplemented(
            "SEV-SNP report signature and VCEK certificate chain are not verified \
             (needs X.509, RSA-PSS and ECDSA P-384 support)",
        ))
    }
}

/// Requests SNP reports through the Linux configfs-tsm interface
/// (`/sys/kernel/config/tsm/report`, Linux 6.7+). Runs inside the SNP guest.
///
/// **Untested against real hardware.**
pub struct SevSnpTsmProvider {
    root: PathBuf,
}

impl SevSnpTsmProvider {
    pub fn new() -> Self {
        Self::with_root("/sys/kernel/config/tsm/report")
    }

    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        SevSnpTsmProvider { root: root.into() }
    }
}

impl Default for SevSnpTsmProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl AttestationProvider for SevSnpTsmProvider {
    fn platform(&self) -> &str {
        PLATFORM_AMD_SEV_SNP
    }

    async fn report(&self, report_data: [u8; 32]) -> anyhow::Result<Vec<u8>> {
        use anyhow::{bail, Context};
        let dir = self
            .root
            .join(format!("rebut-{:016x}", rand::random::<u64>()));
        std::fs::create_dir(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let result = (|| {
            let provider = std::fs::read_to_string(dir.join("provider"))?;
            if provider.trim() != "sev_guest" {
                bail!(
                    "configfs-tsm provider is {:?}, not sev_guest",
                    provider.trim()
                );
            }
            let mut inblob = [0u8; 64];
            inblob[..32].copy_from_slice(&report_data);
            std::fs::write(dir.join("inblob"), inblob)?;
            let out = std::fs::read(dir.join("outblob"))?;
            let parsed = SevSnpReport::parse_unverified(&out)?;
            if parsed.report_data != inblob {
                bail!("SNP report does not carry the requested report data");
            }
            Ok(out)
        })();
        let _ = std::fs::remove_dir(&dir);
        result
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn synthetic_report(report_data: [u8; 32], measurement: [u8; 48], policy: u64) -> Vec<u8> {
        let mut b = vec![0u8; REPORT_LEN];
        b[0x00..0x04].copy_from_slice(&3u32.to_le_bytes());
        b[0x08..0x10].copy_from_slice(&policy.to_le_bytes());
        b[0x34..0x38].copy_from_slice(&SIG_ALGO_ECDSA_P384_SHA384.to_le_bytes());
        b[0x50..0x70].copy_from_slice(&report_data);
        b[0x90..0xC0].copy_from_slice(&measurement);
        b[0x180..0x188].copy_from_slice(&0x1b00_0000_0000_0003u64.to_le_bytes());
        b[0x1A0..0x1E0].copy_from_slice(&[0xcc; 64]);
        b[SIGNED_LEN..SIGNED_LEN + 72].copy_from_slice(&[0x11; 72]);
        b
    }

    #[test]
    fn parses_layout() {
        let b = synthetic_report([7; 32], [9; 48], 0x30000);
        let r = SevSnpReport::parse_unverified(&b).unwrap();
        assert_eq!(r.version, 3);
        assert_eq!(r.policy, 0x30000);
        assert_eq!(&r.report_data[..32], &[7; 32]);
        assert_eq!(&r.report_data[32..], &[0; 32]);
        assert_eq!(r.measurement, [9; 48]);
        assert_eq!(r.reported_tcb, 0x1b00_0000_0000_0003);
        assert_eq!(r.chip_id, [0xcc; 64]);
        assert_eq!(r.signature_r, [0x11; 72]);
        assert_eq!(r.signed_bytes().len(), 0x2A0);
        r.check_policy().unwrap();
        assert!(SevSnpReport::parse_unverified(&b[1..]).is_err());
    }

    #[test]
    fn policy_rejects_debug_and_bad_algo() {
        let b = synthetic_report([0; 32], [0; 48], 0x30000 | POLICY_DEBUG);
        assert!(matches!(
            SevSnpVerifier.verify_report(&b),
            Err(AttestationError::Rejected(_))
        ));
        let mut b = synthetic_report([0; 32], [0; 48], 0x30000);
        b[0x34] = 2;
        assert!(SevSnpReport::parse_unverified(&b)
            .unwrap()
            .check_policy()
            .is_err());
    }

    #[test]
    fn rebut_never_accepts_unauthenticated_reports() {
        let b = synthetic_report([0; 32], [0; 48], 0x30000);
        assert!(matches!(
            SevSnpVerifier.verify_report(&b),
            Err(AttestationError::Unimplemented(_))
        ));
    }
}
