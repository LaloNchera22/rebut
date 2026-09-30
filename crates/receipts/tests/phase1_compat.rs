//! A receipt produced by the phase-1 code (before `predicate.signer`
//! existed) must keep verifying and decode as an operator-key receipt.

use ed25519_dalek::SigningKey;
use verifier_receipts::{
    verify_envelope, verify_receipt_with_policy, Envelope, ReceiptPolicy, SignerIdentity,
    VerifiedSigner,
};

const PHASE1: &str = include_str!("fixtures/phase1-receipt.json");

#[test]
fn phase1_receipt_still_verifies() {
    let env: Envelope = serde_json::from_str(PHASE1).unwrap();
    assert!(!String::from_utf8(env.payload_bytes().unwrap())
        .unwrap()
        .contains("\"signer\""));
    let key = SigningKey::from_bytes(&[7; 32]).verifying_key();

    let st = verify_envelope(&env, &key).unwrap();
    assert_eq!(st.predicate.signer, SignerIdentity::OperatorKey);
    assert_eq!(st.predicate.pr_number, 7);

    let got = verify_receipt_with_policy(&env, &ReceiptPolicy::operator(key)).unwrap();
    assert!(matches!(got.signer, VerifiedSigner::OperatorKey { .. }));
    assert_eq!(got.statement, st);

    let other = SigningKey::from_bytes(&[8; 32]).verifying_key();
    assert!(verify_envelope(&env, &other).is_err());
    assert!(verify_receipt_with_policy(&env, &ReceiptPolicy::operator(other)).is_err());
}
