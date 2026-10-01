use super::*;

const DAY: u64 = SECONDS_PER_DAY;
const SCOPE: &[u8] = b"repo:owner/name:bounty-2026-10";
const NONCE: &[u8] = b"rebut-nonce-0001";

/// alice: 7 verified merges, first one on day 20_000 (+ some seconds).
fn graph() -> TrustGraph {
    let mut g = TrustGraph::new();
    for i in 0..7u64 {
        let r = Digest::of(format!("alice-receipt-{i}").as_bytes());
        g.record_merge_at("alice", r, 20_000 * DAY + 3_600 + i * DAY)
            .unwrap();
    }
    g.record_merge_at("bob", Digest::of(b"bob-receipt"), 19_000 * DAY)
        .unwrap();
    g
}

fn issue_to(sk: &IssuerSecretKey, attrs: &CredentialAttributes) -> (HolderSecret, Credential) {
    let holder = HolderSecret::generate();
    let (req, pending) = request_issuance(&holder).unwrap();
    let issued = issue(sk, &req, attrs).unwrap();
    let cred = accept(&sk.public_key(), &holder, pending, &issued).unwrap();
    (holder, cred)
}

fn setup() -> (IssuerSecretKey, IssuerPublicKey, Credential) {
    let sk = IssuerSecretKey::generate().unwrap();
    let pk = sk.public_key();
    let attrs = CredentialAttributes::from_trust_graph(&graph(), "alice").unwrap();
    let (_, cred) = issue_to(&sk, &attrs);
    (sk, pk, cred)
}

fn at_least(n: u64) -> Predicate {
    Predicate::AtLeast {
        attribute_index: VERIFIED_MERGES,
        value: n,
    }
}

fn at_most_reverts(n: u64) -> Predicate {
    Predicate::AtMost {
        attribute_index: REVERTED_MERGES,
        value: n,
    }
}

#[test]
fn attributes_from_trust_graph() {
    let mut g = graph();
    let a = CredentialAttributes::from_trust_graph(&g, "alice").unwrap();
    assert_eq!(a.verified_merges, 7);
    assert_eq!(a.reverted_merges, 0);
    assert_eq!(a.first_merge_day, 20_000 * DAY, "rounded down to the day");
    assert_eq!(
        a.receipts_commitment,
        receipts_commitment(&g.verified_merges("alice"))
    );

    g.record_revert(g.verified_merges("alice")[0]).unwrap();
    let a = CredentialAttributes::from_trust_graph(&g, "alice").unwrap();
    assert_eq!(a.reverted_merges, 1);

    assert!(CredentialAttributes::from_trust_graph(&g, "carol").is_err());
    let mut untimed = TrustGraph::new();
    untimed.record_merge("dave", Digest::of(b"r")).unwrap();
    assert!(
        CredentialAttributes::from_trust_graph(&untimed, "dave").is_err(),
        "no merge time: refuse rather than invent a first-merge day"
    );
}

#[test]
fn round_trip_issue_present_verify() {
    let (_, pk, cred) = setup();
    let preds = [at_least(5), at_most_reverts(0)];
    let p = present(&pk, &cred, &[FIRST_MERGE_DAY], &preds, SCOPE, NONCE).unwrap();
    let v = verify(&pk, &p, SCOPE, NONCE).unwrap();
    assert_eq!(
        v.disclosed,
        vec![(FIRST_MERGE_DAY, Attribute::FirstMergeDay(20_000 * DAY))]
    );
    assert!(v.proves(&at_least(5)));
    assert!(v.proves(&at_most_reverts(0)));
    assert!(!v.proves(&at_least(1)), "only exactly what was proven");
    assert_eq!(v.attribute(VERIFIED_MERGES), None, "count stays hidden");

    // Through JSON, as a verifier would receive it.
    let back = Presentation::from_json(&p.to_json()).unwrap();
    assert_eq!(verify(&pk, &back, SCOPE, NONCE).unwrap(), v);

    // Nothing disclosed, nothing proven: still a valid, anonymous
    // "I hold a credential from this issuer" with a nullifier.
    let p = present(&pk, &cred, &[], &[], SCOPE, NONCE).unwrap();
    let v = verify(&pk, &p, SCOPE, NONCE).unwrap();
    assert!(v.disclosed.is_empty() && v.predicates.is_empty());

    // Everything disclosed.
    let all = [
        VERIFIED_MERGES,
        REVERTED_MERGES,
        FIRST_MERGE_DAY,
        RECEIPTS_COMMITMENT,
    ];
    let p = present(&pk, &cred, &all, &[at_least(1)], SCOPE, NONCE).unwrap();
    let v = verify(&pk, &p, SCOPE, NONCE).unwrap();
    assert_eq!(v.disclosed.len(), 4);
    assert_eq!(
        v.attribute(VERIFIED_MERGES),
        Some(&Attribute::VerifiedMerges(7))
    );
}

#[test]
fn via_the_trait() {
    fn run<S: CredentialScheme<Error = CredentialError>>(
        sk: &S::IssuerSecretKey,
        pk: &S::IssuerPublicKey,
        holder: &S::HolderSecret,
        attrs: &CredentialAttributes,
    ) -> VerifiedPresentation {
        let (req, pending) = S::request_issuance(holder).unwrap();
        let issued = S::issue(sk, &req, attrs).unwrap();
        let cred = S::accept(pk, holder, pending, &issued).unwrap();
        let p = S::present(pk, &cred, &[], &[at_least(5)], SCOPE, NONCE).unwrap();
        S::verify(pk, &p, SCOPE, NONCE).unwrap()
    }
    let sk = IssuerSecretKey::generate().unwrap();
    let attrs = CredentialAttributes::from_trust_graph(&graph(), "alice").unwrap();
    let v = run::<Bbs>(&sk, &sk.public_key(), &HolderSecret::generate(), &attrs);
    assert!(v.proves(&at_least(5)));
}

#[test]
fn credential_survives_storage() {
    let (_, pk, cred) = setup();
    let stored = serde_json::to_string(&cred).unwrap();
    let back: Credential = serde_json::from_str(&stored).unwrap();
    assert_eq!(back, cred);
    let p = present(&pk, &back, &[], &[at_least(5)], SCOPE, NONCE).unwrap();
    verify(&pk, &p, SCOPE, NONCE).unwrap();
}

#[test]
fn keys_round_trip() {
    let sk = IssuerSecretKey::generate().unwrap();
    let sk2 = IssuerSecretKey::from_bytes(&sk.to_bytes()).unwrap();
    assert_eq!(sk2.public_key(), sk.public_key());
    let pk = IssuerPublicKey::from_bytes(&sk.public_key().to_bytes()).unwrap();
    assert_eq!(pk, sk.public_key());
    assert!(IssuerPublicKey::from_bytes(&[0u8; 10]).is_err());
    let mut identity = [0u8; 96];
    identity[0] = 0xc0;
    assert!(IssuerPublicKey::from_bytes(&identity).is_err());
    assert!(IssuerSecretKey::from_bytes(&[0u8; 32]).is_err());
    let h = HolderSecret::generate();
    assert_eq!(
        HolderSecret::from_bytes(&h.to_bytes()).unwrap().to_bytes(),
        h.to_bytes()
    );
}

#[test]
fn tampered_presentation_is_rejected() {
    let (_, pk, cred) = setup();
    let p = present(&pk, &cred, &[FIRST_MERGE_DAY], &[at_least(5)], SCOPE, NONCE).unwrap();
    verify(&pk, &p, SCOPE, NONCE).unwrap();

    // A bit flip in every component of the proof: the three points, then
    // each 32-byte scalar (e^, r1^, r3^, the m^s, the challenge). One flip
    // per component keeps the test fast in debug builds.
    let positions = (0..3)
        .map(|k| k * 48 + 47)
        .chain((144..p.proof.len()).step_by(32).map(|o| o + 31));
    for i in positions {
        let mut t = p.clone();
        t.proof[i] ^= 0x01;
        assert_eq!(
            verify(&pk, &t, SCOPE, NONCE),
            Err(CredentialError::Invalid),
            "proof byte {i}"
        );
    }
    for i in [0, 23, 47] {
        let mut t = p.clone();
        t.pseudonym[i] ^= 0x01;
        assert_eq!(
            verify(&pk, &t, SCOPE, NONCE),
            Err(CredentialError::Invalid),
            "nym byte {i}"
        );
    }

    // A different disclosed value.
    let mut t = p.clone();
    t.disclosed[0].1 = Attribute::FirstMergeDay(10_000 * DAY);
    assert_eq!(verify(&pk, &t, SCOPE, NONCE), Err(CredentialError::Invalid));

    // An attribute at the wrong index.
    let mut t = p.clone();
    t.disclosed[0].0 = VERIFIED_MERGES;
    assert_eq!(verify(&pk, &t, SCOPE, NONCE), Err(CredentialError::Invalid));

    // Claiming a stronger bucket than the one proven (alice has 7 < 10).
    let mut t = p.clone();
    t.predicates = vec![at_least(10)];
    assert_eq!(verify(&pk, &t, SCOPE, NONCE), Err(CredentialError::Invalid));

    // Dropping a claim or adding one changes the disclosed set.
    let mut t = p.clone();
    t.predicates.clear();
    assert_eq!(verify(&pk, &t, SCOPE, NONCE), Err(CredentialError::Invalid));
    let mut t = p.clone();
    t.predicates.push(at_least(1));
    assert_eq!(verify(&pk, &t, SCOPE, NONCE), Err(CredentialError::Invalid));

    // Replay under another nonce or scope.
    assert_eq!(
        verify(&pk, &p, SCOPE, b"other-nonce"),
        Err(CredentialError::Invalid)
    );
    assert_eq!(
        verify(&pk, &p, b"other-scope", NONCE),
        Err(CredentialError::Invalid)
    );

    // Truncated and extended inputs are rejected, not panics.
    for len in [0, 1, 47, 48, 239, 240, p.proof.len() - 1] {
        let mut t = p.clone();
        t.proof.truncate(len);
        assert_eq!(verify(&pk, &t, SCOPE, NONCE), Err(CredentialError::Invalid));
    }
    let mut t = p.clone();
    t.proof.extend_from_slice(&[0u8; 32]);
    assert_eq!(verify(&pk, &t, SCOPE, NONCE), Err(CredentialError::Invalid));
    let mut t = p.clone();
    t.pseudonym.clear();
    assert_eq!(verify(&pk, &t, SCOPE, NONCE), Err(CredentialError::Invalid));
}

/// The pairing check passes trivially when `Abar` and `Bbar` are the
/// identity; such proofs must be rejected before the library sees them.
#[test]
fn identity_points_are_rejected() {
    let (_, pk, cred) = setup();
    let p = present(&pk, &cred, &[], &[at_least(5)], SCOPE, NONCE).unwrap();
    let mut identity = [0u8; 48];
    identity[0] = 0xc0;
    for k in 0..3 {
        let mut t = p.clone();
        t.proof[k * 48..(k + 1) * 48].copy_from_slice(&identity);
        assert_eq!(verify(&pk, &t, SCOPE, NONCE), Err(CredentialError::Invalid));
    }
    let mut t = p.clone();
    t.pseudonym = identity.to_vec();
    assert_eq!(verify(&pk, &t, SCOPE, NONCE), Err(CredentialError::Invalid));
}

#[test]
fn wrong_issuer_key_is_rejected() {
    let (_, pk, cred) = setup();
    let other = IssuerSecretKey::generate().unwrap().public_key();
    let p = present(&pk, &cred, &[], &[at_least(5)], SCOPE, NONCE).unwrap();
    assert_eq!(
        verify(&other, &p, SCOPE, NONCE),
        Err(CredentialError::Invalid)
    );

    // A holder also refuses a credential that doesn't verify under the key
    // it expects.
    let sk = IssuerSecretKey::generate().unwrap();
    let attrs = cred.attributes().clone();
    let holder = HolderSecret::generate();
    let (req, pending) = request_issuance(&holder).unwrap();
    let issued = issue(&sk, &req, &attrs).unwrap();
    assert!(accept(&other, &holder, pending, &issued).is_err());

    // Or one whose attributes were changed in transit.
    let (req, pending) = request_issuance(&holder).unwrap();
    let mut issued = issue(&sk, &req, &attrs).unwrap();
    issued.attributes.verified_merges = 1_000;
    assert!(accept(&sk.public_key(), &holder, pending, &issued).is_err());
}

#[test]
fn unmet_or_unsupported_predicate_fails() {
    let (_, pk, cred) = setup();
    let present_with = |p: Predicate| present(&pk, &cred, &[], &[p], SCOPE, NONCE);

    // alice has 7 merges.
    assert_eq!(
        present_with(at_least(10)),
        Err(CredentialError::PredicateNotSatisfied(at_least(10)))
    );
    // 7 is not a bucket: no rounding, no false "valid".
    assert_eq!(
        present_with(at_least(7)),
        Err(CredentialError::UnsupportedPredicate(at_least(7)))
    );
    let on_day = Predicate::AtLeast {
        attribute_index: FIRST_MERGE_DAY,
        value: 1,
    };
    assert_eq!(
        present_with(on_day.clone()),
        Err(CredentialError::UnsupportedPredicate(on_day))
    );
    let wrong_direction = Predicate::AtMost {
        attribute_index: VERIFIED_MERGES,
        value: 10,
    };
    assert!(present_with(wrong_direction).is_err());
    assert!(present(&pk, &cred, &[9], &[], SCOPE, NONCE).is_err());

    // A reverted merge fails "none reverted".
    let sk = IssuerSecretKey::generate().unwrap();
    let mut g = graph();
    g.record_revert(g.verified_merges("alice")[0]).unwrap();
    let attrs = CredentialAttributes::from_trust_graph(&g, "alice").unwrap();
    let (_, cred) = issue_to(&sk, &attrs);
    let pk = sk.public_key();
    assert_eq!(
        present(&pk, &cred, &[], &[at_most_reverts(0)], SCOPE, NONCE),
        Err(CredentialError::PredicateNotSatisfied(at_most_reverts(0)))
    );
    let p = present(&pk, &cred, &[], &[at_most_reverts(1)], SCOPE, NONCE).unwrap();
    assert!(verify(&pk, &p, SCOPE, NONCE)
        .unwrap()
        .proves(&at_most_reverts(1)));
    // Swapping the claim to the false bucket doesn't verify.
    let mut t = p;
    t.predicates = vec![at_most_reverts(0)];
    assert_eq!(verify(&pk, &t, SCOPE, NONCE), Err(CredentialError::Invalid));
}

#[test]
fn nullifier_is_stable_per_scope_and_differs_across_scopes() {
    let (sk, pk, cred) = setup();
    let nullifier = |cred: &Credential, scope: &[u8], nonce: &[u8]| {
        let p = present(&pk, cred, &[], &[at_least(5)], scope, nonce).unwrap();
        verify(&pk, &p, scope, nonce).unwrap().nullifier
    };
    let a1 = nullifier(&cred, SCOPE, b"nonce-1");
    let a2 = nullifier(&cred, SCOPE, b"nonce-2");
    assert_eq!(a1, a2, "same holder, same scope");
    let b = nullifier(&cred, b"repo:other/project:bounty", b"nonce-3");
    assert_ne!(a1, b, "different scopes");

    let attrs = cred.attributes().clone();
    let (_, other) = issue_to(&sk, &attrs);
    assert_ne!(
        nullifier(&other, SCOPE, b"nonce-4"),
        a1,
        "different holder, same scope"
    );
}

#[test]
fn presentations_are_not_byte_equal() {
    let (_, pk, cred) = setup();
    let p1 = present(&pk, &cred, &[], &[at_least(5)], SCOPE, NONCE).unwrap();
    let p2 = present(&pk, &cred, &[], &[at_least(5)], SCOPE, NONCE).unwrap();
    assert_ne!(p1.proof, p2.proof);
    // Across scopes nothing is shared, pseudonym included.
    let p3 = present(&pk, &cred, &[], &[at_least(5)], b"elsewhere", NONCE).unwrap();
    assert_ne!(p1.pseudonym, p3.pseudonym);
    let (s1, s3) = (p1.proof.as_slice(), p3.proof.as_slice());
    assert!(
        s1.chunks(32).zip(s3.chunks(32)).all(|(a, b)| a != b),
        "no shared 32-byte chunk between presentations"
    );
}

#[test]
fn issuer_rejects_bad_requests() {
    let sk = IssuerSecretKey::generate().unwrap();
    let attrs = CredentialAttributes::from_trust_graph(&graph(), "alice").unwrap();
    let (req, _) = request_issuance(&HolderSecret::generate()).unwrap();

    // No commitment: the issuer would know the whole pseudonym secret.
    let empty = IssuanceRequest { commitment: vec![] };
    assert!(issue(&sk, &empty, &attrs).is_err());
    let mut short = req.clone();
    short.commitment.pop();
    assert!(issue(&sk, &short, &attrs).is_err());
    let mut bad = req.clone();
    bad.commitment[60] ^= 1;
    assert!(
        issue(&sk, &bad, &attrs).is_err(),
        "commitment proof must verify"
    );

    let mut inconsistent = attrs.clone();
    inconsistent.reverted_merges = 8;
    assert!(issue(&sk, &req, &inconsistent).is_err());

    // Commitments hide the secret: the same secret commits differently.
    let h = HolderSecret::generate();
    let (r1, _) = request_issuance(&h).unwrap();
    let (r2, _) = request_issuance(&h).unwrap();
    assert_ne!(r1.commitment, r2.commitment);
}

#[test]
fn empty_scope_or_nonce_is_refused() {
    let (_, pk, cred) = setup();
    assert!(present(&pk, &cred, &[], &[], b"", NONCE).is_err());
    assert!(present(&pk, &cred, &[], &[], SCOPE, b"").is_err());
    let p = present(&pk, &cred, &[], &[], SCOPE, NONCE).unwrap();
    assert!(verify(&pk, &p, b"", NONCE).is_err());
    assert!(verify(&pk, &p, SCOPE, b"").is_err());
}
