//! RFC 6962 / RFC 9162 Merkle tree hashing and inclusion proofs.

use sha2::{Digest as _, Sha256};
use verifier_core::Digest;

/// `SHA-256(0x00 || data)`.
pub fn leaf_hash(data: &[u8]) -> Digest {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(data);
    Digest(h.finalize().into())
}

/// `SHA-256(0x01 || left || right)`.
pub fn node_hash(left: &Digest, right: &Digest) -> Digest {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left.0);
    h.update(right.0);
    Digest(h.finalize().into())
}

/// Largest power of two strictly smaller than `n` (requires `n > 1`).
fn split(n: usize) -> usize {
    debug_assert!(n > 1);
    1 << (usize::BITS - 1 - (n - 1).leading_zeros())
}

/// Merkle Tree Hash over already-hashed leaves.
pub fn root_hash(leaves: &[Digest]) -> Digest {
    match leaves.len() {
        0 => Digest(Sha256::digest([]).into()),
        1 => leaves[0],
        n => {
            let k = split(n);
            node_hash(&root_hash(&leaves[..k]), &root_hash(&leaves[k..]))
        }
    }
}

fn path(m: usize, leaves: &[Digest], out: &mut Vec<Digest>) {
    let n = leaves.len();
    if n <= 1 {
        return;
    }
    let k = split(n);
    if m < k {
        path(m, &leaves[..k], out);
        out.push(root_hash(&leaves[k..]));
    } else {
        path(m - k, &leaves[k..], out);
        out.push(root_hash(&leaves[..k]));
    }
}

/// Append-only list of leaf hashes.
#[derive(Debug, Clone, Default)]
pub struct MerkleTree {
    leaves: Vec<Digest>,
}

impl MerkleTree {
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a leaf (raw data, hashed here) and returns its index.
    pub fn push(&mut self, data: &[u8]) -> u64 {
        self.leaves.push(leaf_hash(data));
        (self.leaves.len() - 1) as u64
    }

    pub fn size(&self) -> u64 {
        self.leaves.len() as u64
    }

    pub fn leaf(&self, index: u64) -> Option<Digest> {
        self.leaves.get(usize::try_from(index).ok()?).copied()
    }

    pub fn root(&self) -> Digest {
        root_hash(&self.leaves)
    }

    /// Audit path for `index` in the tree of the first `tree_size` leaves.
    pub fn inclusion_proof(&self, index: u64, tree_size: u64) -> Option<Vec<Digest>> {
        let (m, n) = (
            usize::try_from(index).ok()?,
            usize::try_from(tree_size).ok()?,
        );
        if m >= n || n > self.leaves.len() {
            return None;
        }
        let mut out = Vec::new();
        path(m, &self.leaves[..n], &mut out);
        Some(out)
    }
}

/// RFC 9162 §2.1.3.2: verify that `leaf` is at `index` in a tree of
/// `tree_size` leaves with root `root`.
pub fn verify_inclusion(
    leaf: &Digest,
    index: u64,
    tree_size: u64,
    proof: &[Digest],
    root: &Digest,
) -> bool {
    if index >= tree_size {
        return false;
    }
    let (mut fn_, mut sn) = (index, tree_size - 1);
    let mut r = *leaf;
    for p in proof {
        if sn == 0 {
            return false;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            r = node_hash(p, &r);
            while fn_ & 1 == 0 && fn_ != 0 {
                fn_ >>= 1;
                sn >>= 1;
            }
        } else {
            r = node_hash(&r, p);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    sn == 0 && r == *root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(n: usize) -> MerkleTree {
        let mut t = MerkleTree::new();
        for i in 0..n {
            t.push(format!("leaf-{i}").as_bytes());
        }
        t
    }

    #[test]
    fn known_answers() {
        assert_eq!(
            root_hash(&[]).to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let a = leaf_hash(b"a");
        let b = leaf_hash(b"b");
        let c = leaf_hash(b"c");
        assert_eq!(root_hash(&[a]), a);
        // Size 3 splits 2 + 1.
        assert_eq!(root_hash(&[a, b, c]), node_hash(&node_hash(&a, &b), &c));
    }

    #[test]
    fn inclusion_proofs_for_sizes_1_to_20() {
        for n in 1..=20u64 {
            let t = tree(n as usize);
            let root = t.root();
            for m in 0..n {
                let leaf = t.leaf(m).unwrap();
                let proof = t.inclusion_proof(m, n).unwrap();
                assert!(verify_inclusion(&leaf, m, n, &proof, &root), "n={n} m={m}");

                // Every other index, size, root or proof must be rejected.
                if n > 1 {
                    let other = (m + 1) % n;
                    assert!(!verify_inclusion(&leaf, other, n, &proof, &root));
                    assert!(!verify_inclusion(
                        &t.leaf(other).unwrap(),
                        m,
                        n,
                        &proof,
                        &root
                    ));
                    let mut bad = proof.clone();
                    bad[0].0[0] ^= 1;
                    assert!(!verify_inclusion(&leaf, m, n, &bad, &root));
                    assert!(!verify_inclusion(&leaf, m, n, &proof[1..], &root));
                }
                assert!(!verify_inclusion(&leaf, m, n, &proof, &leaf_hash(b"x")));
            }
            // Proofs against an older tree head still verify against its root.
            for size in 1..=n {
                let old_root = root_hash(&t.leaves[..size as usize]);
                let proof = t.inclusion_proof(size - 1, size).unwrap();
                assert!(verify_inclusion(
                    &t.leaf(size - 1).unwrap(),
                    size - 1,
                    size,
                    &proof,
                    &old_root
                ));
            }
            assert!(t.inclusion_proof(n, n).is_none());
        }
    }
}
