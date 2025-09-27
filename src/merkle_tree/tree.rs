use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq)]
#[serde(rename_all = "lowercase")] // ensures "left"/"right" in JSON
pub enum Position {
    Left,
    Right,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProofStep {
    pub hash: String,       // Hex string
    pub position: Position, // Left or Right
}

pub fn hash_pair(left: &[u8], right: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

pub fn build_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }

    let mut level: Vec<[u8; 32]> = leaves.to_vec(); // clone once to be able to mutate
    while level.len() > 1 {
        let mut next = Vec::new();
        for chunk in level.chunks(2) {
            if chunk.len() == 2 {
                next.push(hash_pair(&chunk[0], &chunk[1]));
            } else {
                // odd number of leaves: promote last
                next.push(chunk[0]);
            }
        }
        level = next;
    }
    level[0]
}

pub fn merkle_proof(leaves: &[[u8; 32]], index: usize) -> Vec<ProofStep> {
    let mut proof = Vec::new();
    let mut idx = index;
    let mut current_level: Vec<[u8; 32]> = leaves.to_vec();

    while current_level.len() > 1 {
        let mut next_level = Vec::new();

        for (pair_index, pair) in current_level.chunks(2).enumerate() {
            if pair.len() == 2 {
                let left = pair[0];
                let right = pair[1];

                // does this pair contain our target? If not, it shouldn't be in the proof
                if idx / 2 == pair_index {
                    if idx % 2 == 0 && idx < current_level.len() - 1 {
                        // target is left, sibling is right
                        proof.push(ProofStep {
                            hash: hex::encode(right),
                            position: Position::Right,
                        });
                    } else if idx % 2 == 1 {
                        // target is right, sibling is left
                        proof.push(ProofStep {
                            hash: hex::encode(left),
                            position: Position::Left,
                        });
                    }
                }

                next_level.push(hash_pair(&left, &right));
            } else {
                // odd node promoted
                next_level.push(pair[0]);
            }
        }

        idx /= 2;
        current_level = next_level;
    }

    proof
}

pub fn verify_proof(leaf: [u8; 32], root: [u8; 32], proof: &[ProofStep]) -> bool {
    let mut computed = leaf;

    for step in proof {
        let sibling = hex::decode(&step.hash).unwrap();
        match step.position {
            Position::Left => {
                computed = hash_pair(&sibling, &computed);
            }
            Position::Right => {
                computed = hash_pair(&computed, &sibling);
            }
        }
    }

    computed == root
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn hash_str(s: &str) -> [u8; 32] {
        Sha256::digest(s.as_bytes()).into()
    }

    #[test]
    fn test_hash_pair_consistency() {
        let a: [u8; 32] = Sha256::digest(b"a").into();
        let b: [u8; 32] = Sha256::digest(b"b").into();

        // Compute with hash_pair
        let combined = hash_pair(&a, &b);

        // Compute manually using sha2 directly
        let mut hasher = Sha256::new();
        hasher.update(a);
        hasher.update(b);
        let expected: [u8; 32] = hasher.finalize().into();

        assert_eq!(
            combined, expected,
            "hash_pair should equal direct SHA256(a||b)"
        );
    }

    #[test]
    fn test_root_with_single_leaf() {
        let leaves = vec![hash_str("a")];
        let root = build_merkle_root(&leaves);
        assert_eq!(
            root, leaves[0],
            "Root of single leaf tree should equal the leaf"
        );
        assert_eq!(
            "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
            hex::encode(root)
        )
    }

    #[test]
    fn test_root_with_two_leaves() {
        let leaves = vec![hash_str("a"), hash_str("b")];
        let root = build_merkle_root(&leaves);

        let expected = hash_pair(&leaves[0], &leaves[1]);
        assert_eq!(root, expected, "Root of 2-leaf tree should be hash(a||b)");
        assert_eq!(
            "e5a01fee14e0ed5c48714f22180f25ad8365b53f9779f79dc4a3d7e93963f94a",
            hex::encode(root)
        )
    }

    #[test]
    fn test_proof_verification_all_indices() {
        let leaves: Vec<[u8; 32]> = ["a", "b", "c", "d", "e", "f", "g"]
            .iter()
            .map(|x| hash_str(x))
            .collect();

        let root = build_merkle_root(&leaves);

        for (i, leaf) in leaves.iter().enumerate() {
            let proof = merkle_proof(&leaves, i);
            assert!(
                verify_proof(*leaf, root, &proof),
                "Proof failed for index {}",
                i
            );
        }
    }

    #[test]
    fn test_specific_proof_steps() {
        let leaves: Vec<[u8; 32]> = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"]
            .iter()
            .map(|x| hash_str(x))
            .collect();

        let root = build_merkle_root(&leaves);

        // Proof for "e" is:
        // f: right
        // gh: right
        // ab-cd: left
        // ij: right
        let proof = merkle_proof(&leaves, 4);
        let mut expected: Vec<ProofStep> = Vec::new();
        expected.push(ProofStep {
            hash: hex::encode(hash_str("f")),
            position: Position::Right,
        });
        expected.push(ProofStep {
            hash: hex::encode(hash_pair(
                hash_str("g").as_slice(),
                hash_str("h").as_slice(),
            )),
            position: Position::Right,
        });
        expected.push(ProofStep {
            hash: hex::encode(hash_pair(
                hash_pair(hash_str("a").as_slice(), hash_str("b").as_slice()).as_slice(),
                hash_pair(hash_str("c").as_slice(), hash_str("d").as_slice()).as_slice(),
            )),
            position: Position::Left,
        });
        expected.push(ProofStep {
            hash: hex::encode(hash_pair(
                hash_str("i").as_slice(),
                hash_str("j").as_slice(),
            )),
            position: Position::Right,
        });

        for (i, step) in proof.iter().enumerate() {
            let proof_hash = step.hash.clone();
            let proof_position = step.position;

            assert_eq!(proof_hash, expected[i].hash);
            assert_eq!(proof_position, expected[i].position);
        }

        // Proof for "j" is:
        // i: left
        // abcd-efgh: left
        let proof = merkle_proof(&leaves, 9);
        let mut expected: Vec<ProofStep> = Vec::new();
        expected.push(ProofStep {
            hash: hex::encode(hash_str("i")),
            position: Position::Left,
        });
        expected.push(ProofStep {
            hash: hex::encode(hash_pair(
                hash_pair(
                    hash_pair(hash_str("a").as_slice(), hash_str("b").as_slice()).as_slice(),
                    hash_pair(hash_str("c").as_slice(), hash_str("d").as_slice()).as_slice(),
                )
                .as_slice(),
                hash_pair(
                    hash_pair(hash_str("e").as_slice(), hash_str("f").as_slice()).as_slice(),
                    hash_pair(hash_str("g").as_slice(), hash_str("h").as_slice()).as_slice(),
                )
                .as_slice(),
            )),
            position: Position::Left,
        });

        // Proof for "b" is:
        // a: left
        // cd: right
        // ef-gh: right
        // ij: right
        let proof = merkle_proof(&leaves, 1);
        let mut expected: Vec<ProofStep> = Vec::new();
        expected.push(ProofStep {
            hash: hex::encode(hash_str("a")),
            position: Position::Left,
        });
        expected.push(ProofStep {
            hash: hex::encode(hash_pair(
                hash_str("c").as_slice(),
                hash_str("d").as_slice(),
            )),
            position: Position::Right,
        });
        expected.push(ProofStep {
            hash: hex::encode(hash_pair(
                hash_pair(hash_str("e").as_slice(), hash_str("f").as_slice()).as_slice(),
                hash_pair(hash_str("g").as_slice(), hash_str("h").as_slice()).as_slice(),
            )),
            position: Position::Right,
        });
        expected.push(ProofStep {
            hash: hex::encode(hash_pair(
                hash_str("i").as_slice(),
                hash_str("j").as_slice(),
            )),
            position: Position::Right,
        });

        for (i, step) in proof.iter().enumerate() {
            let proof_hash = step.hash.clone();
            let proof_position = step.position;

            assert_eq!(proof_hash, expected[i].hash);
            assert_eq!(proof_position, expected[i].position);
        }
    }

    #[test]
    fn test_invalid_proof_fails() {
        let leaves: Vec<[u8; 32]> = ["a", "b", "c"].iter().map(|x| hash_str(x)).collect();
        let root = build_merkle_root(&leaves);

        // make a valid proof for "a"
        let mut proof = merkle_proof(&leaves, 0);

        // corrupt the first step hash
        proof[0].hash = hex::encode([0u8; 32]);

        assert!(
            !verify_proof(leaves[0], root, &proof),
            "Corrupted proof should not verify"
        );
    }
}
