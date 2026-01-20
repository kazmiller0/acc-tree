use crate::{Hash, proof::Proof};
use accumulator_ads::{G1Affine, MembershipProof, digest_set_from_set};

/// Non-membership proof using cryptographic accumulator
/// This proves that a key is NOT in the accumulated set using Bézout coefficients
#[derive(Debug, Clone)]
pub struct NonMembershipProof {
    /// The key being proved as non-member
    pub key: String,
    /// The accumulator value of the tree (all keys)
    pub accumulator: G1Affine,
    /// The underlying cryptographic non-membership proof from accumulator_ads
    pub acc_proof: accumulator_ads::NonMembershipProof,
}

impl NonMembershipProof {
    /// Create a new non-membership proof for a key against the given set
    pub fn new(
        key: String,
        accumulator: G1Affine,
        all_keys_set: &accumulator_ads::Set<String>,
    ) -> Option<Self> {
        use accumulator_ads::acc::utils::digest_to_prime_field;
        use accumulator_ads::digest::Digestible;

        // Convert key to field element
        let key_digest = key.to_digest();
        let key_elem = digest_to_prime_field(&key_digest);

        // Convert all keys to digest set
        let digest_set = digest_set_from_set(all_keys_set);

        // Generate cryptographic non-membership proof using Bézout coefficients
        match accumulator_ads::NonMembershipProof::new(key_elem, &digest_set) {
            Ok(acc_proof) => Some(Self {
                key,
                accumulator,
                acc_proof,
            }),
            Err(_) => None, // Key is in the set, cannot create non-membership proof
        }
    }

    /// Verify the non-membership proof
    /// Returns true if the key is proven to NOT be in the accumulated set
    pub fn verify(&self, expected_key: &str) -> bool {
        // Verify the key matches
        if self.key != expected_key {
            return false;
        }

        // Verify the cryptographic non-membership proof
        // This checks: A(s)*P(s) + B(s)*(s-x) = 1 using pairings
        self.acc_proof.verify(self.accumulator)
    }
}

/// Helper function to verify membership using accumulator_ads MembershipProof
/// This delegates all cryptographic verification logic to the underlying library,
/// following DRY principle and ensuring consistency.
fn verify_membership(acc: &G1Affine, witness: &G1Affine, key: &String) -> bool {
    use accumulator_ads::acc::utils::digest_to_prime_field;
    use accumulator_ads::digest::Digestible;

    // Convert key to field element
    let key_digest = key.to_digest();
    let key_fr = digest_to_prime_field(&key_digest);

    // Create membership proof and verify using accumulator_ads
    let proof = MembershipProof {
        witness: *witness,
        element: key_fr,
    };

    proof.verify(*acc)
}

#[derive(Debug, Clone)]
pub struct QueryResponse {
    /// found fid if present
    pub fid: Option<String>,
    /// membership proof for the found leaf (if any)
    pub proof: Option<Proof>,
    /// root hash of the subtree used to produce the proof
    pub root_hash: Option<Hash>,
    /// accumulator value (G1Affine) for the subtree's keys
    pub accumulator: Option<G1Affine>,
    /// membership witness (G1Affine) for the element in the subtree's accumulator
    pub membership_witness: Option<G1Affine>,
    /// non-membership proof when the key is not found
    pub nonmembership: Option<NonMembershipProof>,
}

impl QueryResponse {
    pub fn new(
        fid: Option<String>,
        proof: Option<Proof>,
        root_hash: Option<Hash>,
        accumulator: Option<G1Affine>,
        membership_witness: Option<G1Affine>,
        nonmembership: Option<NonMembershipProof>,
    ) -> Self {
        Self {
            fid,
            proof,
            root_hash,
            accumulator,
            membership_witness,
            nonmembership,
        }
    }

    /// Verify both the Merkle path (leaf correctness) and the accumulator membership witness.
    /// Returns true only if both checks pass. Requires the original `key` and `fid` used
    /// to build the leaf hash.
    pub fn verify_full(&self, key: &str, fid: &str) -> bool {
        // verify Merkle path using provided key/fid (prevents leaf tampering)
        let merkle_ok = match (&self.root_hash, &self.proof) {
            (Some(_root), Some(p)) => p.verify_with_kv(key, fid),
            _ => false,
        };
        if !merkle_ok {
            return false;
        }

        // verify accumulator membership: acc + element_commitment == acc (via witness)
        match (&self.accumulator, &self.membership_witness) {
            (Some(acc), Some(witness)) => verify_membership(acc, witness, &key.to_string()),
            _ => false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct InsertResponse {
    /// key inserted
    pub key: String,
    /// fid inserted
    pub fid: String,
    /// snapshot of roots before insertion: vector of (root_hash, acc)
    pub pre_roots: Vec<(Hash, G1Affine)>,
    /// snapshot of root hash after insertion (the root that contains the inserted key)
    pub post_root_hash: Option<Hash>,
    /// accumulator value after insertion for the root containing the key
    pub post_accumulator: Option<G1Affine>,
    /// merkle/path proof for the inserted leaf after insertion
    pub post_proof: Option<Proof>,
    /// membership witness for the inserted element in the post_accumulator
    pub post_membership_witness: Option<G1Affine>,
    /// optional non-membership proof captured before insertion
    pub pre_nonmembership: Option<NonMembershipProof>,
}

impl InsertResponse {
    pub fn new(
        key: String,
        fid: String,
        pre_roots: Vec<(Hash, G1Affine)>,
        post_root_hash: Option<Hash>,
        post_accumulator: Option<G1Affine>,
        post_proof: Option<Proof>,
        post_membership_witness: Option<G1Affine>,
        pre_nonmembership: Option<NonMembershipProof>,
    ) -> Self {
        Self {
            key,
            fid,
            pre_roots,
            post_root_hash,
            post_accumulator,
            post_proof,
            post_membership_witness,
            pre_nonmembership,
        }
    }
}

#[derive(Debug, Clone)]
pub struct UpdateResponse {
    /// key updated
    pub key: String,
    /// fid before update
    pub old_fid: Option<String>,
    /// fid after update
    pub new_fid: String,
    /// membership proof for the leaf before update
    pub pre_proof: Option<Proof>,
    /// accumulator value before update (for the root containing the key)
    pub pre_accumulator: Option<G1Affine>,
    /// membership witness for the old element
    pub pre_membership_witness: Option<G1Affine>,
    /// membership proof for the leaf after update
    pub post_proof: Proof,
    /// accumulator value after update (for the root containing the key)
    pub post_accumulator: G1Affine,
    /// membership witness for the new element
    pub post_membership_witness: G1Affine,
    /// root hash before update (if available)
    pub pre_root_hash: Option<Hash>,
    /// root hash after update
    pub post_root_hash: Hash,
}

impl UpdateResponse {
    pub fn new(
        key: String,
        old_fid: Option<String>,
        new_fid: String,
        pre_proof: Option<Proof>,
        pre_acc: Option<G1Affine>,
        pre_acc_witness: Option<G1Affine>,
        post_proof: Proof,
        post_acc: G1Affine,
        post_acc_witness: G1Affine,
        pre_root_hash: Option<Hash>,
        post_root_hash: Hash,
    ) -> Self {
        Self {
            key,
            old_fid,
            new_fid,
            pre_proof,
            pre_accumulator: pre_acc,
            pre_membership_witness: pre_acc_witness,
            post_proof,
            post_accumulator: post_acc,
            post_membership_witness: post_acc_witness,
            pre_root_hash,
            post_root_hash,
        }
    }

    /// Verify that the update was well-formed: pre/post proofs are valid and the
    /// Merkle path siblings match (i.e. only the leaf changed), and accumulator
    /// membership holds for old/new values respectively when provided.
    pub fn verify_update(&self) -> bool {
        // verify pre proof if present
        if let Some(pre_p) = &self.pre_proof
            && !pre_p.verify()
        {
            return false;
        }

        // verify post proof
        if !self.post_proof.verify() {
            return false;
        }

        // sibling paths (excluding leaf_hash) should match between pre and post
        if let Some(pre_p) = &self.pre_proof {
            if pre_p.path.len() != self.post_proof.path.len() {
                return false;
            }
            for (i, (psib, pleft)) in pre_p.path.iter().enumerate() {
                let (qsib, qleft) = &self.post_proof.path[i];
                if psib != qsib || pleft != qleft {
                    return false;
                }
            }
        }

        // verify accumulator membership: pre (old) and post (new)
        if let (Some(acc), Some(w)) = (&self.pre_accumulator, &self.pre_membership_witness)
            && let Some(_old) = &self.old_fid
            && !verify_membership(acc, w, &self.key)
        {
            return false;
        }

        if !verify_membership(
            &self.post_accumulator,
            &self.post_membership_witness,
            &self.key,
        ) {
            return false;
        }

        true
    }
}

#[derive(Debug, Clone)]
pub struct DeleteResponse {
    /// key deleted
    pub key: String,
    /// fid before deletion
    pub old_fid: Option<String>,
    /// membership proof for the leaf before deletion
    pub pre_proof: Option<Proof>,
    /// accumulator value before deletion (for the root containing the key)
    pub pre_accumulator: Option<G1Affine>,
    /// membership witness for the old element
    pub pre_membership_witness: Option<G1Affine>,
    /// merkle/path proof for the tombstoned leaf after deletion (leaf hash will be empty_hash)
    pub post_proof: Proof,
    /// accumulator value after deletion for the root containing the tombstone
    pub post_accumulator: G1Affine,
    /// root hash before deletion (if available)
    pub pre_root_hash: Option<Hash>,
    /// root hash after deletion
    pub post_root_hash: Hash,
}

impl DeleteResponse {
    pub fn new(
        key: String,
        old_fid: Option<String>,
        pre_proof: Option<Proof>,
        pre_acc: Option<G1Affine>,
        pre_acc_witness: Option<G1Affine>,
        post_proof: Proof,
        post_acc: G1Affine,
        pre_root_hash: Option<Hash>,
        post_root_hash: Hash,
    ) -> Self {
        Self {
            key,
            old_fid,
            pre_proof,
            pre_accumulator: pre_acc,
            pre_membership_witness: pre_acc_witness,
            post_proof,
            post_accumulator: post_acc,
            pre_root_hash,
            post_root_hash,
        }
    }

    /// Verify deletion: pre/post proofs validate and sibling paths match (only leaf changed),
    /// and pre-acc membership holds for the deleted key when provided.
    pub fn verify_delete(&self) -> bool {
        // verify pre proof if present
        if let Some(pre_p) = &self.pre_proof
            && !pre_p.verify()
        {
            return false;
        }

        // verify post proof
        if !self.post_proof.verify() {
            return false;
        }

        // sibling paths should match between pre and post
        if let Some(pre_p) = &self.pre_proof {
            if pre_p.path.len() != self.post_proof.path.len() {
                return false;
            }
            for (i, (psib, pleft)) in pre_p.path.iter().enumerate() {
                let (qsib, qleft) = &self.post_proof.path[i];
                if psib != qsib || pleft != qleft {
                    return false;
                }
            }
        }

        // verify accumulator membership for pre-state (old element)
        if let (Some(acc), Some(w)) = (&self.pre_accumulator, &self.pre_membership_witness)
            && let Some(_old) = &self.old_fid
            && !verify_membership(acc, w, &self.key)
        {
            return false;
        }

        true
    }
}
