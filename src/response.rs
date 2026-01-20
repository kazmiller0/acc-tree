use crate::{Hash, proof::Proof};
use accumulator_ads::{G1Affine, MembershipProof, Set, digest_set_from_set};

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
    /// found fids if present
    pub fids: Option<Set<String>>,
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
        fids: Option<Set<String>>,
        proof: Option<Proof>,
        root_hash: Option<Hash>,
        accumulator: Option<G1Affine>,
        membership_witness: Option<G1Affine>,
        nonmembership: Option<NonMembershipProof>,
    ) -> Self {
        Self {
            fids,
            proof,
            root_hash,
            accumulator,
            membership_witness,
            nonmembership,
        }
    }

    /// Verify both the Merkle path (leaf correctness) and the accumulator membership witness.
    /// Returns true only if both checks pass. Requires the original `key` and `fids` used
    /// to build the leaf hash.
    pub fn verify_full(&self, key: &str, fids: &Set<String>) -> bool {
        // verify Merkle path using provided key/fids (prevents leaf tampering)
        let merkle_ok = match (&self.root_hash, &self.proof) {
            (Some(_root), Some(p)) => p.verify_with_kv(key, fids),
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
    /// fids inserted
    pub fids: Set<String>,
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
        fids: Set<String>,
        pre_roots: Vec<(Hash, G1Affine)>,
        post_root_hash: Option<Hash>,
        post_accumulator: Option<G1Affine>,
        post_proof: Option<Proof>,
        post_membership_witness: Option<G1Affine>,
        pre_nonmembership: Option<NonMembershipProof>,
    ) -> Self {
        Self {
            key,
            fids,
            pre_roots,
            post_root_hash,
            post_accumulator,
            post_proof,
            post_membership_witness,
            pre_nonmembership,
        }
    }

    /// Verify that the insertion was well-formed.
    /// Checks:
    /// 1. Pre-insertion non-membership proof validates (if present)
    /// 2. Post-insertion Merkle proof validates
    /// 3. Post-insertion accumulator membership holds
    /// 4. Post-proof matches the inserted key and FID set
    pub fn verify_insert(&self) -> bool {
        // 1. Verify pre-insertion non-membership proof (if present)
        if let Some(nm_proof) = &self.pre_nonmembership {
            if !nm_proof.verify(&self.key) {
                return false; // Key was already in tree before insertion
            }
        }

        // 2. Verify post-insertion Merkle proof
        if let Some(post_p) = &self.post_proof {
            if !post_p.verify() {
                return false;
            }
            // Verify the post-proof matches the inserted key and FID set
            if !post_p.verify_with_kv(&self.key, &self.fids) {
                return false;
            }
        } else {
            return false; // Post-proof must be present
        }

        // 3. Verify accumulator membership for post-state
        if let (Some(acc), Some(w)) = (&self.post_accumulator, &self.post_membership_witness) {
            if !verify_membership(acc, w, &self.key) {
                return false;
            }
        } else {
            return false; // Post accumulator and witness must be present
        }

        true
    }
}

#[derive(Debug, Clone)]
pub struct UpdateResponse {
    /// key where the FID was updated
    pub key: String,
    /// the specific old FID that was replaced
    pub old_fid: String,
    /// the new FID that replaced the old one
    pub new_fid: String,
    /// complete FID set before update
    pub old_fids: Option<Set<String>>,
    /// complete FID set after update
    pub new_fids: Set<String>,
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
        old_fid: String,
        new_fid: String,
        old_fids: Option<Set<String>>,
        new_fids: Set<String>,
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
            old_fids,
            new_fids,
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

    /// Verify that the update was well-formed: validates that a specific FID was replaced.
    /// Checks:
    /// 1. The old_fid existed in the old FID set
    /// 2. The new FID set = old FID set - old_fid + new_fid
    /// 3. Merkle proofs validate (pre and post)
    /// 4. Sibling paths match (only leaf content changed, not structure)
    /// 5. Accumulator membership holds for the key in both states
    pub fn verify_update(&self) -> bool {
        // 1. Verify the old_fid was in the old set
        if let Some(old) = &self.old_fids {
            if !old.contains(&self.old_fid) {
                return false; // old_fid wasn't there to begin with
            }

            // 2. Verify new_fids = (old_fids - old_fid) + new_fid
            let expected_new = old
                .difference(&Set::from_vec(vec![self.old_fid.clone()]))
                .union(&Set::from_vec(vec![self.new_fid.clone()]));
            if self.new_fids != expected_new {
                return false; // Incorrect FID set transition
            }
        } else {
            return false; // No old FIDs means nothing to update
        }

        // 3. Verify pre proof if present
        if let Some(pre_p) = &self.pre_proof {
            if !pre_p.verify() {
                return false;
            }
            // Also verify the pre-proof matches the old FID set
            if let Some(old) = &self.old_fids {
                if !pre_p.verify_with_kv(&self.key, old) {
                    return false;
                }
            }
        }

        // 4. Verify post proof
        if !self.post_proof.verify() {
            return false;
        }
        // Verify post-proof matches the new FID set
        if !self.post_proof.verify_with_kv(&self.key, &self.new_fids) {
            return false;
        }

        // 5. Sibling paths should match between pre and post (structure unchanged)
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

        // 6. Verify accumulator membership for both pre and post states
        if let (Some(acc), Some(w)) = (&self.pre_accumulator, &self.pre_membership_witness) {
            if !verify_membership(acc, w, &self.key) {
                return false;
            }
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
    /// key from which the FID was deleted
    pub key: String,
    /// the specific FID that was deleted
    pub deleted_fid: String,
    /// complete FID set before deletion
    pub old_fids: Option<Set<String>>,
    /// FID set after deletion (empty if leaf is now tombstoned, or remaining FIDs)
    pub new_fids: Set<String>,
    /// membership proof for the leaf before deletion
    pub pre_proof: Option<Proof>,
    /// accumulator value before deletion (for the root containing the key)
    pub pre_accumulator: Option<G1Affine>,
    /// membership witness for the old element
    pub pre_membership_witness: Option<G1Affine>,
    /// merkle/path proof for the leaf after deletion
    pub post_proof: Proof,
    /// accumulator value after deletion for the root containing the key
    pub post_accumulator: G1Affine,
    /// root hash before deletion (if available)
    pub pre_root_hash: Option<Hash>,
    /// root hash after deletion
    pub post_root_hash: Hash,
}

impl DeleteResponse {
    pub fn new(
        key: String,
        deleted_fid: String,
        old_fids: Option<Set<String>>,
        new_fids: Set<String>,
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
            deleted_fid,
            old_fids,
            new_fids,
            pre_proof,
            pre_accumulator: pre_acc,
            pre_membership_witness: pre_acc_witness,
            post_proof,
            post_accumulator: post_acc,
            pre_root_hash,
            post_root_hash,
        }
    }

    /// Verify deletion: validates that a specific FID was removed from the key's FID set.
    /// Checks:
    /// 1. The deleted FID existed in the old FID set
    /// 2. The new FID set = old FID set - deleted FID
    /// 3. Merkle proofs validate (pre and post)
    /// 4. Sibling paths match (only leaf content changed, not structure)
    /// 5. Accumulator membership holds for the key in pre-state
    /// 6. Post-state hash matches the new FID set (or empty_hash if tombstoned)
    pub fn verify_delete(&self) -> bool {
        // 1. Verify the deleted FID was in the old set
        if let Some(old) = &self.old_fids {
            if !old.contains(&self.deleted_fid) {
                return false; // FID wasn't there to begin with
            }

            // 2. Verify new_fids = old_fids - deleted_fid
            let expected_new = old.difference(&Set::from_vec(vec![self.deleted_fid.clone()]));
            if self.new_fids != expected_new {
                return false; // Incorrect FID set transition
            }
        } else {
            return false; // No old FIDs means nothing to delete
        }

        // 3. Verify pre proof if present
        if let Some(pre_p) = &self.pre_proof {
            if !pre_p.verify() {
                return false;
            }
            // Also verify the pre-proof matches the old FID set
            if let Some(old) = &self.old_fids {
                if !pre_p.verify_with_kv(&self.key, old) {
                    return false;
                }
            }
        }

        // 4. Verify post proof
        if !self.post_proof.verify() {
            return false;
        }
        // Verify post-proof matches the new FID set
        if !self.post_proof.verify_with_kv(&self.key, &self.new_fids) {
            return false;
        }

        // 5. Sibling paths should match between pre and post (structure unchanged)
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

        // 6. Verify accumulator membership for pre-state (key was in tree)
        if let (Some(acc), Some(w)) = (&self.pre_accumulator, &self.pre_membership_witness) {
            if !verify_membership(acc, w, &self.key) {
                return false;
            }
        }

        true
    }
}

/// Unit tests for response structures
///
/// These tests verify the basic construction and validation logic of response types.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::leaf_hash_fids;
    use std::sync::Once;

    static INIT: Once = Once::new();

    fn init_test_params() {
        INIT.call_once(|| {
            use accumulator_ads::acc::setup::{PublicParameters, init_public_parameters_direct};
            use ark_bls12_381::Fr;
            let secret_s = Fr::from(123456789u128);
            let params = PublicParameters::generate_for_testing(secret_s, 50);
            init_public_parameters_direct(params).expect("Failed to initialize");
        });
    }

    #[test]
    fn test_query_response_construction() {
        init_test_params();
        let fids = Set::from_vec(vec!["fid1".to_string()]);
        let qr = QueryResponse::new(Some(fids.clone()), None, None, None, None, None);

        assert_eq!(qr.fids, Some(fids));
        assert!(qr.proof.is_none());
        assert!(qr.nonmembership.is_none());
    }

    #[test]
    fn test_query_response_verify_full_fails_without_proof() {
        init_test_params();
        let fids = Set::from_vec(vec!["fid1".to_string()]);
        let qr = QueryResponse::new(Some(fids.clone()), None, None, None, None, None);

        assert!(!qr.verify_full("key", &fids));
    }

    #[test]
    fn test_insert_response_construction() {
        init_test_params();
        let fids = Set::from_vec(vec!["fid1".to_string()]);
        let resp = InsertResponse::new(
            "key1".to_string(),
            fids.clone(),
            vec![],
            None,
            None,
            None,
            None,
            None,
        );

        assert_eq!(resp.key, "key1");
        assert_eq!(resp.fids, fids);
        assert!(resp.pre_roots.is_empty());
    }

    #[test]
    fn test_update_response_verify_fails_with_mismatched_paths() {
        init_test_params();
        use crate::crypto::empty_hash;

        let old_fids = Set::from_vec(vec!["old".to_string()]);
        let new_fids = Set::from_vec(vec!["new".to_string()]);
        let other_fids = Set::from_vec(vec!["other".to_string()]);

        let pre_proof = Proof::new(
            empty_hash(),
            leaf_hash_fids("key", &old_fids),
            vec![(empty_hash(), true)],
        );

        let post_proof = Proof::new(
            empty_hash(),
            leaf_hash_fids("key", &new_fids),
            vec![(leaf_hash_fids("other", &other_fids), true)], // Different sibling
        );

        let resp = UpdateResponse::new(
            "key".to_string(),
            "old".to_string(),
            "new".to_string(),
            Some(old_fids),
            new_fids,
            Some(pre_proof),
            Some(crate::crypto::empty_acc()), // pre_acc
            Some(crate::crypto::empty_acc()), // pre_acc_witness
            post_proof,
            crate::crypto::empty_acc(),
            crate::crypto::empty_acc(),
            None,
            empty_hash(),
        );

        // Should fail because sibling hashes don't match
        assert!(!resp.verify_update());
    }

    #[test]
    fn test_delete_response_construction() {
        init_test_params();
        use crate::crypto::empty_hash;

        let post_proof = Proof::new(empty_hash(), empty_hash(), vec![]);
        let old_fids = Set::from_vec(vec!["fid1".to_string()]);

        let resp = DeleteResponse::new(
            "key1".to_string(),
            "fid1".to_string(),
            Some(old_fids.clone()),
            Set::new(),
            None,
            None,
            None,
            post_proof,
            crate::crypto::empty_acc(),
            None,
            empty_hash(),
        );

        assert_eq!(resp.key, "key1");
        assert_eq!(resp.old_fids, Some(old_fids));
    }

    #[test]
    fn test_delete_response_verify_post_proof() {
        init_test_params();
        use crate::crypto::empty_hash;

        // Valid single-leaf proof
        let post_proof = Proof::new(empty_hash(), empty_hash(), vec![]);
        let old_fids = Set::from_vec(vec!["fid1".to_string()]);

        let resp = DeleteResponse::new(
            "key1".to_string(),
            "fid1".to_string(),
            Some(old_fids),
            Set::new(),
            None,
            None,
            None,
            post_proof,
            crate::crypto::empty_acc(),
            None,
            empty_hash(),
        );

        // Should pass basic verification
        assert!(resp.verify_delete());
    }

    #[test]
    fn test_nonmembership_proof_verify_key_mismatch() {
        init_test_params();
        use accumulator_ads::Set;

        let all_keys = Set::from_vec(vec!["a".to_string(), "b".to_string()]);
        let acc = {
            use accumulator_ads::DynamicAccumulator;
            let digest_set = digest_set_from_set(&all_keys);
            DynamicAccumulator::calculate_commitment(&digest_set)
        };

        if let Some(nm_proof) = NonMembershipProof::new("z".to_string(), acc, &all_keys) {
            // Should fail if we check with wrong key
            assert!(!nm_proof.verify("wrong_key"));
            // Should pass with correct key
            assert!(nm_proof.verify("z"));
        }
    }

    #[test]
    fn test_nonmembership_proof_fails_for_existing_key() {
        init_test_params();
        use accumulator_ads::Set;

        let all_keys = Set::from_vec(vec!["a".to_string(), "b".to_string()]);
        let acc = {
            use accumulator_ads::DynamicAccumulator;
            let digest_set = digest_set_from_set(&all_keys);
            DynamicAccumulator::calculate_commitment(&digest_set)
        };

        // Should return None when trying to prove non-membership for existing key
        let result = NonMembershipProof::new("a".to_string(), acc, &all_keys);
        assert!(result.is_none());
    }
}
