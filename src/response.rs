use crate::Hash;
use crate::acc_proof::{AccProof, MembershipProof, NonMembershipProof};
use crate::merkle_proof::Proof as MerkleProof;
use accumulator_ads::{G1Affine, Set};

#[derive(Debug, Clone)]
pub struct QueryResponse {
    /// found fids if present
    pub fids: Option<Set<String>>,
    /// Merkle proof for the found leaf (if any)
    pub merkle_proof: Option<MerkleProof>,
    /// Accumulator info (acc value)
    pub accumulator: Option<G1Affine>,
    /// Accumulator proof (Membership or NonMembership)
    pub acc_proof: Option<AccProof>,
}

impl QueryResponse {
    pub fn new(
        fids: Option<Set<String>>,
        merkle_proof: Option<MerkleProof>,
        accumulator: Option<G1Affine>,
        acc_proof: Option<AccProof>,
    ) -> Self {
        Self {
            fids,
            merkle_proof,
            accumulator,
            acc_proof,
        }
    }

    /// Get root hash from the proof (if present)
    pub fn root_hash(&self) -> Option<Hash> {
        self.merkle_proof.as_ref().map(|p| p.root_hash)
    }

    /// Verify both the Merkle path (leaf correctness) and the accumulator membership witness.
    /// Returns true only if both checks pass. Requires the original `key` and `fids` used
    /// to build the leaf hash.
    pub fn verify_full(&self, key: &str, fids: &Set<String>) -> bool {
        // verify Merkle path using provided key/fids (prevents leaf tampering)
        let merkle_ok = match &self.merkle_proof {
            Some(p) => p.verify_with_kv(key, fids),
            _ => false,
        };
        if !merkle_ok {
            return false;
        }

        // verify accumulator membership
        if let (Some(_acc), Some(AccProof::NonMembership(kp))) =
            (&self.accumulator, &self.acc_proof)
        {
            return kp.verify(key);
        }

        match (&self.accumulator, &self.acc_proof) {
            (Some(acc), Some(AccProof::Membership(mp))) => mp.verify(acc, key),
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
    /// accumulator value after insertion for the root containing the key
    pub post_accumulator: Option<G1Affine>,
    /// Merkle proof for the inserted leaf after insertion
    pub post_merkle_proof: Option<MerkleProof>,
    /// Acc membership proof for the inserted element in the post_accumulator
    pub post_acc_proof: Option<MembershipProof>,
    /// optional non-membership proof captured before insertion
    pub pre_acc_proof: Option<NonMembershipProof>,
}

impl InsertResponse {
    pub fn new(
        key: String,
        fids: Set<String>,
        post_accumulator: Option<G1Affine>,
        post_merkle_proof: Option<MerkleProof>,
        post_acc_proof: Option<MembershipProof>,
        pre_acc_proof: Option<NonMembershipProof>,
    ) -> Self {
        Self {
            key,
            fids,
            post_accumulator,
            post_merkle_proof,
            post_acc_proof,
            pre_acc_proof,
        }
    }

    /// Get post-insertion root hash from the proof (if present)
    pub fn post_root_hash(&self) -> Option<Hash> {
        self.post_merkle_proof.as_ref().map(|p| p.root_hash)
    }

    /// Verify that the insertion was well-formed.
    /// Checks:
    /// 1. Pre-insertion non-membership proof validates (if present)
    /// 2. Post-insertion Merkle proof validates
    /// 3. Post-insertion accumulator membership holds
    /// 4. Post-proof matches the inserted key and FID set
    pub fn verify_insert(&self) -> bool {
        // 1. Verify pre-insertion non-membership proof (if present)
        if let Some(nm_proof) = &self.pre_acc_proof {
            if !nm_proof.verify(&self.key) {
                return false; // Key was already in tree before insertion
            }
        }

        // 2. Verify post-insertion Merkle proof
        if let Some(post_p) = &self.post_merkle_proof {
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
        if let (Some(acc), Some(mp)) = (&self.post_accumulator, &self.post_acc_proof) {
            if !mp.verify(acc, &self.key) {
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
    pub pre_merkle_proof: Option<MerkleProof>,
    /// accumulator value before update (for the root containing the key)
    pub pre_accumulator: Option<G1Affine>,
    /// membership proof for the old element
    pub pre_acc_proof: Option<MembershipProof>,
    /// membership proof for the leaf after update
    pub post_merkle_proof: MerkleProof,
    /// accumulator value after update (for the root containing the key)
    pub post_accumulator: G1Affine,
    /// membership proof for the new element
    pub post_acc_proof: MembershipProof,
}

impl UpdateResponse {
    pub fn new(
        key: String,
        old_fid: String,
        new_fid: String,
        old_fids: Option<Set<String>>,
        new_fids: Set<String>,
        pre_merkle_proof: Option<MerkleProof>,
        pre_acc: Option<G1Affine>,
        pre_acc_proof: Option<MembershipProof>,
        post_merkle_proof: MerkleProof,
        post_acc: G1Affine,
        post_acc_proof: MembershipProof,
    ) -> Self {
        Self {
            key,
            old_fid,
            new_fid,
            old_fids,
            new_fids,
            pre_merkle_proof,
            pre_accumulator: pre_acc,
            pre_acc_proof,
            post_merkle_proof,
            post_accumulator: post_acc,
            post_acc_proof,
        }
    }

    /// Get pre-update root hash from the proof (if present)
    pub fn pre_root_hash(&self) -> Option<Hash> {
        self.pre_merkle_proof.as_ref().map(|p| p.root_hash)
    }

    /// Get post-update root hash from the proof
    pub fn post_root_hash(&self) -> Hash {
        self.post_merkle_proof.root_hash
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
        if let Some(pre_p) = &self.pre_merkle_proof {
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
        if !self.post_merkle_proof.verify() {
            return false;
        }
        // Verify post-proof matches the new FID set
        if !self
            .post_merkle_proof
            .verify_with_kv(&self.key, &self.new_fids)
        {
            return false;
        }

        // 5. Sibling paths should match between pre and post (structure unchanged)
        if let Some(pre_p) = &self.pre_merkle_proof {
            if pre_p.path.len() != self.post_merkle_proof.path.len() {
                return false;
            }
            for (i, (psib, pleft)) in pre_p.path.iter().enumerate() {
                let (qsib, qleft) = &self.post_merkle_proof.path[i];
                if psib != qsib || pleft != qleft {
                    return false;
                }
            }
        }

        // 6. Verify accumulator membership for both pre and post states
        if let (Some(acc), Some(mp)) = (&self.pre_accumulator, &self.pre_acc_proof) {
            if !mp.verify(acc, &self.key) {
                return false;
            }
        }

        if !self
            .post_acc_proof
            .verify(&self.post_accumulator, &self.key)
        {
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
    pub pre_merkle_proof: Option<MerkleProof>,
    /// accumulator value before deletion (for the root containing the key)
    pub pre_accumulator: Option<G1Affine>,
    /// membership proof for the old element
    pub pre_acc_proof: Option<MembershipProof>,
    /// merkle/path proof for the leaf after deletion
    pub post_merkle_proof: MerkleProof,
    /// accumulator value after deletion for the root containing the key
    pub post_accumulator: G1Affine,
}

impl DeleteResponse {
    pub fn new(
        key: String,
        deleted_fid: String,
        old_fids: Option<Set<String>>,
        new_fids: Set<String>,
        pre_merkle_proof: Option<MerkleProof>,
        pre_acc: Option<G1Affine>,
        pre_acc_proof: Option<MembershipProof>,
        post_merkle_proof: MerkleProof,
        post_acc: G1Affine,
    ) -> Self {
        Self {
            key,
            deleted_fid,
            old_fids,
            new_fids,
            pre_merkle_proof,
            pre_accumulator: pre_acc,
            pre_acc_proof,
            post_merkle_proof,
            post_accumulator: post_acc,
        }
    }

    /// Get pre-deletion root hash from the proof (if present)
    pub fn pre_root_hash(&self) -> Option<Hash> {
        self.pre_merkle_proof.as_ref().map(|p| p.root_hash)
    }

    /// Get post-deletion root hash from the proof
    pub fn post_root_hash(&self) -> Hash {
        self.post_merkle_proof.root_hash
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
        if let Some(pre_p) = &self.pre_merkle_proof {
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
        if !self.post_merkle_proof.verify() {
            return false;
        }
        // Verify post-proof matches the new FID set (or empty hash if tombstoned)
        if self.new_fids.is_empty() {
            // For tombstoned leaf, verify leaf hash is empty
            use crate::utils::empty_hash;
            if self.post_merkle_proof.leaf_hash != empty_hash() {
                return false;
            }
        } else {
            // For non-empty FID set, verify with key/value
            if !self
                .post_merkle_proof
                .verify_with_kv(&self.key, &self.new_fids)
            {
                return false;
            }
        }

        // 5. Sibling paths should match between pre and post (structure unchanged)
        if let Some(pre_p) = &self.pre_merkle_proof {
            if pre_p.path.len() != self.post_merkle_proof.path.len() {
                return false;
            }
            for (i, (psib, pleft)) in pre_p.path.iter().enumerate() {
                let (qsib, qleft) = &self.post_merkle_proof.path[i];
                if psib != qsib || pleft != qleft {
                    return false;
                }
            }
        }

        // 6. Verify accumulator membership for pre-state (key was in tree)
        if let (Some(acc), Some(mp)) = (&self.pre_accumulator, &self.pre_acc_proof) {
            if !mp.verify(acc, &self.key) {
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
    use crate::utils::leaf_hash;
    use accumulator_ads::digest_set_from_set;
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
        let qr = QueryResponse::new(Some(fids.clone()), None, None, None);

        assert_eq!(qr.fids, Some(fids));
        assert!(qr.merkle_proof.is_none());
        assert!(qr.acc_proof.is_none());
    }

    #[test]
    fn test_query_response_verify_full_fails_without_proof() {
        init_test_params();
        let fids = Set::from_vec(vec!["fid1".to_string()]);
        let qr = QueryResponse::new(Some(fids.clone()), None, None, None);

        assert!(!qr.verify_full("key", &fids));
    }

    #[test]
    fn test_insert_response_construction() {
        init_test_params();
        let fids = Set::from_vec(vec!["fid1".to_string()]);
        let resp = InsertResponse::new("key1".to_string(), fids.clone(), None, None, None, None);

        assert_eq!(resp.key, "key1");
        assert_eq!(resp.fids, fids);
    }

    #[test]
    fn test_update_response_verify_fails_with_mismatched_paths() {
        init_test_params();
        use crate::utils::empty_hash;

        let old_fids = Set::from_vec(vec!["old".to_string()]);
        let new_fids = Set::from_vec(vec!["new".to_string()]);
        let other_fids = Set::from_vec(vec!["other".to_string()]);

        let pre_proof = MerkleProof::new(
            empty_hash(),
            leaf_hash("key", &old_fids, 0, false),
            vec![(empty_hash(), true)],
        );

        let post_proof = MerkleProof::new(
            empty_hash(),
            leaf_hash("key", &new_fids, 0, false),
            vec![(leaf_hash("other", &other_fids, 0, false), true)], // Different sibling
        );

        let resp = UpdateResponse::new(
            "key".to_string(),
            "old".to_string(),
            "new".to_string(),
            Some(old_fids),
            new_fids,
            Some(pre_proof),
            Some(crate::utils::empty_acc()), // pre_acc
            Some(MembershipProof {
                witness: crate::utils::empty_acc(),
            }), // pre_acc_proof
            post_proof,
            crate::utils::empty_acc(),
            MembershipProof {
                witness: crate::utils::empty_acc(),
            },
        );

        // Should fail because sibling hashes don't match
        assert!(!resp.verify_update());
    }

    #[test]
    fn test_delete_response_construction() {
        init_test_params();
        use crate::utils::empty_hash;

        let post_proof = MerkleProof::new(empty_hash(), empty_hash(), vec![]);
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
            crate::utils::empty_acc(),
        );

        assert_eq!(resp.key, "key1");
        assert_eq!(resp.old_fids, Some(old_fids));
    }

    #[test]
    fn test_delete_response_verify_post_proof() {
        init_test_params();
        use crate::utils::empty_hash;
        use accumulator_ads::{DynamicAccumulator, Set, digest_set_from_set};

        let old_fids = Set::from_vec(vec!["fid1".to_string()]);
        let new_fids = Set::new();

        // Create matching pre and post proofs with proper root hashes
        let old_leaf = leaf_hash("key1", &old_fids, 0, false);
        let pre_proof = MerkleProof::new(
            old_leaf, // root = leaf for single node
            old_leaf,
            vec![],
        );
        let post_proof = MerkleProof::new(
            empty_hash(), // root = empty for tombstoned leaf
            empty_hash(),
            vec![],
        );

        // Calculate valid accumulator for key1 being in the set
        let key_set = Set::from_vec(vec!["key1".to_string()]);
        let digest_set = digest_set_from_set(&key_set);
        let pre_acc = DynamicAccumulator::calculate_commitment(&digest_set);

        // Witness for key1 in {key1} is the empty accumulator (g1)
        // because witness = g1 ^ product(s+x_j) for j != k; if set={k}, product is empty=1.
        let pre_witness = MembershipProof {
            witness: crate::utils::empty_acc(),
        };

        let resp = DeleteResponse::new(
            "key1".to_string(),
            "fid1".to_string(),
            Some(old_fids),
            new_fids,
            Some(pre_proof),
            Some(pre_acc),
            Some(pre_witness),
            post_proof,
            crate::utils::empty_acc(),
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
