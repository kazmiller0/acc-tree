use accumulator_ads::acc::utils::digest_to_prime_field;
use accumulator_ads::digest::Digestible;
use accumulator_ads::{G1Affine, digest_set_from_set};

#[derive(Debug, Clone)]
pub struct MembershipProof {
    pub witness: G1Affine,
}

impl MembershipProof {
    pub fn verify(&self, acc: &G1Affine, key: &str) -> bool {
        // Convert key to field element
        let key_digest = key.to_digest();
        let key_fr = digest_to_prime_field(&key_digest);

        // Create membership proof and verify using accumulator_ads
        let proof = accumulator_ads::MembershipProof {
            witness: self.witness,
            element: key_fr,
        };

        proof.verify(*acc)
    }
}

/// Helper function to verify membership using accumulator_ads MembershipProof
/// This delegates all cryptographic verification logic to the underlying library,
/// following DRY principle and ensuring consistency.
pub fn verify_membership(acc: &G1Affine, witness: &G1Affine, key: &str) -> bool {
    MembershipProof { witness: *witness }.verify(acc, key)
}

#[derive(Debug, Clone)]
pub enum AccProof {
    Membership(MembershipProof),
    NonMembership(NonMembershipProof),
}

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
    pub fn new(
        key: String,
        accumulator: G1Affine,
        all_keys_set: &accumulator_ads::Set<String>,
    ) -> Option<Self> {
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
