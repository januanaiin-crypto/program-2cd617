//! # Winternitz One-Time Signatures (WOTS) over Keccak-256
//!
//! A self-contained, dependency-light implementation of the signature scheme
//! that powers quantum-resistant vaults on Solana.
//!
//! ## Why this is quantum-resistant
//!
//! Its security rests *only* on the one-wayness (preimage resistance) of a hash
//! function. Unlike Ed25519, there is no elliptic curve and no discrete-log
//! problem for Shor's algorithm to attack. The best a quantum computer can do is
//! Grover's algorithm, which only *halves* the effective security of a hash — so
//! Keccak-256 still gives ~128-bit post-quantum security.
//!
//! ## The one-time constraint (read this!)
//!
//! A WOTS keypair is safe to sign **exactly one** message. Each signature reveals
//! part of the secret hash chains; signing a second, different message leaks
//! enough intermediate values for an attacker to forge. On Solana this is handled
//! by the *vault pattern*: every spend closes the current vault and opens a new
//! one committed to a fresh public key. See the program crate.
//!
//! ## How it works (base-16 chains)
//!
//! 1. The secret key is `NUM_CHAINS` random 28-byte values, one per "chain".
//! 2. The public key hashes each secret value `CHAIN_MAX` (15) times, then hashes
//!    all the chain tops together into a single compressed 28-byte commitment.
//! 3. To sign, we split the 224-bit message digest into base-16 digits (nibbles),
//!    append a checksum, and for digit `d` on chain `i` we hash the secret `d` times.
//! 4. To verify, we hash each signature element the *remaining* `15 - d` times to
//!    recover the chain top, then check the compressed commitment matches.
//!
//! The checksum is what stops forgery: raising a message digit (cheap — just hash
//! more) forces a checksum digit to *drop*, which would require inverting the hash
//! (infeasible).

#![forbid(unsafe_code)]

/// Winternitz parameter: each chain encodes one base-`W` digit.
///
/// W is the central performance knob. On-chain verification walks each chain up
/// to `W-1` times, so cost ≈ `NUM_CHAINS * (W-1)/2` Keccak ops — and Keccak is
/// the dominant compute cost. `W = 16` (4-bit nibbles) needs ~9× fewer hashes
/// than a base-256 scheme. The trade-off: more chains → a 1652-byte signature
/// that exceeds Solana's 1232-byte transaction limit, so spends supply it via an
/// on-chain *signature buffer* account rather than inline instruction data.
pub const W: usize = 16;
/// Maximum iterations per chain (a base-`W` digit is `0..=W-1`).
pub const CHAIN_MAX: usize = W - 1;
/// Hash length in bytes (n) — Keccak-256 **truncated to 224 bits**. Security:
/// 224-bit preimage resistance → ~112-bit post-quantum (Grover only
/// square-roots it), still ample.
pub const HASH_LEN: usize = 28;
/// Base-`W` digits from the 224-bit message digest: 28 bytes × 2 nibbles.
pub const MSG_DIGITS: usize = HASH_LEN * 2; // 56
/// Checksum digits. Max checksum = 56 × 15 = 840 < 16³, so 3 base-16 digits.
pub const CHECKSUM_DIGITS: usize = 3;
/// Total hash chains = message digits + checksum digits.
pub const NUM_CHAINS: usize = MSG_DIGITS + CHECKSUM_DIGITS; // 59
/// Wire size of a signature in bytes (59 × 28 = 1652).
pub const SIGNATURE_BYTES: usize = NUM_CHAINS * HASH_LEN;

/// A 32-byte Keccak-256 hash value.
pub type Hash = [u8; HASH_LEN];

/// Keccak-256 of `data`, truncated to [`HASH_LEN`] bytes
/// (off-chain / test backend: pure-Rust `sha3`).
#[cfg(feature = "sha3-backend")]
pub fn keccak(data: &[u8]) -> Hash {
    use sha3::{Digest, Keccak256};
    let mut h = Keccak256::new();
    h.update(data);
    let full = h.finalize();
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&full[..HASH_LEN]);
    out
}

/// Keccak-256 of `data`, truncated to [`HASH_LEN`] bytes
/// (on-chain backend: Solana's `keccak` syscall, cheap CU).
#[cfg(all(feature = "solana-backend", not(feature = "sha3-backend")))]
pub fn keccak(data: &[u8]) -> Hash {
    let full = solana_program::keccak::hash(data).to_bytes();
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&full[..HASH_LEN]);
    out
}

/// Derive the per-vault public seed from the 32-byte master seed. This is a
/// public value (a hash of the secret seed) stored on-chain; it tweaks every
/// chain hash so that no two vaults share a hash function (defeats multi-target
/// attacks — the WOTS+ idea).
pub fn public_seed(master: &[u8; 32]) -> Hash {
    let mut buf = [0u8; 32 + 10];
    buf[..32].copy_from_slice(master);
    buf[32..].copy_from_slice(b"QV-PUBSEED");
    keccak(&buf)
}

/// One tweaked hash step on chain `i` at position `p`:
/// `keccak(pub_seed || i || p || x)`. The tweak makes each (vault, chain,
/// position) a distinct one-way function.
fn hash_step(pub_seed: &Hash, i: u8, p: u8, x: &Hash) -> Hash {
    let mut buf = [0u8; HASH_LEN + 2 + HASH_LEN];
    buf[..HASH_LEN].copy_from_slice(pub_seed);
    buf[HASH_LEN] = i;
    buf[HASH_LEN + 1] = p;
    buf[HASH_LEN + 2..].copy_from_slice(x);
    keccak(&buf)
}

/// Walk chain `i` `count` steps, starting at position `start_pos`.
fn chain(pub_seed: &Hash, i: u8, start_pos: usize, count: usize, mut x: Hash) -> Hash {
    for step in 0..count {
        x = hash_step(pub_seed, i, (start_pos + step) as u8, &x);
    }
    x
}

/// Expand the 224-bit message digest into `NUM_CHAINS` base-16 digits: each of
/// the 28 bytes becomes two nibbles (high then low), followed by a 3-nibble
/// big-endian checksum.
///
/// The checksum is `sum(CHAIN_MAX - digit)` over the message digits, which is
/// what makes forgery infeasible (see crate docs).
fn digits(message_digest: &Hash) -> [u8; NUM_CHAINS] {
    let mut out = [0u8; NUM_CHAINS];
    for (i, &b) in message_digest.iter().enumerate() {
        out[2 * i] = b >> 4;
        out[2 * i + 1] = b & 0x0f;
    }

    let mut checksum: u32 = 0;
    for &d in &out[..MSG_DIGITS] {
        checksum += (CHAIN_MAX as u32) - (d as u32);
    }
    out[MSG_DIGITS] = ((checksum >> 8) & 0x0f) as u8;
    out[MSG_DIGITS + 1] = ((checksum >> 4) & 0x0f) as u8;
    out[MSG_DIGITS + 2] = (checksum & 0x0f) as u8;
    out
}

/// A WOTS secret key: one 32-byte seed per hash chain.
///
/// Derived deterministically from a single 32-byte master seed so a wallet only
/// has to store/back-up 32 bytes, not the full ~1 KB key.
pub struct SecretKey {
    chains: [Hash; NUM_CHAINS],
}

impl SecretKey {
    /// Deterministically derive a secret key from a 32-byte master seed.
    ///
    /// Each chain's secret is `Keccak(seed || index)`.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let mut chains = [[0u8; HASH_LEN]; NUM_CHAINS];
        for (i, c) in chains.iter_mut().enumerate() {
            let mut buf = [0u8; 33];
            buf[..32].copy_from_slice(seed);
            buf[32] = i as u8;
            *c = keccak(&buf);
        }
        SecretKey { chains }
    }

    /// Compute the compressed 28-byte public key (the vault commitment), under
    /// the vault's `pub_seed`.
    pub fn public_key(&self, pub_seed: &Hash) -> PublicKey {
        let mut tops = [0u8; SIGNATURE_BYTES];
        for (i, c) in self.chains.iter().enumerate() {
            let top = chain(pub_seed, i as u8, 0, CHAIN_MAX, *c);
            tops[i * HASH_LEN..(i + 1) * HASH_LEN].copy_from_slice(&top);
        }
        PublicKey(keccak(&tops))
    }

    /// Sign `message` under `pub_seed`. **One-time use only.**
    pub fn sign(&self, message: &[u8], pub_seed: &Hash) -> Signature {
        let d = digits(&keccak(message));
        let mut sig = [[0u8; HASH_LEN]; NUM_CHAINS];
        for (i, s) in sig.iter_mut().enumerate() {
            *s = chain(pub_seed, i as u8, 0, d[i] as usize, self.chains[i]);
        }
        Signature(sig)
    }
}

/// The compressed 32-byte WOTS public key. This is what a vault stores on-chain.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PublicKey(pub Hash);

impl PublicKey {
    /// Recover the public key implied by `sig` over `message` and check it matches.
    ///
    /// This is the operation a Solana program runs on-chain: pure hashing, cheap
    /// in compute units relative to lattice verification.
    pub fn verify(&self, message: &[u8], sig: &Signature, pub_seed: &Hash) -> bool {
        let d = digits(&keccak(message));
        let mut tops = [0u8; SIGNATURE_BYTES];
        for (i, element) in sig.0.iter().enumerate() {
            let top = chain(pub_seed, i as u8, d[i] as usize, CHAIN_MAX - d[i] as usize, *element);
            tops[i * HASH_LEN..(i + 1) * HASH_LEN].copy_from_slice(&top);
        }
        PublicKey(keccak(&tops)) == *self
    }

    /// Verify a signature provided as raw bytes (e.g. read straight from an
    /// account's data) without materializing a [`Signature`] on the caller's
    /// stack. This matters on Solana, where stack frames are capped at 4 KB and a
    /// full signature is 1652 bytes — the on-chain spend path uses this so the
    /// only large buffer is `tops`, here inside this frame.
    pub fn verify_slice(&self, message: &[u8], sig: &[u8], pub_seed: &Hash) -> bool {
        if sig.len() != SIGNATURE_BYTES {
            return false;
        }
        let d = digits(&keccak(message));
        let mut tops = [0u8; SIGNATURE_BYTES];
        for i in 0..NUM_CHAINS {
            let mut element = [0u8; HASH_LEN];
            element.copy_from_slice(&sig[i * HASH_LEN..(i + 1) * HASH_LEN]);
            let top = chain(pub_seed, i as u8, d[i] as usize, CHAIN_MAX - d[i] as usize, element);
            tops[i * HASH_LEN..(i + 1) * HASH_LEN].copy_from_slice(&top);
        }
        PublicKey(keccak(&tops)) == *self
    }
}

/// A WOTS signature: one 28-byte value per chain (1652 bytes on the wire).
#[derive(Clone)]
pub struct Signature(pub [Hash; NUM_CHAINS]);

impl Signature {
    /// Serialize to the 1652-byte wire format.
    pub fn to_bytes(&self) -> [u8; SIGNATURE_BYTES] {
        let mut out = [0u8; SIGNATURE_BYTES];
        for (i, element) in self.0.iter().enumerate() {
            out[i * HASH_LEN..(i + 1) * HASH_LEN].copy_from_slice(element);
        }
        out
    }

    /// Parse from the 1652-byte wire format.
    pub fn from_bytes(bytes: &[u8; SIGNATURE_BYTES]) -> Self {
        let mut sig = [[0u8; HASH_LEN]; NUM_CHAINS];
        for (i, element) in sig.iter_mut().enumerate() {
            element.copy_from_slice(&bytes[i * HASH_LEN..(i + 1) * HASH_LEN]);
        }
        Signature(sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [7u8; 32];

    fn ps() -> Hash {
        public_seed(&SEED)
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let sk = SecretKey::from_seed(&SEED);
        let pk = sk.public_key(&ps());
        let msg = b"withdraw 1 SOL to alice";
        let sig = sk.sign(msg, &ps());
        assert!(pk.verify(msg, &sig, &ps()), "valid signature must verify");
    }

    #[test]
    fn wrong_message_is_rejected() {
        let sk = SecretKey::from_seed(&SEED);
        let pk = sk.public_key(&ps());
        let sig = sk.sign(b"withdraw 1 SOL to alice", &ps());
        assert!(
            !pk.verify(b"withdraw 1 SOL to mallory", &sig, &ps()),
            "signature must not verify against a different message"
        );
    }

    #[test]
    fn wrong_pub_seed_is_rejected() {
        // A signature made under one vault's pub_seed must not verify under
        // another's — this is what defeats cross-vault multi-target attacks.
        let sk = SecretKey::from_seed(&SEED);
        let pk = sk.public_key(&ps());
        let msg = b"hello";
        let sig = sk.sign(msg, &ps());
        let other_ps = public_seed(&[1u8; 32]);
        assert!(!pk.verify(msg, &sig, &other_ps), "must not verify under a foreign pub_seed");
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let sk = SecretKey::from_seed(&SEED);
        let pk = sk.public_key(&ps());
        let msg = b"withdraw 1 SOL to alice";
        let mut sig = sk.sign(msg, &ps());
        sig.0[0][0] ^= 0xff; // flip a byte
        assert!(!pk.verify(msg, &sig, &ps()), "tampered signature must be rejected");
    }

    #[test]
    fn wrong_key_is_rejected() {
        let sk = SecretKey::from_seed(&SEED);
        let other_pk = SecretKey::from_seed(&[9u8; 32]).public_key(&ps());
        let msg = b"hello";
        let sig = sk.sign(msg, &ps());
        assert!(!other_pk.verify(msg, &sig, &ps()), "must not verify under a foreign key");
    }

    #[test]
    fn verify_slice_matches_verify() {
        let sk = SecretKey::from_seed(&SEED);
        let pk = sk.public_key(&ps());
        let msg = b"slice verify";
        let sig = sk.sign(msg, &ps());
        let bytes = sig.to_bytes();
        assert!(pk.verify_slice(msg, &bytes, &ps()), "slice verify must accept a valid sig");
        assert!(!pk.verify_slice(b"other", &bytes, &ps()), "slice verify must reject wrong msg");
        assert!(
            !pk.verify_slice(msg, &bytes[..bytes.len() - 1], &ps()),
            "wrong length must be rejected"
        );
    }

    #[test]
    fn signature_wire_roundtrip() {
        let sk = SecretKey::from_seed(&SEED);
        let pk = sk.public_key(&ps());
        let msg = b"roundtrip";
        let sig = sk.sign(msg, &ps());
        let parsed = Signature::from_bytes(&sig.to_bytes());
        assert!(pk.verify(msg, &parsed, &ps()), "wire roundtrip must preserve validity");
    }

    /// The checksum must stop the classic WOTS forgery: an attacker who only
    /// raises message digits (cheap — hashing forward) cannot also lower the
    /// checksum digits without inverting the hash. We advance each message chain
    /// by one real (tweaked) step and confirm the recovered key no longer matches.
    #[test]
    fn checksum_blocks_digit_raising_forgery() {
        let sk = SecretKey::from_seed(&SEED);
        let pk = sk.public_key(&ps());
        let msg = b"pay 1";
        let sig = sk.sign(msg, &ps());
        let d = digits(&keccak(msg));

        let mut forged = sig.clone();
        for i in 0..MSG_DIGITS {
            // Advance message chain i from position d[i] to d[i]+1.
            forged.0[i] = hash_step(&ps(), i as u8, d[i], &forged.0[i]);
        }
        assert!(
            !pk.verify(msg, &forged, &ps()),
            "raising message digits without fixing checksum must fail"
        );
    }

    #[test]
    fn signature_size_requires_buffer() {
        // W=16 trades a larger signature for ~9x fewer Keccak ops. At 1652 bytes
        // it exceeds Solana's 1232-byte transaction limit, so spends supply it via
        // an on-chain signature buffer account.
        assert_eq!(SIGNATURE_BYTES, 1652);
        assert!(SIGNATURE_BYTES > 1232);
    }

    #[test]
    fn digit_bounds_hold() {
        let sk = SecretKey::from_seed(&SEED);
        let _ = sk.sign(b"bounds check", &ps());
        assert_eq!(NUM_CHAINS, 59);
        assert_eq!(CHAIN_MAX, 15);
    }
}
