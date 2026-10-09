//! Run with: `cargo run -p wots --example demo`
//!
//! Walks through the full WOTS lifecycle and makes the sizes + the one-time
//! constraint tangible.

use wots::{public_seed, SecretKey, Signature, NUM_CHAINS, SIGNATURE_BYTES};

fn main() {
    println!("== Winternitz One-Time Signature demo ==\n");

    // A wallet only needs to back up this 32-byte seed.
    let seed = [42u8; 32];
    let sk = SecretKey::from_seed(&seed);
    // The per-vault public seed tweaks every hash (WOTS+ style multi-target defense).
    let ps = public_seed(&seed);
    let pk = sk.public_key(&ps);

    println!("Master seed:        32 bytes (all a wallet stores)");
    println!("Public key (vault): {} bytes  -> {}", pk.0.len(), hex(&pk.0));
    println!("Public seed:        {} bytes  -> {}", ps.len(), hex(&ps));
    println!("Chains:             {NUM_CHAINS}");
    println!("Signature size:     {SIGNATURE_BYTES} bytes (uploaded on-chain via a buffer)\n");

    // Sign a withdrawal intent (on-chain this would be the instruction data).
    let message = b"withdraw 1000000000 lamports to Alice";
    let sig = sk.sign(message, &ps);
    println!("Message:  {:?}", std::str::from_utf8(message).unwrap());
    println!("Verify:   {}\n", pk.verify(message, &sig, &ps));

    // Tamper check.
    let tampered = b"withdraw 1000000000 lamports to Mallory";
    println!("Attacker swaps recipient -> verify: {}", pk.verify(tampered, &sig, &ps));

    // Wire format roundtrip (what travels in the transaction).
    let wire = sig.to_bytes();
    let parsed = Signature::from_bytes(&wire);
    println!("Wire roundtrip verify:               {}\n", pk.verify(message, &parsed, &ps));

    println!("!! One-time rule: this seed has now signed once. Signing a SECOND");
    println!("   different message with it would leak the key. In the vault, the");
    println!("   withdrawal tx also commits the NEXT public key and closes this one.");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
