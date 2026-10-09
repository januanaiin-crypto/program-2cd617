//! Live devnet smoke test: open a vault, upload a Winternitz signature into a
//! buffer, spend SOL from it, and confirm the vault rotated — all against the
//! real deployed program on devnet.
//!
//! Run: `cargo run -p harness --example devnet_smoke`
//! Uses the default Solana CLI wallet (`~/.config/solana/id.json`) as payer.

use borsh::to_vec;
use quantum_vault::VaultInstruction;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    instruction::{AccountMeta, Instruction},
    native_token::LAMPORTS_PER_SOL,
    pubkey::Pubkey,
    signature::{read_keypair_file, Keypair, Signer},
    system_program,
    transaction::Transaction,
};
use std::time::{SystemTime, UNIX_EPOCH};
use wots::SecretKey;

const URL: &str = "https://api.devnet.solana.com";

fn main() {
    let program_id = quantum_vault::ID;
    let url = std::env::var("RPC").unwrap_or_else(|_| URL.to_string());
    let client = RpcClient::new_with_commitment(url, CommitmentConfig::confirmed());

    let wallet = std::env::var("ADMIN_KEYPAIR").unwrap_or_else(|_| {
        format!("{}/.config/solana/id.json", std::env::var("USERPROFILE").unwrap())
    });
    let payer = read_keypair_file(&wallet).expect("read default wallet");
    println!("payer:   {}", payer.pubkey());
    println!("program: {program_id}");

    // Unique genesis per run so the vault PDA is fresh.
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
    let mut seed0 = [0u8; 32];
    seed0[..8].copy_from_slice(&nonce.to_le_bytes());
    let sk0 = SecretKey::from_seed(&seed0);
    let ps = wots::public_seed(&seed0);
    let genesis: [u8; 28] = sk0.public_key(&ps).0;
    let next: [u8; 28] = SecretKey::from_seed(&[seed0[0] ^ 0xFF; 32]).public_key(&ps).0;

    let vault = Pubkey::find_program_address(&[b"vault", &genesis], &program_id).0;
    let sigbuf =
        Pubkey::find_program_address(&[b"sigbuf", &genesis, payer.pubkey().as_ref()], &program_id).0;
    let destination = Keypair::new().pubkey();

    let deposit = LAMPORTS_PER_SOL / 500; // 0.002 SOL (shared devnet wallet: thrifty)
    let amount = LAMPORTS_PER_SOL / 1000; // 0.001 SOL (> rent-exempt min of a fresh account)

    // 1. open vault
    send(&client, &payer, &[ix(
        program_id,
        vec![
            AccountMeta::new(vault, false),
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        &VaultInstruction::OpenVault { genesis_pubkey: genesis, pub_seed: ps, deposit },
    )], "open_vault");

    // 2. sign the spend and upload it to the buffer
    let message = spend_sol_message(&genesis, amount, &destination, &next);
    let sig = sk0.sign(&message, &ps).to_bytes();

    send(&client, &payer, &[ix(
        program_id,
        vec![
            AccountMeta::new(sigbuf, false),
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        &VaultInstruction::InitSigBuffer { genesis_pubkey: genesis },
    )], "init_sig_buffer");

    const CHUNK: usize = 900;
    let mut offset = 0usize;
    while offset < sig.len() {
        let end = (offset + CHUNK).min(sig.len());
        send(&client, &payer, &[ix(
            program_id,
            vec![
                AccountMeta::new(sigbuf, false),
                AccountMeta::new_readonly(payer.pubkey(), true),
            ],
            &VaultInstruction::WriteSigBuffer { offset: offset as u16, chunk: sig[offset..end].to_vec() },
        )], &format!("write_sig_buffer @{offset}"));
        offset = end;
    }

    // 3. spend
    send(&client, &payer, &[ix(
        program_id,
        vec![
            AccountMeta::new(vault, false),
            AccountMeta::new(sigbuf, false),
            AccountMeta::new(destination, false),
            AccountMeta::new(payer.pubkey(), false),
        ],
        &VaultInstruction::SpendSol { genesis_pubkey: genesis, amount, next_pubkey: next },
    )], "spend_sol");

    // 4. verify on-chain state
    let dest_balance = client.get_balance(&destination).unwrap();
    let vault_data = client.get_account(&vault).unwrap().data;
    let mut current = [0u8; 28];
    current.copy_from_slice(&vault_data[1..29]);

    println!("\n--- results ---");
    println!("destination balance: {dest_balance} lamports (expected {amount})");
    println!("vault rotated to next key: {}", current == next);
    assert_eq!(dest_balance, amount, "destination must receive the withdrawal");
    assert_eq!(current, next, "vault must rotate");
    println!("\n✅ live devnet spend succeeded");
    println!("vault:       https://explorer.solana.com/address/{vault}?cluster=devnet");
    println!("destination: https://explorer.solana.com/address/{destination}?cluster=devnet");
}

fn ix(program_id: Pubkey, accounts: Vec<AccountMeta>, data: &VaultInstruction) -> Instruction {
    Instruction { program_id, accounts, data: to_vec(data).unwrap() }
}

fn send(client: &RpcClient, payer: &Keypair, ixs: &[Instruction], label: &str) {
    let bh = client.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(ixs, Some(&payer.pubkey()), &[payer], bh);
    let sig = client
        .send_and_confirm_transaction(&tx)
        .unwrap_or_else(|e| panic!("{label} failed: {e}"));
    println!("  {label:24} {sig}");
}

fn spend_sol_message(genesis: &[u8; 28], amount: u64, dest: &Pubkey, next: &[u8; 28]) -> Vec<u8> {
    let mut m = vec![0x01u8];
    m.extend_from_slice(genesis);
    m.extend_from_slice(&amount.to_le_bytes());
    m.extend_from_slice(dest.as_ref());
    m.extend_from_slice(next);
    m
}
