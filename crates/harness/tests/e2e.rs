//! End-to-end tests for the native quantum-vault program, driven in LiteSVM.
//!
//! A spend is a short sequence: create a signature-buffer PDA, upload the
//! 1652-byte WOTS signature into it across a couple of transactions, then run the
//! spend instruction (which verifies, moves funds, rotates the one-time key, and
//! closes the buffer). The tests report the real compute-unit cost of the spend.

use anchor_lang::AccountDeserialize;
use anchor_spl::associated_token::{get_associated_token_address, spl_associated_token_account};
use anchor_spl::token::spl_token;
use anchor_spl::token::spl_token::solana_program::program_pack::Pack;
use anchor_spl::token::TokenAccount;
use litesvm::types::TransactionMetadata;
use litesvm::LiteSVM;
use quantum_vault::VaultInstruction;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_instruction, system_program,
    transaction::Transaction,
};
use wots::{public_seed, SecretKey};

const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

// --- plumbing --------------------------------------------------------------

fn program_so() -> std::path::PathBuf {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let candidates = [
        manifest.join("../../target/deploy/quantum_vault.so"),
        std::path::PathBuf::from(r"D:\cargo-target\deploy\quantum_vault.so"),
    ];
    candidates
        .iter()
        .filter(|p| p.exists())
        .max_by_key(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok())
        .unwrap_or_else(|| panic!("quantum_vault.so not found; run `cargo build-sbf` first"))
        .clone()
}

fn setup() -> (LiteSVM, Keypair, Pubkey) {
    let program_id = quantum_vault::ID;
    let mut svm = LiteSVM::new();
    svm.add_program_from_file(program_id, program_so()).unwrap();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 100 * LAMPORTS_PER_SOL).unwrap();
    (svm, payer, program_id)
}

fn ix(program_id: Pubkey, accounts: Vec<AccountMeta>, data: &VaultInstruction) -> Instruction {
    Instruction { program_id, accounts, data: borsh::to_vec(data).unwrap() }
}

fn send(svm: &mut LiteSVM, payer: &Keypair, ixs: &[Instruction]) -> TransactionMetadata {
    let tx = Transaction::new_signed_with_payer(
        ixs,
        Some(&payer.pubkey()),
        &[payer],
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).expect("transaction should succeed")
}

fn vault_pda(genesis: &[u8; 28], program_id: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"vault", genesis], program_id).0
}

fn sigbuf_pda(genesis: &[u8; 28], payer: &Pubkey, program_id: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"sigbuf", genesis, payer.as_ref()], program_id).0
}

fn vault_current_pubkey(svm: &LiteSVM, vault: &Pubkey) -> [u8; 28] {
    let acc = svm.get_account(vault).expect("vault exists");
    assert_eq!(acc.data[0], 1, "vault tag");
    let mut p = [0u8; 28];
    p.copy_from_slice(&acc.data[1..29]);
    p
}

/// Create the signature buffer and upload `sig` into it in chunks that fit a tx.
fn upload_signature(svm: &mut LiteSVM, payer: &Keypair, program_id: Pubkey, genesis: [u8; 28], sig: &[u8]) {
    let sigbuf = sigbuf_pda(&genesis, &payer.pubkey(), &program_id);
    send(
        svm,
        payer,
        &[ix(
            program_id,
            vec![
                AccountMeta::new(sigbuf, false),
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new_readonly(system_program::ID, false),
            ],
            &VaultInstruction::InitSigBuffer { genesis_pubkey: genesis },
        )],
    );

    const CHUNK: usize = 900;
    let mut offset = 0usize;
    while offset < sig.len() {
        let end = (offset + CHUNK).min(sig.len());
        send(
            svm,
            payer,
            &[ix(
                program_id,
                vec![
                    AccountMeta::new(sigbuf, false),
                    AccountMeta::new_readonly(payer.pubkey(), true),
                ],
                &VaultInstruction::WriteSigBuffer {
                    offset: offset as u16,
                    chunk: sig[offset..end].to_vec(),
                },
            )],
        );
        offset = end;
    }
}

fn open_vault(
    svm: &mut LiteSVM,
    payer: &Keypair,
    program_id: Pubkey,
    genesis: [u8; 28],
    pub_seed: [u8; 28],
    deposit: u64,
) -> Pubkey {
    let vault = vault_pda(&genesis, &program_id);
    send(
        svm,
        payer,
        &[ix(
            program_id,
            vec![
                AccountMeta::new(vault, false),
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new_readonly(system_program::ID, false),
            ],
            &VaultInstruction::OpenVault { genesis_pubkey: genesis, pub_seed, deposit },
        )],
    );
    vault
}

// Messages must match the program byte-for-byte.
fn spend_sol_message(genesis: &[u8; 28], amount: u64, dest: &Pubkey, next: &[u8; 28]) -> Vec<u8> {
    let mut m = vec![0x01u8];
    m.extend_from_slice(genesis);
    m.extend_from_slice(&amount.to_le_bytes());
    m.extend_from_slice(dest.as_ref());
    m.extend_from_slice(next);
    m
}

fn spend_token_message(genesis: &[u8; 28], mint: &Pubkey, amount: u64, dest: &Pubkey, next: &[u8; 28]) -> Vec<u8> {
    let mut m = vec![0x02u8];
    m.extend_from_slice(genesis);
    m.extend_from_slice(mint.as_ref());
    m.extend_from_slice(&amount.to_le_bytes());
    m.extend_from_slice(dest.as_ref());
    m.extend_from_slice(next);
    m
}

// --- SPL helpers (test utilities; the program is not involved in deposits) ---

fn create_mint(svm: &mut LiteSVM, payer: &Keypair, authority: &Pubkey, decimals: u8) -> Pubkey {
    let mint = Keypair::new();
    let len = spl_token::state::Mint::LEN;
    let rent = solana_sdk::rent::Rent::default().minimum_balance(len);
    let create = system_instruction::create_account(&payer.pubkey(), &mint.pubkey(), rent, len as u64, &spl_token::ID);
    let init = spl_token::instruction::initialize_mint2(&spl_token::ID, &mint.pubkey(), authority, None, decimals).unwrap();
    let tx = Transaction::new_signed_with_payer(&[create, init], Some(&payer.pubkey()), &[payer, &mint], svm.latest_blockhash());
    svm.send_transaction(tx).expect("create mint");
    mint.pubkey()
}

fn create_ata(svm: &mut LiteSVM, payer: &Keypair, owner: &Pubkey, mint: &Pubkey) -> Pubkey {
    let i = spl_associated_token_account::instruction::create_associated_token_account(&payer.pubkey(), owner, mint, &spl_token::ID);
    send(svm, payer, &[i]);
    get_associated_token_address(owner, mint)
}

fn mint_to(svm: &mut LiteSVM, payer: &Keypair, mint: &Pubkey, dest: &Pubkey, authority: &Keypair, amount: u64) {
    let i = spl_token::instruction::mint_to(&spl_token::ID, mint, dest, &authority.pubkey(), &[], amount).unwrap();
    let tx = Transaction::new_signed_with_payer(&[i], Some(&payer.pubkey()), &[payer, authority], svm.latest_blockhash());
    svm.send_transaction(tx).expect("mint_to");
}

fn token_transfer(svm: &mut LiteSVM, payer: &Keypair, from: &Pubkey, to: &Pubkey, authority: &Keypair, amount: u64) {
    let i = spl_token::instruction::transfer(&spl_token::ID, from, to, &authority.pubkey(), &[], amount).unwrap();
    let tx = Transaction::new_signed_with_payer(&[i], Some(&payer.pubkey()), &[payer, authority], svm.latest_blockhash());
    svm.send_transaction(tx).expect("token transfer");
}

fn token_balance(svm: &LiteSVM, ata: &Pubkey) -> u64 {
    let acc = svm.get_account(ata).expect("token account exists");
    TokenAccount::try_deserialize(&mut &acc.data[..]).expect("unpack").amount
}

// --- tests -----------------------------------------------------------------

#[test]
fn sol_spend_and_rotate() {
    let (mut svm, payer, program_id) = setup();

    let seed0 = [1u8; 32];
    let ps = public_seed(&seed0);
    let sk0 = SecretKey::from_seed(&seed0);
    let genesis: [u8; 28] = sk0.public_key(&ps).0;
    let vault = open_vault(&mut svm, &payer, program_id, genesis, ps, 2 * LAMPORTS_PER_SOL);
    assert!(svm.get_account(&vault).unwrap().lamports >= 2 * LAMPORTS_PER_SOL);

    let destination = Keypair::new().pubkey();
    let next: [u8; 28] = SecretKey::from_seed(&[2u8; 32]).public_key(&ps).0;
    let amount = LAMPORTS_PER_SOL;

    let message = spend_sol_message(&genesis, amount, &destination, &next);
    let sig = sk0.sign(&message, &ps).to_bytes();
    upload_signature(&mut svm, &payer, program_id, genesis, &sig);

    let meta = send(
        &mut svm,
        &payer,
        &[ix(
            program_id,
            vec![
                AccountMeta::new(vault, false),
                AccountMeta::new(sigbuf_pda(&genesis, &payer.pubkey(), &program_id), false),
                AccountMeta::new(destination, false),
                AccountMeta::new(payer.pubkey(), false),
            ],
            &VaultInstruction::SpendSol { genesis_pubkey: genesis, amount, next_pubkey: next },
        )],
    );
    println!("\n>>> native SOL spend cost: {} compute units\n", meta.compute_units_consumed);

    assert_eq!(svm.get_account(&destination).unwrap().lamports, amount, "recipient funded");
    assert_eq!(vault_current_pubkey(&svm, &vault), next, "vault rotated");
    // Buffer was closed.
    assert!(svm.get_account(&sigbuf_pda(&genesis, &payer.pubkey(), &program_id)).map_or(true, |a| a.lamports == 0));
}

#[test]
fn forged_signature_is_rejected() {
    let (mut svm, payer, program_id) = setup();

    let seed0 = [3u8; 32];
    let ps = public_seed(&seed0);
    let sk0 = SecretKey::from_seed(&seed0);
    let genesis: [u8; 28] = sk0.public_key(&ps).0;
    let vault = open_vault(&mut svm, &payer, program_id, genesis, ps, 2 * LAMPORTS_PER_SOL);

    let attacker = SecretKey::from_seed(&[99u8; 32]);
    let destination = Keypair::new().pubkey();
    let next: [u8; 28] = SecretKey::from_seed(&[4u8; 32]).public_key(&ps).0;
    let amount = LAMPORTS_PER_SOL;
    let message = spend_sol_message(&genesis, amount, &destination, &next);
    let bad_sig = attacker.sign(&message, &ps).to_bytes();
    upload_signature(&mut svm, &payer, program_id, genesis, &bad_sig);

    let tx = Transaction::new_signed_with_payer(
        &[ix(
            program_id,
            vec![
                AccountMeta::new(vault, false),
                AccountMeta::new(sigbuf_pda(&genesis, &payer.pubkey(), &program_id), false),
                AccountMeta::new(destination, false),
                AccountMeta::new(payer.pubkey(), false),
            ],
            &VaultInstruction::SpendSol { genesis_pubkey: genesis, amount, next_pubkey: next },
        )],
        Some(&payer.pubkey()),
        &[&payer],
        svm.latest_blockhash(),
    );
    assert!(svm.send_transaction(tx).is_err(), "forged signature must be rejected");
}

#[test]
fn token_spend_and_rotate() {
    let (mut svm, payer, program_id) = setup();

    // Mint + a depositor holding 1000 tokens.
    let mint = create_mint(&mut svm, &payer, &payer.pubkey(), 6);
    let depositor_ata = create_ata(&mut svm, &payer, &payer.pubkey(), &mint);
    mint_to(&mut svm, &payer, &mint, &depositor_ata, &payer, 1_000_000_000);

    // Vault + its token account (created externally; deposits need no program ix).
    let seed0 = [10u8; 32];
    let ps = public_seed(&seed0);
    let sk0 = SecretKey::from_seed(&seed0);
    let genesis: [u8; 28] = sk0.public_key(&ps).0;
    let vault = open_vault(&mut svm, &payer, program_id, genesis, ps, 0);
    let vault_ata = create_ata(&mut svm, &payer, &vault, &mint);
    token_transfer(&mut svm, &payer, &depositor_ata, &vault_ata, &payer, 600_000_000);
    assert_eq!(token_balance(&svm, &vault_ata), 600_000_000);

    // Spend 250 tokens to a fresh recipient.
    let recipient = Keypair::new().pubkey();
    let recipient_ata = create_ata(&mut svm, &payer, &recipient, &mint);
    let next: [u8; 28] = SecretKey::from_seed(&[11u8; 32]).public_key(&ps).0;
    let amount = 250_000_000u64;

    let message = spend_token_message(&genesis, &mint, amount, &recipient_ata, &next);
    let sig = sk0.sign(&message, &ps).to_bytes();
    upload_signature(&mut svm, &payer, program_id, genesis, &sig);

    let meta = send(
        &mut svm,
        &payer,
        &[ix(
            program_id,
            vec![
                AccountMeta::new(vault, false),
                AccountMeta::new(sigbuf_pda(&genesis, &payer.pubkey(), &program_id), false),
                AccountMeta::new_readonly(mint, false),
                AccountMeta::new(vault_ata, false),
                AccountMeta::new(recipient_ata, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new(payer.pubkey(), false),
            ],
            &VaultInstruction::SpendToken { genesis_pubkey: genesis, amount, next_pubkey: next },
        )],
    );
    println!("\n>>> native token spend cost: {} compute units\n", meta.compute_units_consumed);

    assert_eq!(token_balance(&svm, &recipient_ata), amount, "recipient funded");
    assert_eq!(token_balance(&svm, &vault_ata), 600_000_000 - amount, "vault debited");
    assert_eq!(vault_current_pubkey(&svm, &vault), next, "vault rotated");
}

#[test]
fn attacker_cannot_corrupt_victim_buffer() {
    // F1: the signature buffer is scoped to its relayer; no one else can write it.
    let (mut svm, victim, program_id) = setup();
    let attacker = Keypair::new();
    svm.airdrop(&attacker.pubkey(), 10 * LAMPORTS_PER_SOL).unwrap();

    let seed0 = [7u8; 32];
    let ps = public_seed(&seed0);
    let sk0 = SecretKey::from_seed(&seed0);
    let genesis: [u8; 28] = sk0.public_key(&ps).0;
    open_vault(&mut svm, &victim, program_id, genesis, ps, 2 * LAMPORTS_PER_SOL);

    // Victim creates their (relayer-scoped) buffer.
    let victim_sigbuf = sigbuf_pda(&genesis, &victim.pubkey(), &program_id);
    send(
        &mut svm,
        &victim,
        &[ix(
            program_id,
            vec![
                AccountMeta::new(victim_sigbuf, false),
                AccountMeta::new(victim.pubkey(), true),
                AccountMeta::new_readonly(system_program::ID, false),
            ],
            &VaultInstruction::InitSigBuffer { genesis_pubkey: genesis },
        )],
    );

    // Attacker tries to overwrite the victim's buffer, signing as themselves.
    let tx = Transaction::new_signed_with_payer(
        &[ix(
            program_id,
            vec![
                AccountMeta::new(victim_sigbuf, false),
                AccountMeta::new_readonly(attacker.pubkey(), true),
            ],
            &VaultInstruction::WriteSigBuffer { offset: 0, chunk: vec![0xFFu8; 100] },
        )],
        Some(&attacker.pubkey()),
        &[&attacker],
        svm.latest_blockhash(),
    );
    assert!(
        svm.send_transaction(tx).is_err(),
        "attacker must not be able to write to the victim's buffer",
    );
}
