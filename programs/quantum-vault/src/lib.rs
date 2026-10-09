//! Quantum-resistant vault for Solana — native (no framework) implementation.
//!
//! Funds live in a PDA whose withdrawals are authorized not by an Ed25519 key
//! (which Shor's algorithm would break) but by a **Winternitz one-time
//! signature** verified on-chain with cheap Keccak hashing.
//!
//! ## Why native + a signature buffer
//!
//! Using a low Winternitz parameter (`W=16`) cuts on-chain hashing ~9× — but the
//! signature grows to 1652 bytes, past Solana's 1232-byte transaction limit. So a
//! spend is a short sequence: create a **signature buffer** PDA, write the
//! signature into it across a couple of transactions, then run the spend, which
//! reads the buffer, verifies, moves funds, rotates the one-time key, and closes
//! the buffer. Going native (instead of Anchor) keeps the per-instruction
//! overhead minimal now that hashing is no longer the dominant cost.
//!
//! ## Vault pattern
//!
//! A WOTS key signs only once. Every spend commits the *next* public key; on
//! success the vault rotates `current_pubkey` to it, retiring the spent key. The
//! vault address is derived from an immutable `genesis_pubkey`, so the deposit
//! address never changes. Authorization is purely cryptographic — any relayer
//! may submit the transactions; only a valid WOTS signature moves funds.

#![forbid(unsafe_code)]

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    declare_id,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction,
    sysvar::Sysvar,
};

declare_id!("B9NvpqrBERJxPjku8JMKZTedYTKtTxQgrhpzkiAoRDv5");

/// The SPL Token program.
const SPL_TOKEN_ID: Pubkey =
    solana_program::pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");

const VAULT_TAG: u8 = 1;
const SIGBUF_TAG: u8 = 2;

/// Vault account: `[tag(1)][current_pubkey(28)][bump(1)][pub_seed(28)]`.
/// `pub_seed` is the vault's WOTS+ tweak — fixed for the vault's whole life.
const VAULT_LEN: usize = 1 + 28 + 1 + 28;
/// Signature buffer account: `[tag(1)][bump(1)][payer(32)][signature(1652)]`.
/// The buffer is bound to the relayer that created it, and only that relayer can
/// write to it — so no one can corrupt a victim's in-flight signature.
const SIGBUF_LEN: usize = 2 + 32 + wots::SIGNATURE_BYTES;
/// Byte offset where the signature begins inside the buffer.
const SIGBUF_SIG_OFFSET: usize = 2 + 32;

/// Domain-separation tags so a signature for one action type can never be
/// replayed as another.
const DOMAIN_SPEND_SOL: u8 = 0x01;
const DOMAIN_SPEND_TOKEN: u8 = 0x02;

const VAULT_SEED: &[u8] = b"vault";
const SIGBUF_SEED: &[u8] = b"sigbuf";

/// Program errors (surfaced as `ProgramError::Custom`).
#[derive(Clone, Copy)]
#[repr(u32)]
pub enum VaultError {
    InvalidSignature = 0,
    InsufficientFunds = 1,
    BadTokenProgram = 2,
    BufferTooSmall = 3,
    UnauthorizedBuffer = 4,
}

impl From<VaultError> for ProgramError {
    fn from(e: VaultError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

/// Instruction set. Borsh-serialized; the leading byte is the variant index.
#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub enum VaultInstruction {
    /// Create a vault bound to `genesis_pubkey` (with WOTS+ tweak `pub_seed`) and
    /// fund it with `deposit`. Accounts: `[vault(w), funder(w,s), system_program]`.
    OpenVault {
        genesis_pubkey: [u8; 28],
        pub_seed: [u8; 28],
        deposit: u64,
    },
    /// Create the relayer-scoped signature buffer PDA `["sigbuf", genesis, payer]`.
    /// Accounts: `[sig_buffer(w), payer(w,s), system_program]`.
    InitSigBuffer { genesis_pubkey: [u8; 28] },
    /// Write `chunk` into the signature buffer at `offset`. Only the buffer's
    /// own relayer (payer) may write. Accounts: `[sig_buffer(w), payer(s)]`.
    WriteSigBuffer { offset: u16, chunk: Vec<u8> },
    /// Verify the buffered signature, withdraw `amount` lamports, rotate, close.
    /// Accounts: `[vault(w), sig_buffer(w), destination(w), rent_refund(w)]`.
    SpendSol {
        genesis_pubkey: [u8; 28],
        amount: u64,
        next_pubkey: [u8; 28],
    },
    /// Verify the buffered signature, withdraw `amount` SPL tokens, rotate, close.
    /// Accounts: `[vault(w), sig_buffer(w), mint, vault_token(w),
    ///            destination_token(w), token_program, rent_refund(w)]`.
    SpendToken {
        genesis_pubkey: [u8; 28],
        amount: u64,
        next_pubkey: [u8; 28],
    },
}

#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    match VaultInstruction::try_from_slice(data)
        .map_err(|_| ProgramError::InvalidInstructionData)?
    {
        VaultInstruction::OpenVault { genesis_pubkey, pub_seed, deposit } => {
            open_vault(program_id, accounts, genesis_pubkey, pub_seed, deposit)
        }
        VaultInstruction::InitSigBuffer { genesis_pubkey } => {
            init_sig_buffer(program_id, accounts, genesis_pubkey)
        }
        VaultInstruction::WriteSigBuffer { offset, chunk } => {
            write_sig_buffer(program_id, accounts, offset, chunk)
        }
        VaultInstruction::SpendSol { genesis_pubkey, amount, next_pubkey } => {
            spend_sol(program_id, accounts, genesis_pubkey, amount, next_pubkey)
        }
        VaultInstruction::SpendToken { genesis_pubkey, amount, next_pubkey } => {
            spend_token(program_id, accounts, genesis_pubkey, amount, next_pubkey)
        }
    }
}

fn open_vault(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    genesis: [u8; 28],
    pub_seed: [u8; 28],
    deposit: u64,
) -> ProgramResult {
    let iter = &mut accounts.iter();
    let vault = next_account_info(iter)?;
    let funder = next_account_info(iter)?;
    let system_program = next_account_info(iter)?;

    let (pda, bump) = Pubkey::find_program_address(&[VAULT_SEED, &genesis], program_id);
    if pda != *vault.key {
        return Err(ProgramError::InvalidSeeds);
    }
    if !funder.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let lamports = Rent::get()?.minimum_balance(VAULT_LEN) + deposit;
    invoke_signed(
        &system_instruction::create_account(
            funder.key,
            vault.key,
            lamports,
            VAULT_LEN as u64,
            program_id,
        ),
        &[funder.clone(), vault.clone(), system_program.clone()],
        &[&[VAULT_SEED, &genesis, &[bump]]],
    )?;

    let mut d = vault.try_borrow_mut_data()?;
    d[0] = VAULT_TAG;
    d[1..29].copy_from_slice(&genesis); // current_pubkey starts at genesis
    d[29] = bump;
    d[30..58].copy_from_slice(&pub_seed);
    Ok(())
}

fn init_sig_buffer(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    genesis: [u8; 28],
) -> ProgramResult {
    let iter = &mut accounts.iter();
    let buffer = next_account_info(iter)?;
    let payer = next_account_info(iter)?;
    let system_program = next_account_info(iter)?;

    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let (pda, bump) =
        Pubkey::find_program_address(&[SIGBUF_SEED, &genesis, payer.key.as_ref()], program_id);
    if pda != *buffer.key {
        return Err(ProgramError::InvalidSeeds);
    }

    let lamports = Rent::get()?.minimum_balance(SIGBUF_LEN);
    invoke_signed(
        &system_instruction::create_account(
            payer.key,
            buffer.key,
            lamports,
            SIGBUF_LEN as u64,
            program_id,
        ),
        &[payer.clone(), buffer.clone(), system_program.clone()],
        &[&[SIGBUF_SEED, &genesis, payer.key.as_ref(), &[bump]]],
    )?;

    let mut d = buffer.try_borrow_mut_data()?;
    d[0] = SIGBUF_TAG;
    d[1] = bump;
    d[2..34].copy_from_slice(payer.key.as_ref());
    Ok(())
}

fn write_sig_buffer(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    offset: u16,
    chunk: Vec<u8>,
) -> ProgramResult {
    let iter = &mut accounts.iter();
    let buffer = next_account_info(iter)?;
    let payer = next_account_info(iter)?;

    if buffer.owner != program_id {
        return Err(ProgramError::IllegalOwner);
    }
    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let mut d = buffer.try_borrow_mut_data()?;
    if d.len() != SIGBUF_LEN || d[0] != SIGBUF_TAG {
        return Err(ProgramError::InvalidAccountData);
    }
    // Only the relayer that created the buffer may write to it.
    if d[2..34] != *payer.key.as_ref() {
        return Err(VaultError::UnauthorizedBuffer.into());
    }
    let start = SIGBUF_SIG_OFFSET + offset as usize;
    let end = start
        .checked_add(chunk.len())
        .ok_or(VaultError::BufferTooSmall)?;
    if end > SIGBUF_LEN {
        return Err(VaultError::BufferTooSmall.into());
    }
    d[start..end].copy_from_slice(&chunk);
    Ok(())
}

// `#[inline(never)]` keeps the 1652-byte signature buffers out of the shared
// `process_instruction` frame, which would otherwise exceed BPF's 4096-byte stack.
#[inline(never)]
fn spend_sol(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    genesis: [u8; 28],
    amount: u64,
    next: [u8; 28],
) -> ProgramResult {
    let iter = &mut accounts.iter();
    let vault = next_account_info(iter)?;
    let buffer = next_account_info(iter)?;
    let destination = next_account_info(iter)?;
    let rent_refund = next_account_info(iter)?;

    let (current, pub_seed) = read_vault(vault, program_id, &genesis)?;
    let message = spend_sol_message(&genesis, amount, destination.key, &next);
    verify_buffered(buffer, program_id, &genesis, &current, &pub_seed, &message)?;

    let min = Rent::get()?.minimum_balance(vault.data_len());
    let available = vault.lamports().saturating_sub(min);
    if amount > available {
        return Err(VaultError::InsufficientFunds.into());
    }
    **vault.try_borrow_mut_lamports()? -= amount;
    **destination.try_borrow_mut_lamports()? += amount;

    rotate(vault, &next)?;
    close_account(buffer, rent_refund)
}

#[inline(never)]
fn spend_token(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    genesis: [u8; 28],
    amount: u64,
    next: [u8; 28],
) -> ProgramResult {
    let iter = &mut accounts.iter();
    let vault = next_account_info(iter)?;
    let buffer = next_account_info(iter)?;
    let mint = next_account_info(iter)?;
    let vault_token = next_account_info(iter)?;
    let destination_token = next_account_info(iter)?;
    let token_program = next_account_info(iter)?;
    let rent_refund = next_account_info(iter)?;

    if *token_program.key != SPL_TOKEN_ID {
        return Err(VaultError::BadTokenProgram.into());
    }

    if *mint.owner != SPL_TOKEN_ID || mint.data_len() < 82 {
        return Err(ProgramError::InvalidAccountData);
    }

    let (current, pub_seed) = read_vault(vault, program_id, &genesis)?;
    let bump = vault.try_borrow_data()?[29];
    let message = spend_token_message(&genesis, mint.key, amount, destination_token.key, &next);
    verify_buffered(buffer, program_id, &genesis, &current, &pub_seed, &message)?;

    // SPL Token `TransferChecked` (tag 12): [source(w), mint, destination(w),
    // authority(s)]. Binding the mint + decimals means the transfer can't be
    // redirected to a different token than the one the signature authorized.
    let decimals = mint.try_borrow_data()?[44];
    let mut data = Vec::with_capacity(10);
    data.push(12u8);
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);
    let ix = Instruction {
        program_id: *token_program.key,
        accounts: vec![
            AccountMeta::new(*vault_token.key, false),
            AccountMeta::new_readonly(*mint.key, false),
            AccountMeta::new(*destination_token.key, false),
            AccountMeta::new_readonly(*vault.key, true),
        ],
        data,
    };
    invoke_signed(
        &ix,
        &[
            vault_token.clone(),
            mint.clone(),
            destination_token.clone(),
            vault.clone(),
            token_program.clone(),
        ],
        &[&[VAULT_SEED, &genesis, &[bump]]],
    )?;

    rotate(vault, &next)?;
    close_account(buffer, rent_refund)
}

// --- helpers ---------------------------------------------------------------

/// Returns `(current_pubkey, pub_seed)`.
fn read_vault(
    vault: &AccountInfo,
    program_id: &Pubkey,
    genesis: &[u8; 28],
) -> Result<([u8; 28], [u8; 28]), ProgramError> {
    if vault.owner != program_id {
        return Err(ProgramError::IllegalOwner);
    }
    let d = vault.try_borrow_data()?;
    if d.len() != VAULT_LEN || d[0] != VAULT_TAG {
        return Err(ProgramError::InvalidAccountData);
    }
    let bump = d[29];
    let expected = Pubkey::create_program_address(&[VAULT_SEED, genesis, &[bump]], program_id)
        .map_err(|_| ProgramError::InvalidSeeds)?;
    if expected != *vault.key {
        return Err(ProgramError::InvalidSeeds);
    }
    let mut current = [0u8; 28];
    current.copy_from_slice(&d[1..29]);
    let mut pub_seed = [0u8; 28];
    pub_seed.copy_from_slice(&d[30..58]);
    Ok((current, pub_seed))
}

/// Verify the WOTS signature stored in `buffer` against `current`/`message`,
/// reading the 1652-byte signature straight from account data (no stack copy).
#[inline(never)]
fn verify_buffered(
    buffer: &AccountInfo,
    program_id: &Pubkey,
    genesis: &[u8; 28],
    current: &[u8; 28],
    pub_seed: &[u8; 28],
    message: &[u8],
) -> ProgramResult {
    if buffer.owner != program_id {
        return Err(ProgramError::IllegalOwner);
    }
    let d = buffer.try_borrow_data()?;
    if d.len() != SIGBUF_LEN || d[0] != SIGBUF_TAG {
        return Err(ProgramError::InvalidAccountData);
    }
    // Confirm this is the canonical buffer for (genesis, its stored relayer).
    let expected = Pubkey::create_program_address(
        &[SIGBUF_SEED, genesis, &d[2..34], &[d[1]]],
        program_id,
    )
    .map_err(|_| ProgramError::InvalidSeeds)?;
    if expected != *buffer.key {
        return Err(ProgramError::InvalidSeeds);
    }
    let pk = wots::PublicKey(*current);
    if pk.verify_slice(
        message,
        &d[SIGBUF_SIG_OFFSET..SIGBUF_SIG_OFFSET + wots::SIGNATURE_BYTES],
        pub_seed,
    ) {
        Ok(())
    } else {
        Err(VaultError::InvalidSignature.into())
    }
}

fn rotate(vault: &AccountInfo, next: &[u8; 28]) -> ProgramResult {
    let mut d = vault.try_borrow_mut_data()?;
    d[1..29].copy_from_slice(next);
    Ok(())
}

/// Drain `account` into `refund` and zero it so the runtime reaps it.
fn close_account(account: &AccountInfo, refund: &AccountInfo) -> ProgramResult {
    let lamports = account.lamports();
    **refund.try_borrow_mut_lamports()? += lamports;
    **account.try_borrow_mut_lamports()? = 0;
    let mut d = account.try_borrow_mut_data()?;
    for b in d.iter_mut() {
        *b = 0;
    }
    Ok(())
}

fn spend_sol_message(genesis: &[u8; 28], amount: u64, destination: &Pubkey, next: &[u8; 28]) -> Vec<u8> {
    let mut m = Vec::with_capacity(1 + 28 + 8 + 32 + 28);
    m.push(DOMAIN_SPEND_SOL);
    m.extend_from_slice(genesis);
    m.extend_from_slice(&amount.to_le_bytes());
    m.extend_from_slice(destination.as_ref());
    m.extend_from_slice(next);
    m
}

fn spend_token_message(
    genesis: &[u8; 28],
    mint: &Pubkey,
    amount: u64,
    destination: &Pubkey,
    next: &[u8; 28],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(1 + 28 + 32 + 8 + 32 + 28);
    m.push(DOMAIN_SPEND_TOKEN);
    m.extend_from_slice(genesis);
    m.extend_from_slice(mint.as_ref());
    m.extend_from_slice(&amount.to_le_bytes());
    m.extend_from_slice(destination.as_ref());
    m.extend_from_slice(next);
    m
}
