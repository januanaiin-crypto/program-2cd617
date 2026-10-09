//! Launch-kit client for the vault program (orders/jday-vault.sh). Env: RPC, ADMIN_KEYPAIR (payer), PROGRAM_ID, KIT_STATE.
//!   kit_vault check | probe | probe-keep | refund | inventory   [--send]
//! probe      = open a vault with 0.001 SOL, spend it back to the payer (the vault's rent stays in it)
//! probe-keep = (rehearsal) open a vault with 0.01 SOL whose WOTS seed the kit keeps, owed to a fresh holder address
//! refund     = spend every kit-kept vault back to its holder (users' vaults move only with their own phrase)
//! inventory  = every vault and the SOL above rent it still holds
//! Every send: CU price set, the same signed bytes rebroadcast every 3 s until confirmed or the blockhash expires
//! (then re-signed, up to 3 times), finalized before judging. Last stdout line = one JSON.
use borsh::to_vec;
use quantum_vault::VaultInstruction;
use solana_client::{rpc_client::RpcClient, rpc_config::RpcProgramAccountsConfig, rpc_filter::RpcFilterType};
use solana_sdk::{
    commitment_config::CommitmentConfig,
    compute_budget::ComputeBudgetInstruction,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{read_keypair_file, Keypair, Signature, Signer},
    system_program,
    transaction::Transaction,
};
use std::{str::FromStr, thread::sleep, time::Duration};
use wots::SecretKey;

const VAULT_LEN: u64 = 58;
const CHUNK: usize = 900;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).cloned().unwrap_or_default();
    let send = args.iter().any(|a| a == "--send");
    let r = std::panic::catch_unwind(|| run(&cmd, send));
    if let Err(e) = r {
        let msg = e.downcast_ref::<String>().cloned().or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default();
        println!("{{\"stage\":\"{}\",\"ok\":false,\"send\":{send},\"error\":{:?}}}", stage(&cmd), msg);
        std::process::exit(1);
    }
}
fn stage(cmd: &str) -> &str { if cmd == "probe-keep" { "probe" } else { cmd } }

struct Ctx { c: RpcClient, pid: Pubkey, payer: Keypair, state: String, send: bool }

fn run(cmd: &str, send: bool) {
    let rpc = std::env::var("RPC").expect("RPC not set");
    let pid = Pubkey::from_str(&std::env::var("PROGRAM_ID").unwrap_or(quantum_vault::ID.to_string())).expect("PROGRAM_ID");
    let payer = read_keypair_file(std::env::var("ADMIN_KEYPAIR").expect("ADMIN_KEYPAIR not set")).expect("read ADMIN_KEYPAIR");
    let state = std::env::var("KIT_STATE").unwrap_or("/tmp".into());
    let x = Ctx { c: RpcClient::new_with_commitment(rpc, CommitmentConfig::confirmed()), pid, payer, state, send };
    match cmd {
        "check" => check(&x),
        "probe" => probe(&x),
        "probe-keep" => probe_keep(&x),
        "refund" => refund(&x),
        "inventory" => { let (n, with, funds) = inventory(&x, &[]); done("inventory", send, &format!(",\"vaults\":{n},\"withFunds\":{with},\"fundsLamports\":{funds}")) }
        _ => panic!("usage: kit_vault check|probe|probe-keep|refund|inventory [--send]"),
    }
}
fn done(stage: &str, send: bool, extra: &str) { println!("{{\"stage\":\"{stage}\",\"ok\":true,\"send\":{send}{extra}}}"); }

fn check(x: &Ctx) {
    let loader = Pubkey::from_str("BPFLoaderUpgradeab1e11111111111111111111111").unwrap();
    let pd = Pubkey::find_program_address(&[x.pid.as_ref()], &loader).0;
    let p = x.c.get_account_with_commitment(&x.pid, CommitmentConfig::confirmed()).unwrap().value;
    let d = x.c.get_account_with_commitment(&pd, CommitmentConfig::confirmed()).unwrap().value;
    let auth = d.as_ref().filter(|a| a.data.len() >= 45 && a.data[12] == 1).map(|a| Pubkey::try_from(&a.data[13..45]).unwrap().to_string());
    let deployed = p.as_ref().map_or(false, |a| a.executable) && d.is_some();
    // no config in this program: deployed = ready (the kit reads `initialized`)
    let ok = deployed || p.is_none();
    println!("{{\"stage\":\"check\",\"ok\":{ok},\"send\":false,\"deployed\":{deployed},\"initialized\":{deployed},\"paused\":false,\"closing\":false,\"authority\":{}}}",
        auth.map_or("null".into(), |a| format!("\"{a}\"")));
    if !ok { std::process::exit(1) }
}

// ---------------------------------------------------------------- vault ops
struct Keys { genesis: [u8; 28], ps: [u8; 28], sk: SecretKey, next: [u8; 28] }
fn keys(seed: &[u8; 32]) -> Keys {
    let sk = SecretKey::from_seed(seed);
    let ps = wots::public_seed(seed);
    let mut s1 = *seed; s1[31] ^= 0xA5;
    Keys { genesis: sk.public_key(&ps).0, next: SecretKey::from_seed(&s1).public_key(&ps).0, ps, sk }
}
fn vault_of(x: &Ctx, g: &[u8; 28]) -> Pubkey { Pubkey::find_program_address(&[b"vault", g], &x.pid).0 }
fn ix(x: &Ctx, accounts: Vec<AccountMeta>, d: &VaultInstruction) -> Instruction { Instruction { program_id: x.pid, accounts, data: to_vec(d).unwrap() } }
fn open(x: &Ctx, k: &Keys, deposit: u64) {
    let v = vault_of(x, &k.genesis);
    tx(x, "open_vault", vec![ix(x, vec![AccountMeta::new(v, false), AccountMeta::new(x.payer.pubkey(), true), AccountMeta::new_readonly(system_program::ID, false)],
        &VaultInstruction::OpenVault { genesis_pubkey: k.genesis, pub_seed: k.ps, deposit })]);
}
// WOTS-signed SOL spend: buffer, upload the signature, spend (vault rotates to `next`, buffer rent back to the payer)
fn spend(x: &Ctx, k: &Keys, amount: u64, dest: &Pubkey) {
    let v = vault_of(x, &k.genesis);
    let buf = Pubkey::find_program_address(&[b"sigbuf", &k.genesis, x.payer.pubkey().as_ref()], &x.pid).0;
    let mut m = vec![0x01u8]; m.extend_from_slice(&k.genesis); m.extend_from_slice(&amount.to_le_bytes()); m.extend_from_slice(dest.as_ref()); m.extend_from_slice(&k.next);
    let sig = k.sk.sign(&m, &k.ps).to_bytes();
    if x.c.get_account_with_commitment(&buf, CommitmentConfig::confirmed()).unwrap().value.is_none() {
        tx(x, "init_sig_buffer", vec![ix(x, vec![AccountMeta::new(buf, false), AccountMeta::new(x.payer.pubkey(), true), AccountMeta::new_readonly(system_program::ID, false)],
            &VaultInstruction::InitSigBuffer { genesis_pubkey: k.genesis })]);
    }
    let mut off = 0;
    while off < sig.len() {
        let end = (off + CHUNK).min(sig.len());
        tx(x, &format!("write_sig_buffer @{off}"), vec![ix(x, vec![AccountMeta::new(buf, false), AccountMeta::new_readonly(x.payer.pubkey(), true)],
            &VaultInstruction::WriteSigBuffer { offset: off as u16, chunk: sig[off..end].to_vec() })]);
        off = end;
    }
    tx(x, "spend_sol", vec![ix(x, vec![AccountMeta::new(v, false), AccountMeta::new(buf, false), AccountMeta::new(*dest, false), AccountMeta::new(x.payer.pubkey(), false)],
        &VaultInstruction::SpendSol { genesis_pubkey: k.genesis, amount, next_pubkey: k.next })]);
}
fn available(x: &Ctx, v: &Pubkey) -> u64 {
    let a = x.c.get_account_with_commitment(v, CommitmentConfig::finalized()).unwrap().value;
    a.map_or(0, |a| a.lamports.saturating_sub(x.c.get_minimum_balance_for_rent_exemption(a.data.len()).unwrap()))
}
fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
fn unhex(s: &str) -> [u8; 32] { let mut o = [0u8; 32]; for i in 0..32 { o[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap() } o }
fn fresh_seed() -> [u8; 32] { let k = Keypair::new(); let mut s = [0u8; 32]; s.copy_from_slice(&k.to_bytes()[..32]); s }

fn probe(x: &Ctx) {
    let deposit = 1_000_000u64;
    if !x.send { println!("plan: open a vault with 0.001 SOL, spend it back to {} (the vault keeps its ~0.00095 SOL rent)", x.payer.pubkey()); return done("probe", false, ",\"needSol\":0.005"); }
    let before = x.c.get_balance(&x.payer.pubkey()).unwrap();
    let k = keys(&fresh_seed());
    open(x, &k, deposit);
    let v = vault_of(x, &k.genesis);
    let a = available(x, &v);
    if a < deposit { panic!("vault holds {a} above rent, expected {deposit}") }
    spend(x, &k, deposit, &x.payer.pubkey());
    if available(x, &v) != 0 { panic!("vault still holds SOL above rent after the spend") }
    let spent = before - x.c.get_balance(&x.payer.pubkey()).unwrap();
    println!("probe round trip: {deposit} lamports in and back; cost {spent} (vault rent + fees)");
    if spent > 3_000_000 { panic!("probe cost {spent} lamports: the deposit did not come back") }
    done("probe", true, &format!(",\"needSol\":0.005,\"vault\":\"{v}\",\"costLamports\":{spent}"))
}

fn keep_file(x: &Ctx) -> String { format!("{}/vault-probe.txt", x.state) }
fn probe_keep(x: &Ctx) {
    if std::env::var("CLUSTER").as_deref() == Ok("mainnet") { panic!("probe-keep is for rehearsals only") }
    if !x.send { return done("probe", false, ",\"needSol\":0.02") }
    let f = keep_file(x);
    let (seed, holder) = match std::fs::read_to_string(&f) {
        Ok(t) => { let mut it = t.split_whitespace(); (unhex(it.next().unwrap()), Pubkey::from_str(it.next().unwrap()).unwrap()) }
        Err(_) => { let s = fresh_seed(); let h = Keypair::new().pubkey(); std::fs::write(&f, format!("{} {}\n", hex(&s), h)).unwrap(); (s, h) }
    };
    let k = keys(&seed);
    let v = vault_of(x, &k.genesis);
    let deposit = 10_000_000u64;
    if x.c.get_account_with_commitment(&v, CommitmentConfig::confirmed()).unwrap().value.is_none() { open(x, &k, deposit) }
    let kept = available(x, &v);
    println!("kept: vault {v} holds {kept} lamports above rent, owed to {holder}");
    done("probe", true, &format!(",\"keptLamports\":{kept},\"keptHolder\":\"{holder}\",\"vault\":\"{v}\""))
}

fn refund(x: &Ctx) {
    let mut back = 0u64; let mut own = vec![];
    if let Ok(t) = std::fs::read_to_string(keep_file(x)) {
        let mut it = t.split_whitespace();
        let k = keys(&unhex(it.next().unwrap())); let holder = Pubkey::from_str(it.next().unwrap()).unwrap();
        let v = vault_of(x, &k.genesis); own.push(v);
        let a = available(x, &v);
        if a > 0 {
            println!("refund kit vault {v} -> {holder}: {a} lamports");
            if x.send { spend(x, &k, a, &holder); back += a } else { println!("check only: spend {a} back to {holder}") }
        }
    }
    let (n, with, funds) = inventory(x, &own);
    println!("user vaults: {n} open, {with} with SOL above rent ({funds} lamports): only their owners' phrases move it (notice window)");
    done("refund", true, &format!(",\"refundedLamports\":{back},\"userVaults\":{n},\"userWithFunds\":{with},\"userFundsLamports\":{funds}"))
}
fn inventory(x: &Ctx, skip: &[Pubkey]) -> (usize, usize, u64) {
    let cfg = RpcProgramAccountsConfig { filters: Some(vec![RpcFilterType::DataSize(VAULT_LEN)]), ..Default::default() };
    let list = x.c.get_program_accounts_with_config(&x.pid, cfg).unwrap();
    let rent = x.c.get_minimum_balance_for_rent_exemption(VAULT_LEN as usize).unwrap();
    let mut n = 0; let mut with = 0; let mut funds = 0u64;
    for (k, a) in list.iter().filter(|(k, a)| !skip.contains(k) && a.data.first() == Some(&1)) {
        n += 1; let f = a.lamports.saturating_sub(rent);
        if f > 0 { with += 1; funds += f; println!("  vault {k}: {f} lamports above rent") }
    }
    (n, with, funds)
}

// ---------------------------------------------------------------- send until landed
fn tx(x: &Ctx, label: &str, ixs: Vec<Instruction>) {
    let mut all = vec![ComputeBudgetInstruction::set_compute_unit_limit(200_000), ComputeBudgetInstruction::set_compute_unit_price(100_000)];
    all.extend(ixs);
    for attempt in 1..=3 {
        let bh = x.c.get_latest_blockhash().unwrap();
        let t = Transaction::new_signed_with_payer(&all, Some(&x.payer.pubkey()), &[&x.payer], bh);
        let sim = x.c.simulate_transaction(&t).unwrap().value;
        if let Some(e) = sim.err { panic!("{label}: simulation failed {e:?} {:?}", sim.logs.unwrap_or_default().iter().rev().take(4).collect::<Vec<_>>()) }
        if !x.send { println!("check only {label}: {} CU", sim.units_consumed.unwrap_or(0)); return }
        let sig: Signature = t.signatures[0];
        println!("sent {label}: {sig}");
        let mut landed = false;
        for i in 0.. {
            if i % 3 == 0 { if let Err(e) = x.c.send_transaction_with_config(&t, solana_client::rpc_config::RpcSendTransactionConfig { skip_preflight: true, max_retries: Some(0), ..Default::default() }) { println!("rebroadcast {label}: {e}") } }
            sleep(Duration::from_secs(1));
            if let Some(st) = x.c.get_signature_statuses(&[sig]).unwrap().value[0].clone() {
                if let Some(e) = st.err { panic!("{label}: failed {e:?} {sig}") }
                if st.confirmations.is_none() || st.confirmations.unwrap_or(0) >= 1 { landed = true; break }
            }
            if i % 3 == 2 && !x.c.is_blockhash_valid(&bh, CommitmentConfig::processed()).unwrap_or(true) { break }
        }
        if !landed { println!("{label}: blockhash expired without landing {sig}: re-signing (try {})", attempt + 1); continue }
        for _ in 0..90 {
            if x.c.confirm_transaction_with_commitment(&sig, CommitmentConfig::finalized()).map(|r| r.value).unwrap_or(false) { println!("ok {label}: {sig}"); return }
            sleep(Duration::from_secs(1));
        }
        panic!("{label}: confirmed but not finalized in 90 s {sig}");
    }
    panic!("{label}: did not land in 3 tries");
}
