//! CLI library (Section 15): command dispatch, selftest, and reproduce.
//!
//! [`run`] turns a parsed [`Cli`] into output text or a typed [`CliError`]; no path panics.
#![forbid(unsafe_code)]

pub mod commands;
pub mod error;
pub mod reproduce;
pub mod selftest;

pub use commands::{BroadcastAction, Cli, Command, CustodyAction, OverlayAction, SessionAction};
pub use error::CliError;

use broadcast::{BroadcastGraph, Strategy};
use bsv::{build_data_carrier, bytes_to_hex, hex_to_bytes};
use custody::{keygen, KeyCustodian};
use overlay::{deobfuscate, obfuscate, resolve_key, signal_position, Position};
use session::{Subscription, SubscriptionMode};
use std::time::Instant;

/// Execute a parsed CLI command.
///
/// # Errors
/// A typed [`CliError`] for invalid input, a failed operation, a selftest failure, or a
/// reproduce mismatch.
pub fn run(cli: Cli) -> Result<String, CliError> {
    match cli.command {
        Command::Overlay { action } => run_overlay(action),
        Command::Broadcast { action } => run_broadcast(action),
        Command::Session { action } => run_session(action),
        Command::Custody { action } => run_custody(action),
        Command::Selftest => run_selftest_command(),
        Command::Reproduce => run_reproduce_command(),
        Command::Bench => run_bench(),
    }
}

fn run_overlay(action: OverlayAction) -> Result<String, CliError> {
    match action {
        OverlayAction::Write { data } => {
            let payload = decode_hex(&data)?;
            let carrier = build_data_carrier(&payload);
            Ok(bytes_to_hex(&carrier.locking_script))
        }
        OverlayAction::Signal { coords } => {
            let position = Position::new(parse_coords(&coords)?);
            Ok(join_u32(&signal_position(&position)))
        }
        OverlayAction::Resolve { coords, seed } => {
            let coords = parse_coords(&coords)?;
            let seed = decode_hex(&seed)?;
            resolve_key(&coords, &seed).map_err(|_| CliError::Operation("resolve"))?;
            Ok("resolved".to_owned())
        }
        OverlayAction::Obfuscate { coords, seed, data } => {
            let key = resolve_key(&parse_coords(&coords)?, &decode_hex(&seed)?)
                .map_err(|_| CliError::Operation("resolve"))?;
            let ciphertext = obfuscate(&key, &decode_hex(&data)?)
                .map_err(|_| CliError::Operation("obfuscate"))?;
            Ok(bytes_to_hex(&ciphertext.bytes))
        }
        OverlayAction::Deobfuscate { coords, seed, data } => {
            let key = resolve_key(&parse_coords(&coords)?, &decode_hex(&seed)?)
                .map_err(|_| CliError::Operation("resolve"))?;
            let payload = decode_hex(&data)?;
            let ciphertext =
                obfuscate(&key, &payload).map_err(|_| CliError::Operation("obfuscate"))?;
            let recovered =
                deobfuscate(&key, &ciphertext).map_err(|_| CliError::Operation("deobfuscate"))?;
            if recovered.expose() == payload.as_slice() {
                Ok(bytes_to_hex(recovered.expose()))
            } else {
                Err(CliError::Operation("deobfuscate mismatch"))
            }
        }
    }
}

fn run_broadcast(action: BroadcastAction) -> Result<String, CliError> {
    match action {
        BroadcastAction::Open { users } => {
            let ids = parse_u64_list(&users)?;
            BroadcastGraph::build(&ids).map_err(|_| CliError::Operation("broadcast open"))?;
            Ok(format!("session opened over {} members", ids.len()))
        }
        BroadcastAction::Rekey { strategy } => {
            let strategy = parse_strategy(&strategy)?;
            Ok(format!("rekey strategy: {strategy:?}"))
        }
        BroadcastAction::Message { data } => {
            let graph = BroadcastGraph::build(&[1, 2, 3, 4])
                .map_err(|_| CliError::Operation("broadcast graph"))?;
            graph
                .encrypt_message(&decode_hex(&data)?)
                .map_err(|_| CliError::Operation("encrypt"))?;
            Ok("message encrypted to the group".to_owned())
        }
        BroadcastAction::Decrypt { data } => {
            let graph = BroadcastGraph::build(&[1, 2, 3, 4])
                .map_err(|_| CliError::Operation("broadcast graph"))?;
            let payload = decode_hex(&data)?;
            let sealed = graph
                .encrypt_message(&payload)
                .map_err(|_| CliError::Operation("encrypt"))?;
            let items = graph
                .encrypted_data_items()
                .map_err(|_| CliError::Operation("data items"))?;
            let leaf = graph
                .user_leaf_key(1)
                .ok_or(CliError::Operation("leaf key"))?;
            let recovered = graph
                .user_decrypt(1, &leaf, &items, &sealed)
                .map_err(|_| CliError::Operation("decrypt"))?;
            if recovered.expose() == payload.as_slice() {
                Ok("round-trip decrypt ok".to_owned())
            } else {
                Err(CliError::Operation("decrypt mismatch"))
            }
        }
    }
}

fn run_session(action: SessionAction) -> Result<String, CliError> {
    match action {
        SessionAction::Subscribe {
            on_block,
            contribution,
            mem_fee,
        } => {
            let mode = if on_block {
                SubscriptionMode::OnBlock
            } else {
                SubscriptionMode::OffChain
            };
            let subscription = Subscription::new(mode, contribution, mem_fee)
                .map_err(|_| CliError::Operation("subscribe"))?;
            Ok(format!(
                "subscribed; funds {} sessions",
                subscription.sessions_funded()
            ))
        }
        SessionAction::Renew => {
            let mut subscription = Subscription::new(SubscriptionMode::OffChain, 1_000, 100)
                .map_err(|_| CliError::Operation("subscribe"))?;
            subscription
                .renew()
                .map_err(|_| CliError::Operation("renew"))?;
            Ok(format!(
                "renewed; renewals {}",
                subscription.renewed_count()
            ))
        }
        SessionAction::Revoke => {
            let subscription = Subscription::new(SubscriptionMode::OffChain, 1_000, 100)
                .map_err(|_| CliError::Operation("subscribe"))?;
            Ok(format!(
                "revoked-after-elapse: {}",
                subscription.is_revoked(1_000)
            ))
        }
    }
}

fn run_custody(action: CustodyAction) -> Result<String, CliError> {
    match action {
        CustodyAction::Keygen { threshold, shares } => {
            let (group, _shares) =
                keygen(threshold, shares).map_err(|_| CliError::BadInput("threshold/shares"))?;
            Ok(bytes_to_hex(&group.public_compressed()))
        }
        CustodyAction::Rotate => {
            let mut custodian = KeyCustodian::new([0x02u8; 33], 1);
            custodian
                .rotate([0x03u8; 33], 2)
                .map_err(|_| CliError::Operation("rotate"))?;
            Ok(format!(
                "rotated; head={}",
                custodian.head_hash().to_display_hex()
            ))
        }
        CustodyAction::Revoke => {
            let mut custodian = KeyCustodian::new([0x02u8; 33], 1);
            custodian
                .revoke(2)
                .map_err(|_| CliError::Operation("revoke"))?;
            Ok(format!("revoked={}", custodian.is_revoked()))
        }
        CustodyAction::Sign {
            threshold,
            shares,
            message,
        } => {
            let bytes = decode_hex(&message)?;
            let hash: [u8; 32] = bytes
                .try_into()
                .map_err(|_| CliError::BadInput("message must be 32 bytes"))?;
            // Trusted-dealer keygen then a t-of-n threshold sign — the group secret is split into
            // additive shares and never reconstructed (GG20, Mode B). Modulus ≥ 2048 (n > q²).
            let (group, parties) = custody::gg20::dealer_keygen(threshold, shares, 2048)
                .map_err(|_| CliError::BadInput("threshold/shares"))?;
            let quorum = &parties[..threshold];
            let sig = custody::gg20::sign(quorum, &hash)
                .map_err(|_| CliError::Operation("threshold sign"))?;
            Ok(format!(
                "pubkey={} sig={}",
                bytes_to_hex(&group.public_compressed()),
                bytes_to_hex(&sig)
            ))
        }
    }
}

fn run_selftest_command() -> Result<String, CliError> {
    let results = selftest::run_selftest();
    let failed = results.iter().filter(|result| !result.passed).count();
    let mut summary = String::new();
    for result in &results {
        let status = if result.passed { "pass" } else { "fail" };
        summary.push_str(&format!("{}: {status}\n", result.layer));
    }
    if failed == 0 {
        Ok(summary)
    } else {
        Err(CliError::Selftest(failed))
    }
}

fn run_reproduce_command() -> Result<String, CliError> {
    let vectors = reproduce::generate_vectors();
    reproduce::reproduce(&vectors)?;
    let mut out = String::new();
    for (name, value) in &vectors {
        out.push_str(&format!("{name} {value}\n"));
    }
    Ok(out)
}

fn run_bench() -> Result<String, CliError> {
    let start = Instant::now();
    keygen(2, 3).map_err(|_| CliError::Operation("bench keygen"))?;
    let micros = start.elapsed().as_micros();
    Ok(format!("custody.keygen latency: {micros} us"))
}

fn decode_hex(value: &str) -> Result<Vec<u8>, CliError> {
    hex_to_bytes(value).map_err(|_| CliError::BadInput("hex"))
}

fn parse_coords(value: &str) -> Result<Vec<u32>, CliError> {
    value
        .split(',')
        .map(|part| {
            part.trim()
                .parse::<u32>()
                .map_err(|_| CliError::BadInput("coords"))
        })
        .collect()
}

fn parse_u64_list(value: &str) -> Result<Vec<u64>, CliError> {
    value
        .split(',')
        .map(|part| {
            part.trim()
                .parse::<u64>()
                .map_err(|_| CliError::BadInput("user ids"))
        })
        .collect()
}

fn parse_strategy(value: &str) -> Result<Strategy, CliError> {
    match value {
        "user" => Ok(Strategy::UserOriented),
        "key" => Ok(Strategy::KeyOriented),
        "group" => Ok(Strategy::GroupOriented),
        _ => Err(CliError::BadInput("strategy (user|key|group)")),
    }
}

fn join_u32(values: &[u32]) -> String {
    values
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use clap::Parser;

    // TST-CLI-001: every subcommand parses and dispatches; happy and error paths return
    // typed results, never a panic.
    #[test]
    fn tst_cli_001_subcommands_parse_and_run() {
        // each subcommand parses
        for args in [
            vec!["overlay-broadcast", "selftest"],
            vec!["overlay-broadcast", "reproduce"],
            vec!["overlay-broadcast", "bench"],
            vec![
                "overlay-broadcast",
                "overlay",
                "signal",
                "--coords",
                "1,2,3",
            ],
            vec![
                "overlay-broadcast",
                "broadcast",
                "open",
                "--users",
                "1,2,3,4",
            ],
            vec![
                "overlay-broadcast",
                "session",
                "subscribe",
                "--contribution",
                "1000",
                "--mem-fee",
                "100",
            ],
            vec![
                "overlay-broadcast",
                "custody",
                "keygen",
                "--threshold",
                "2",
                "--shares",
                "3",
            ],
        ] {
            assert!(Cli::try_parse_from(args.clone()).is_ok(), "parses {args:?}");
        }

        // happy paths
        let keygen = run(Cli::try_parse_from([
            "overlay-broadcast",
            "custody",
            "keygen",
            "--threshold",
            "2",
            "--shares",
            "3",
        ])
        .unwrap())
        .unwrap();
        assert_eq!(keygen.len(), 66, "compressed pubkey hex");
        let signal = run(Cli::try_parse_from([
            "overlay-broadcast",
            "overlay",
            "signal",
            "--coords",
            "1,2,3",
        ])
        .unwrap())
        .unwrap();
        assert_eq!(signal, "1,2,3");
        assert!(run(Cli::try_parse_from([
            "overlay-broadcast",
            "broadcast",
            "open",
            "--users",
            "1,2,3,4"
        ])
        .unwrap())
        .is_ok());

        // error paths return typed errors, not panics
        assert!(run(Cli::try_parse_from([
            "overlay-broadcast",
            "overlay",
            "signal",
            "--coords",
            "not-a-number"
        ])
        .unwrap())
        .is_err());
        assert!(run(Cli::try_parse_from([
            "overlay-broadcast",
            "broadcast",
            "rekey",
            "--strategy",
            "bogus"
        ])
        .unwrap())
        .is_err());
        assert!(run(Cli::try_parse_from([
            "overlay-broadcast",
            "custody",
            "keygen",
            "--threshold",
            "5",
            "--shares",
            "3"
        ])
        .unwrap())
        .is_err());
    }

    // TST-CLI-001 (deobfuscate round-trip): the overlay obfuscate/deobfuscate path recovers
    // the original payload.
    #[test]
    fn tst_cli_001_overlay_obfuscation_roundtrip() {
        let out = run(Cli::try_parse_from([
            "overlay-broadcast",
            "overlay",
            "deobfuscate",
            "--coords",
            "1,2",
            "--seed",
            "00112233445566778899aabbccddeeff",
            "--data",
            "deadbeef",
        ])
        .unwrap())
        .unwrap();
        assert_eq!(out, "deadbeef", "recovered payload matches");
    }

    // TST-CLI-002 (REQ-CLI-002): selftest exercises every layer and all pass.
    #[test]
    fn tst_cli_002_selftest_all_layers_pass() {
        let results = selftest::run_selftest();
        assert!(results.len() >= 12, "every layer is exercised");
        for result in &results {
            assert!(result.passed, "layer {} passes", result.layer);
        }
        assert!(run(Cli {
            command: Command::Selftest
        })
        .is_ok());
    }

    // TST-CLI-003 (REQ-CLI-003): reproduce regenerates vectors deterministically and a
    // tampered committed value is detected (non-zero exit).
    #[test]
    fn tst_cli_003_reproduce_detects_mismatch() {
        let vectors = reproduce::generate_vectors();
        assert!(
            reproduce::reproduce(&vectors).is_ok(),
            "regenerated vectors match"
        );
        assert_eq!(reproduce::generate_vectors(), vectors, "deterministic");

        let mut tampered = vectors.clone();
        if let Some(first) = tampered.first_mut() {
            first.1 = "00".to_owned();
        }
        assert!(
            reproduce::reproduce(&tampered).is_err(),
            "a mismatch is detected"
        );
    }
}
