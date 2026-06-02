//! The clap command tree (REQ-CLI-001). Every subcommand the spec enumerates is present;
//! argument parsing and validation are handled by clap, and each dispatches to a typed,
//! panic-free handler.
use clap::{Parser, Subcommand};

/// The overlay-broadcast command-line interface.
#[derive(Parser, Debug)]
#[command(name = "overlay-broadcast", about = "Overlay + broadcast service CLI")]
pub struct Cli {
    /// The subcommand to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Top-level subcommands.
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Overlay (EP) operations.
    Overlay {
        /// The overlay action.
        #[command(subcommand)]
        action: OverlayAction,
    },
    /// Broadcast (GB) operations.
    Broadcast {
        /// The broadcast action.
        #[command(subcommand)]
        action: BroadcastAction,
    },
    /// Session lifecycle operations.
    Session {
        /// The session action.
        #[command(subcommand)]
        action: SessionAction,
    },
    /// Custody (threshold key) operations.
    Custody {
        /// The custody action.
        #[command(subcommand)]
        action: CustodyAction,
    },
    /// Exercise every layer end to end.
    Selftest,
    /// Regenerate and diff deterministic vectors.
    Reproduce,
    /// Measure a representative operation's latency.
    Bench,
}

/// Overlay actions (REQ-API-001 overlay.*).
#[derive(Subcommand, Debug)]
pub enum OverlayAction {
    /// Build an OP_RETURN data-carrier for a hex payload.
    Write {
        /// Hex payload.
        #[arg(long)]
        data: String,
    },
    /// Signal a node position (comma-separated coords).
    Signal {
        /// Comma-separated path coordinates.
        #[arg(long)]
        coords: String,
    },
    /// Resolve the key at a signalled position from a seed.
    Resolve {
        /// Comma-separated path coordinates.
        #[arg(long)]
        coords: String,
        /// Hex seed.
        #[arg(long)]
        seed: String,
    },
    /// Obfuscate a hex payload under the position's second-function key.
    Obfuscate {
        /// Comma-separated path coordinates.
        #[arg(long)]
        coords: String,
        /// Hex seed.
        #[arg(long)]
        seed: String,
        /// Hex payload.
        #[arg(long)]
        data: String,
    },
    /// Obfuscate then de-obfuscate a hex payload, returning the recovered bytes.
    Deobfuscate {
        /// Comma-separated path coordinates.
        #[arg(long)]
        coords: String,
        /// Hex seed.
        #[arg(long)]
        seed: String,
        /// Hex payload.
        #[arg(long)]
        data: String,
    },
}

/// Broadcast actions (REQ-API-001 broadcast.*).
#[derive(Subcommand, Debug)]
pub enum BroadcastAction {
    /// Open a session over a comma-separated set of user ids.
    Open {
        /// Comma-separated user ids.
        #[arg(long)]
        users: String,
    },
    /// Select a rekeying strategy (user|key|group).
    Rekey {
        /// The rekeying strategy.
        #[arg(long)]
        strategy: String,
    },
    /// Encrypt a hex message to the current group.
    Message {
        /// Hex message.
        #[arg(long)]
        data: String,
    },
    /// Encrypt then decrypt a message, proving the round-trip.
    Decrypt {
        /// Hex message.
        #[arg(long)]
        data: String,
    },
}

/// Session actions (REQ-API-001 session.*).
#[derive(Subcommand, Debug)]
pub enum SessionAction {
    /// Subscribe (off-chain by default; `--on-block` for on-block).
    Subscribe {
        /// Use the on-block subscription model.
        #[arg(long)]
        on_block: bool,
        /// The contribution amount.
        #[arg(long)]
        contribution: u64,
        /// The per-session membership fee.
        #[arg(long)]
        mem_fee: u64,
    },
    /// Renew a subscription.
    Renew,
    /// Check revocation status for a subscription.
    Revoke,
}

/// Custody actions (REQ-API-001 custody.*).
#[derive(Subcommand, Debug)]
pub enum CustodyAction {
    /// Generate a threshold group key.
    Keygen {
        /// The signing threshold.
        #[arg(long)]
        threshold: usize,
        /// The number of shares.
        #[arg(long)]
        shares: usize,
    },
    /// Rotate a custody key.
    Rotate,
    /// Revoke a custody key.
    Revoke,
    /// Threshold-sign a 32-byte prehash with a t-of-n quorum (Mode B; the group private key is
    /// never reconstructed). Prints the group public key and a standard ECDSA (DER, low-S) signature.
    Sign {
        /// The signing threshold.
        #[arg(long)]
        threshold: usize,
        /// The number of shares.
        #[arg(long)]
        shares: usize,
        /// The 32-byte message hash to sign (hex).
        #[arg(long)]
        message: String,
    },
}
