//! Echo-broadcast round for identifiable abort (REQ-CUS-004, Goldwasser–Lindell). A
//! malicious party can *equivocate* — send different round-one messages to different
//! receivers — which a plain point-to-point round cannot detect. After round one, every
//! receiver echoes a hash of the full set of messages it received; if any two receivers'
//! hashes disagree, some sender equivocated, and the disagreement localizes to that exact
//! sender. This converts a silent inconsistency into an **identifiable abort**: the honest
//! parties learn *which* party cheated.
use bsv::{double_sha256, Hash256};

/// One receiver's view of round one: `messages[s]` is the message it received from sender
/// `s` (its own message included at its own index).
#[derive(Clone, Debug)]
pub struct PartyView {
    /// The receiving party's index.
    pub receiver: usize,
    /// The message received from each sender, indexed by sender.
    pub messages: Vec<Vec<u8>>,
}

/// The outcome of the echo round.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EchoOutcome {
    /// All receivers saw the same transcript; its hash is returned (the agreed value).
    Consistent(Hash256),
    /// The sender at this index equivocated (sent different messages to different
    /// receivers) — an identifiable abort.
    Equivocator(usize),
}

/// The transcript hash a receiver echoes: a collision-resistant commitment to the ordered
/// `(sender, message)` set it received.
#[must_use]
pub fn transcript_hash(messages: &[Vec<u8>]) -> Hash256 {
    let mut buffer = Vec::new();
    for (sender, message) in messages.iter().enumerate() {
        buffer.extend_from_slice(&u64::try_from(sender).unwrap_or(0).to_be_bytes());
        buffer.extend_from_slice(&u64::try_from(message.len()).unwrap_or(0).to_be_bytes());
        buffer.extend_from_slice(message);
    }
    double_sha256(&buffer)
}

/// Run the echo round over every receiver's view. If all transcripts agree the round is
/// consistent; otherwise the equivocating sender is identified.
#[must_use]
pub fn run_echo_round(views: &[PartyView]) -> EchoOutcome {
    let Some(first) = views.first() else {
        return EchoOutcome::Consistent(double_sha256(&[]));
    };
    let agreed = transcript_hash(&first.messages);
    if views
        .iter()
        .all(|view| transcript_hash(&view.messages).internal() == agreed.internal())
    {
        return EchoOutcome::Consistent(agreed);
    }
    // Transcripts disagree: find the sender whose message differs across receivers.
    let sender_count = views
        .iter()
        .map(|view| view.messages.len())
        .max()
        .unwrap_or(0);
    for sender in 0..sender_count {
        let mut reference: Option<&Vec<u8>> = None;
        for view in views {
            if let Some(message) = view.messages.get(sender) {
                match reference {
                    None => reference = Some(message),
                    Some(seen) if seen != message => return EchoOutcome::Equivocator(sender),
                    Some(_) => {}
                }
            }
        }
    }
    // Disagreement with no single differing sender (e.g. ragged views): blame the last.
    EchoOutcome::Equivocator(sender_count.saturating_sub(1))
}
