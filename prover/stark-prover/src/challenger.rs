//! A byte-transparent logging wrapper around the Plonky3 `HashChallenger`.
//!
//! `LoggingChallenger` implements `CanObserve<u8>` and `CanSample<u8>` by forwarding to the
//! wrapped challenger and recording every observed and sampled byte. Wrapped in
//! `SerializingChallenger64`, the upstream `prove` and `verify` functions run completely
//! unmodified; the verifier-side recording is the ground truth that `docs/PROTOCOL.md` and the
//! mirror in `mirror.rs` are checked against.
//!
//! Logging depth: the challenger stored inside a `StarkConfig` is the template (depth 0).
//! `initialise_challenger` clones it once (depth 1); only depth-1 instances write to the log.
//! The proof-of-work grinder clones the depth-1 instance for every candidate witness; those
//! clones are depth 2 and silent, so the log only contains the transcript that both parties
//! actually run.

use std::sync::{Arc, Mutex};

use p3_challenger::{CanObserve, CanSample};
use serde::{Deserialize, Serialize};

/// One run of consecutive observed bytes or consecutive sampled bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RawEvent {
    Observe(Vec<u8>),
    Sample(Vec<u8>),
}

/// The byte-level transcript: alternating runs, consecutive runs of the same kind are merged so
/// the representation is canonical and comparable across implementations.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawTranscript {
    pub events: Vec<RawEvent>,
}

impl RawTranscript {
    pub fn push_observe(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        if let Some(RawEvent::Observe(run)) = self.events.last_mut() {
            run.extend_from_slice(bytes);
        } else {
            self.events.push(RawEvent::Observe(bytes.to_vec()));
        }
    }

    pub fn push_sample(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        if let Some(RawEvent::Sample(run)) = self.events.last_mut() {
            run.extend_from_slice(bytes);
        } else {
            self.events.push(RawEvent::Sample(bytes.to_vec()));
        }
    }

    /// Total observed bytes.
    pub fn observed_len(&self) -> usize {
        self.events
            .iter()
            .map(|e| match e {
                RawEvent::Observe(b) => b.len(),
                RawEvent::Sample(_) => 0,
            })
            .sum()
    }

    /// Total sampled bytes.
    pub fn sampled_len(&self) -> usize {
        self.events
            .iter()
            .map(|e| match e {
                RawEvent::Sample(b) => b.len(),
                RawEvent::Observe(_) => 0,
            })
            .sum()
    }

    /// Human-readable dump, one run per line.
    pub fn dump(&self) -> String {
        let mut out = String::new();
        for (i, e) in self.events.iter().enumerate() {
            match e {
                RawEvent::Observe(b) => out.push_str(&format!(
                    "{i:4} observe {:4} bytes {}\n",
                    b.len(),
                    hex::encode(b)
                )),
                RawEvent::Sample(b) => out.push_str(&format!(
                    "{i:4} sample  {:4} bytes {}\n",
                    b.len(),
                    hex::encode(b)
                )),
            }
        }
        out
    }
}

/// Shared handle to a transcript log.
pub type TranscriptLog = Arc<Mutex<RawTranscript>>;

/// Create an empty shared log.
pub fn new_log() -> TranscriptLog {
    Arc::new(Mutex::new(RawTranscript::default()))
}

/// Take the recorded transcript out of a log (leaving it empty).
pub fn take_log(log: &TranscriptLog) -> RawTranscript {
    std::mem::take(&mut *log.lock().expect("transcript log poisoned"))
}

/// The logging wrapper. See the module documentation for the depth semantics.
#[derive(Debug)]
pub struct LoggingChallenger<Inner> {
    inner: Inner,
    log: TranscriptLog,
    depth: u8,
}

impl<Inner> LoggingChallenger<Inner> {
    /// Wrap `inner` as a template (depth 0).
    pub fn new(inner: Inner, log: TranscriptLog) -> Self {
        Self {
            inner,
            log,
            depth: 0,
        }
    }

    /// Whether this instance writes to the log.
    pub fn is_recording(&self) -> bool {
        self.depth == 1
    }
}

impl<Inner: Clone> Clone for LoggingChallenger<Inner> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            log: Arc::clone(&self.log),
            depth: self.depth.saturating_add(1),
        }
    }
}

impl<Inner: CanObserve<u8>> CanObserve<u8> for LoggingChallenger<Inner> {
    fn observe(&mut self, value: u8) {
        self.inner.observe(value);
        if self.depth == 1 {
            self.log
                .lock()
                .expect("transcript log poisoned")
                .push_observe(&[value]);
        }
    }

    fn observe_slice(&mut self, values: &[u8]) {
        self.inner.observe_slice(values);
        if self.depth == 1 {
            self.log
                .lock()
                .expect("transcript log poisoned")
                .push_observe(values);
        }
    }
}

impl<Inner: CanSample<u8>> CanSample<u8> for LoggingChallenger<Inner> {
    fn sample(&mut self) -> u8 {
        let value = self.inner.sample();
        if self.depth == 1 {
            self.log
                .lock()
                .expect("transcript log poisoned")
                .push_sample(&[value]);
        }
        value
    }
}

#[cfg(test)]
mod tests {
    use p3_challenger::HashChallenger;
    use p3_keccak::Keccak256Hash;

    use super::*;

    #[test]
    fn only_depth_one_records() {
        let log = new_log();
        let template = LoggingChallenger::new(
            HashChallenger::<u8, Keccak256Hash, 32>::new(Vec::new(), Keccak256Hash {}),
            Arc::clone(&log),
        );
        let mut active = template.clone();
        assert!(active.is_recording());
        active.observe(1u8);
        active.observe_slice(&[2, 3]);
        let mut silent = active.clone();
        silent.observe(9u8);
        let _ = silent.sample();
        let s = active.sample();
        let recorded = take_log(&log);
        assert_eq!(
            recorded.events,
            vec![RawEvent::Observe(vec![1, 2, 3]), RawEvent::Sample(vec![s])]
        );
    }
}
