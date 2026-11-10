use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::identity::{AttemptId, CaptureId, DestinationId, OccurrenceId, PublicationBinding};

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OccurrenceState {
    PENDING,
    READY,
    ACTIVE,
    RETRY_WAIT,
    RECOVERING,
    COMPLETED,
    PARTIALLY_COMPLETED,
    FAILED,
    CANCELED,
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptState {
    PREPARING,
    TRANSFERRING,
    VERIFYING,
    COMMITTING,
    WAITING,
    PAUSED,
    RECOVERING,
    COMPLETED,
    PARTIALLY_COMPLETED,
    FAILED,
    CANCELED,
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DestinationState {
    PENDING,
    PREPARING,
    TRANSFERRING,
    VERIFYING,
    COMMITTING,
    POST_VERIFYING,
    WAITING,
    PAUSED,
    RECOVERING,
    COMPLETED,
    FAILED,
    CANCELED,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DomainError {
    InvalidTransition,
    UnknownDestination,
    CaptureMismatch,
    IdempotencyConflict,
    UncertainOutcome,
    MissingReceipt,
    DuplicateAttempt,
    InvalidScope,
}

impl fmt::Display for DomainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for DomainError {}

#[derive(Clone, Debug)]
pub struct DestinationRun {
    pub destination_id: DestinationId,
    state: DestinationState,
    prior_phase: Option<DestinationState>,
    reason: Option<String>,
    is_uncertain: bool,
}

impl DestinationRun {
    pub fn new(destination_id: DestinationId) -> Self {
        Self {
            destination_id,
            state: DestinationState::PENDING,
            prior_phase: None,
            reason: None,
            is_uncertain: false,
        }
    }

    pub fn get_state(&self) -> DestinationState {
        self.state
    }

    pub fn transition(&mut self, target: DestinationState) -> Result<(), DomainError> {
        use DestinationState::*;
        let allowed = matches!(
            (self.state, target),
            (PENDING, PREPARING)
                | (PREPARING, TRANSFERRING)
                | (TRANSFERRING, VERIFYING)
                | (VERIFYING, COMMITTING)
                | (COMMITTING, POST_VERIFYING)
                | (COMMITTING, COMPLETED)
                | (POST_VERIFYING, COMPLETED)
                | (POST_VERIFYING, FAILED)
        );

        if !allowed || self.is_uncertain {
            return Err(DomainError::InvalidTransition);
        }

        self.state = target;

        Ok(())
    }

    pub fn suspend(&mut self, target: DestinationState, reason: String) -> Result<(), DomainError> {
        use DestinationState::*;
        if !matches!(target, WAITING | PAUSED | RECOVERING)
            || !matches!(
                self.state,
                PENDING | PREPARING | TRANSFERRING | VERIFYING | COMMITTING | POST_VERIFYING
            )
            || reason.is_empty()
        {
            return Err(DomainError::InvalidTransition);
        }

        self.prior_phase = Some(self.state);
        self.is_uncertain = target == RECOVERING;
        self.reason = Some(reason);
        self.state = target;

        Ok(())
    }

    pub fn resume(&mut self, is_reconciled: bool) -> Result<(), DomainError> {
        if self.is_uncertain && !is_reconciled {
            return Err(DomainError::UncertainOutcome);
        }

        self.state = self
            .prior_phase
            .take()
            .ok_or(DomainError::InvalidTransition)?;
        self.reason = None;
        self.is_uncertain = false;

        Ok(())
    }

    pub fn terminate(&mut self, target: DestinationState) -> Result<(), DomainError> {
        if self.is_uncertain {
            return Err(DomainError::UncertainOutcome);
        }

        if !matches!(
            target,
            DestinationState::FAILED | DestinationState::CANCELED
        ) || matches!(
            self.state,
            DestinationState::COMPLETED | DestinationState::FAILED | DestinationState::CANCELED
        ) {
            return Err(DomainError::InvalidTransition);
        }

        self.state = target;

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct Attempt {
    pub attempt_id: AttemptId,
    pub selected: BTreeSet<DestinationId>,
    state: AttemptState,
}

impl Attempt {
    pub fn new(
        attempt_id: AttemptId,
        selected: BTreeSet<DestinationId>,
    ) -> Result<Self, DomainError> {
        if selected.is_empty() {
            return Err(DomainError::InvalidScope);
        }

        Ok(Self {
            attempt_id,
            selected,
            state: AttemptState::PREPARING,
        })
    }

    pub fn get_state(&self) -> AttemptState {
        self.state
    }

    pub fn advance(&mut self, target: AttemptState) -> Result<(), DomainError> {
        use AttemptState::*;
        if !matches!(
            (self.state, target),
            (PREPARING, TRANSFERRING) | (TRANSFERRING, VERIFYING) | (VERIFYING, COMMITTING)
        ) {
            return Err(DomainError::InvalidTransition);
        }

        self.state = target;

        Ok(())
    }

    pub fn finish(
        &mut self,
        succeeded: usize,
        has_uncertain: bool,
        is_canceled: bool,
    ) -> Result<(), DomainError> {
        if has_uncertain {
            return Err(DomainError::UncertainOutcome);
        }

        if matches!(
            self.state,
            AttemptState::COMPLETED
                | AttemptState::PARTIALLY_COMPLETED
                | AttemptState::FAILED
                | AttemptState::CANCELED
        ) || succeeded > self.selected.len()
        {
            return Err(DomainError::InvalidTransition);
        }

        self.state = if is_canceled {
            AttemptState::CANCELED
        } else if succeeded == self.selected.len() {
            AttemptState::COMPLETED
        } else if succeeded > 0 {
            AttemptState::PARTIALLY_COMPLETED
        } else {
            AttemptState::FAILED
        };

        Ok(())
    }
}

/// In-memory transition model. Persistence and publication authority belong to the caller.
#[derive(Clone, Debug)]
pub struct Occurrence {
    pub occurrence_id: OccurrenceId,
    pub capture_id: CaptureId,
    pub predecessor: Option<OccurrenceId>,
    scope: BTreeSet<DestinationId>,
    state: OccurrenceState,
    bindings: BTreeMap<DestinationId, PublicationBinding>,
    receipts: BTreeSet<DestinationId>,
    uncertain: BTreeSet<DestinationId>,
    attempts: BTreeSet<AttemptId>,
}

impl Occurrence {
    pub fn new(
        occurrence_id: OccurrenceId,
        capture_id: CaptureId,
        scope: BTreeSet<DestinationId>,
        predecessor: Option<OccurrenceId>,
    ) -> Result<Self, DomainError> {
        if scope.is_empty() || predecessor.as_ref() == Some(&occurrence_id) {
            return Err(DomainError::InvalidScope);
        }

        Ok(Self {
            occurrence_id,
            capture_id,
            predecessor,
            scope,
            state: OccurrenceState::PENDING,
            bindings: BTreeMap::new(),
            receipts: BTreeSet::new(),
            uncertain: BTreeSet::new(),
            attempts: BTreeSet::new(),
        })
    }

    pub fn get_state(&self) -> OccurrenceState {
        self.state
    }

    pub fn get_receipts(&self) -> &BTreeSet<DestinationId> {
        &self.receipts
    }

    pub fn set_ready(&mut self) -> Result<(), DomainError> {
        if self.state != OccurrenceState::PENDING {
            return Err(DomainError::InvalidTransition);
        }

        self.state = OccurrenceState::READY;
        Ok(())
    }

    pub fn admit_attempt(&mut self, attempt: &Attempt) -> Result<(), DomainError> {
        if !matches!(
            self.state,
            OccurrenceState::READY | OccurrenceState::RETRY_WAIT
        ) || !attempt.selected.is_subset(&self.scope)
            || !attempt.selected.is_disjoint(&self.receipts)
            || !attempt.selected.is_disjoint(&self.uncertain)
        {
            return Err(DomainError::InvalidTransition);
        }

        if !self.attempts.insert(attempt.attempt_id.clone()) {
            return Err(DomainError::DuplicateAttempt);
        }

        self.state = OccurrenceState::ACTIVE;
        Ok(())
    }

    pub fn bind_publication(&mut self, binding: PublicationBinding) -> Result<(), DomainError> {
        let destination = &binding.commit_key.destination_id;
        if self.state != OccurrenceState::ACTIVE {
            return Err(DomainError::InvalidTransition);
        }

        if self.bindings.values().any(|existing| {
            existing.manifest_digest != binding.manifest_digest
                || existing.commit_key.authority_id != binding.commit_key.authority_id
                || existing.commit_key.job_id != binding.commit_key.job_id
        }) {
            return Err(DomainError::IdempotencyConflict);
        }

        if !self.scope.contains(destination)
            || binding.commit_key.occurrence_id != self.occurrence_id
        {
            return Err(DomainError::UnknownDestination);
        }

        if binding.capture_id != self.capture_id {
            return Err(DomainError::CaptureMismatch);
        }

        if let Some(existing) = self.bindings.get(destination) {
            if existing != &binding {
                return Err(DomainError::IdempotencyConflict);
            }
        } else {
            self.bindings.insert(destination.clone(), binding);
        }

        Ok(())
    }

    pub fn mark_uncertain(&mut self, destination: &DestinationId) -> Result<(), DomainError> {
        if self.state != OccurrenceState::ACTIVE
            || !self.bindings.contains_key(destination)
            || self.receipts.contains(destination)
        {
            return Err(DomainError::InvalidTransition);
        }

        self.uncertain.insert(destination.clone());
        self.state = OccurrenceState::RECOVERING;
        Ok(())
    }

    pub fn reconcile(&mut self, destination: &DestinationId) -> Result<(), DomainError> {
        if !self.uncertain.remove(destination) {
            return Err(DomainError::InvalidTransition);
        }

        if self.uncertain.is_empty() {
            self.state = OccurrenceState::ACTIVE;
        }

        Ok(())
    }

    pub fn record_receipt(&mut self, binding: &PublicationBinding) -> Result<(), DomainError> {
        if !matches!(
            self.state,
            OccurrenceState::ACTIVE | OccurrenceState::RECOVERING
        ) {
            return Err(DomainError::InvalidTransition);
        }

        if self.uncertain.contains(&binding.commit_key.destination_id) {
            return Err(DomainError::UncertainOutcome);
        }

        if self.bindings.get(&binding.commit_key.destination_id) != Some(binding) {
            return Err(DomainError::IdempotencyConflict);
        }

        self.receipts
            .insert(binding.commit_key.destination_id.clone());
        Ok(())
    }

    pub fn retry_wait(&mut self) -> Result<(), DomainError> {
        if self.state != OccurrenceState::ACTIVE || !self.uncertain.is_empty() {
            return Err(DomainError::InvalidTransition);
        }

        self.state = OccurrenceState::RETRY_WAIT;
        Ok(())
    }

    pub fn finalize(&mut self, is_canceled: bool) -> Result<(), DomainError> {
        if !self.uncertain.is_empty() || self.state == OccurrenceState::RECOVERING {
            return Err(DomainError::UncertainOutcome);
        }

        if !matches!(
            self.state,
            OccurrenceState::PENDING
                | OccurrenceState::READY
                | OccurrenceState::ACTIVE
                | OccurrenceState::RETRY_WAIT
        ) || (!is_canceled
            && !matches!(
                self.state,
                OccurrenceState::ACTIVE | OccurrenceState::RETRY_WAIT
            ))
        {
            return Err(DomainError::InvalidTransition);
        }

        self.state = if is_canceled {
            OccurrenceState::CANCELED
        } else if self.receipts.len() == self.scope.len() {
            OccurrenceState::COMPLETED
        } else if self.receipts.is_empty() {
            OccurrenceState::FAILED
        } else {
            OccurrenceState::PARTIALLY_COMPLETED
        };
        Ok(())
    }
}
