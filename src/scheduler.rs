use std::fmt;

use chrono::{DateTime, Datelike, Duration, LocalResult, NaiveDateTime, TimeZone, Timelike, Utc};
use chrono_tz::Tz;

use crate::identity::{CalendarOccurrence, IdentityError, JobId, OccurrenceId, TriggerId};

const MAX_GAP_SECONDS: i64 = 172_800;

#[derive(Debug)]
pub enum ScheduleError {
    InvalidCron,
    InvalidBounds,
    HorizonExceeded,
    ResultLimitExceeded,
    UnresolvedGap,
    Identity(IdentityError),
}

impl fmt::Display for ScheduleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ScheduleError {}

#[derive(Clone, Debug)]
struct Field {
    values: Vec<bool>,
    is_restricted: bool,
}

impl Field {
    fn parse(text: &str, minimum: u32, maximum: u32) -> Result<Self, ScheduleError> {
        let mut values = vec![false; maximum as usize + 1];
        let is_restricted = text != "*";

        for item in text.split(',') {
            let mut step_parts = item.split('/');
            let range = step_parts.next().ok_or(ScheduleError::InvalidCron)?;
            let step = match step_parts.next() {
                Some(value) => value
                    .parse::<u32>()
                    .map_err(|_| ScheduleError::InvalidCron)?,
                None => 1,
            };

            if step == 0 || step_parts.next().is_some() {
                return Err(ScheduleError::InvalidCron);
            }

            let (start, end) = if range == "*" {
                (minimum, maximum)
            } else if let Some((first, last)) = range.split_once('-') {
                (
                    first
                        .parse::<u32>()
                        .map_err(|_| ScheduleError::InvalidCron)?,
                    last.parse::<u32>()
                        .map_err(|_| ScheduleError::InvalidCron)?,
                )
            } else {
                let number = range
                    .parse::<u32>()
                    .map_err(|_| ScheduleError::InvalidCron)?;
                (number, if item.contains('/') { maximum } else { number })
            };

            if start < minimum || end > maximum || start > end {
                return Err(ScheduleError::InvalidCron);
            }

            for value in start..=end {
                if (value - start) % step == 0 {
                    values[value as usize] = true;
                }
            }
        }

        Ok(Self {
            values,
            is_restricted,
        })
    }

    fn matches(&self, value: u32) -> bool {
        self.values.get(value as usize).copied().unwrap_or(false)
    }
}

#[derive(Clone, Debug)]
pub struct CronSchedule {
    minute: Field,
    hour: Field,
    day: Field,
    month: Field,
    weekday: Field,
}

impl CronSchedule {
    pub fn parse(expression: &str) -> Result<Self, ScheduleError> {
        let fields: Vec<_> = expression.split_whitespace().collect();

        if fields.len() != 5 {
            return Err(ScheduleError::InvalidCron);
        }

        Ok(Self {
            minute: Field::parse(fields[0], 0, 59)?,
            hour: Field::parse(fields[1], 0, 23)?,
            day: Field::parse(fields[2], 1, 31)?,
            month: Field::parse(fields[3], 1, 12)?,
            weekday: Field::parse(fields[4], 0, 6)?,
        })
    }

    pub fn matches(&self, local: NaiveDateTime) -> bool {
        let day = self.day.matches(local.day());
        let weekday = self.weekday.matches(local.weekday().num_days_from_sunday());
        let is_day_match = if self.day.is_restricted && self.weekday.is_restricted {
            day || weekday
        } else {
            day && weekday
        };

        self.minute.matches(local.minute())
            && self.hour.matches(local.hour())
            && self.month.matches(local.month())
            && is_day_match
    }
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub enum GapPolicy {
    #[default]
    FIRST_VALID,
    SKIP,
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub enum FoldPolicy {
    #[default]
    FIRST,
    SECOND,
    BOTH,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Projection {
    pub occurrence_id: OccurrenceId,
    pub intended_local_time: NaiveDateTime,
    pub intended_utc_instant: DateTime<Utc>,
    pub fold_ordinal: u8,
}

#[derive(Clone, Debug)]
pub struct CalendarProjection {
    pub job_id: JobId,
    pub schedule_revision: String,
    pub trigger_id: TriggerId,
    pub timezone: Tz,
    pub timezone_database_version: String,
    pub gap_policy: GapPolicy,
    pub fold_policy: FoldPolicy,
}

impl CalendarProjection {
    pub fn project(
        &self,
        schedule: &CronSchedule,
        start: NaiveDateTime,
        end: NaiveDateTime,
        max_minutes: u64,
        max_results: usize,
    ) -> Result<Vec<Projection>, ScheduleError> {
        if end <= start
            || start.second() != 0
            || start.nanosecond() != 0
            || end.second() != 0
            || end.nanosecond() != 0
            || max_results == 0
            || self.timezone_database_version.is_empty()
        {
            return Err(ScheduleError::InvalidBounds);
        }

        let minutes = end.signed_duration_since(start).num_minutes();

        if minutes < 0 || minutes as u64 > max_minutes {
            return Err(ScheduleError::HorizonExceeded);
        }

        let mut results = Vec::new();
        let mut local = start;

        while local < end {
            if schedule.matches(local) {
                for (instant, ordinal) in self.resolve(local)? {
                    if results.len() == max_results {
                        return Err(ScheduleError::ResultLimitExceeded);
                    }

                    let calendar = CalendarOccurrence {
                        job_id: self.job_id.clone(),
                        schedule_revision: self.schedule_revision.clone(),
                        trigger_id: self.trigger_id.clone(),
                        intended_local_time: local.format("%Y-%m-%dT%H:%M:%S%.9f").to_string(),
                        intended_utc_instant: instant.format("%Y-%m-%dT%H:%M:%S%.9fZ").to_string(),
                        fold_ordinal: ordinal,
                    };
                    results.push(Projection {
                        occurrence_id: calendar.digest().map_err(ScheduleError::Identity)?,
                        intended_local_time: local,
                        intended_utc_instant: instant,
                        fold_ordinal: ordinal,
                    });
                }
            }

            local = local
                .checked_add_signed(Duration::minutes(1))
                .ok_or(ScheduleError::InvalidBounds)?;
        }

        results.sort_by_key(|projection| {
            (
                projection.intended_utc_instant,
                projection.intended_local_time,
                projection.fold_ordinal,
            )
        });

        Ok(results)
    }

    fn resolve(&self, local: NaiveDateTime) -> Result<Vec<(DateTime<Utc>, u8)>, ScheduleError> {
        match self.timezone.from_local_datetime(&local) {
            LocalResult::Single(value) => Ok(vec![(value.with_timezone(&Utc), 0)]),
            LocalResult::Ambiguous(first, second) => {
                let first = first.with_timezone(&Utc);
                let second = second.with_timezone(&Utc);
                let (first, second) = if first <= second {
                    (first, second)
                } else {
                    (second, first)
                };

                Ok(match self.fold_policy {
                    FoldPolicy::FIRST => vec![(first, 0)],
                    FoldPolicy::SECOND => vec![(second, 1)],
                    FoldPolicy::BOTH => vec![(first, 0), (second, 1)],
                })
            }
            LocalResult::None if self.gap_policy == GapPolicy::SKIP => Ok(Vec::new()),
            LocalResult::None => {
                for seconds in 1..=MAX_GAP_SECONDS {
                    let candidate = local
                        .checked_add_signed(Duration::seconds(seconds))
                        .ok_or(ScheduleError::InvalidBounds)?;

                    match self.timezone.from_local_datetime(&candidate) {
                        LocalResult::Single(value) => {
                            return Ok(vec![(value.with_timezone(&Utc), 0)]);
                        }
                        LocalResult::Ambiguous(first, second) => {
                            return Ok(vec![(first.min(second).with_timezone(&Utc), 0)]);
                        }
                        LocalResult::None => {}
                    }
                }

                Err(ScheduleError::UnresolvedGap)
            }
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissedPolicy {
    SKIP,
    RUN_LATEST,
    RUN_ALL_BOUNDED,
    NEXT_REGULAR,
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DropReason {
    EXPIRED,
    POLICY,
    CAPACITY,
}

#[derive(Clone, Debug)]
pub struct CatchUpResult {
    pub selected: Vec<Projection>,
    pub dropped: Vec<(Projection, DropReason)>,
}

pub fn select_catch_up(
    mut projections: Vec<Projection>,
    now: DateTime<Utc>,
    horizon: Duration,
    limit: usize,
    policy: MissedPolicy,
) -> Result<CatchUpResult, ScheduleError> {
    if horizon < Duration::zero()
        || limit == 0
        || projections
            .iter()
            .any(|projection| projection.intended_utc_instant > now)
    {
        return Err(ScheduleError::InvalidBounds);
    }

    let earliest = now
        .checked_sub_signed(horizon)
        .ok_or(ScheduleError::InvalidBounds)?;
    projections.sort_by_key(|projection| {
        (
            projection.intended_utc_instant,
            projection.intended_local_time,
            projection.fold_ordinal,
        )
    });
    let mut selected = Vec::new();
    let mut dropped = Vec::new();
    let eligible = projections
        .into_iter()
        .filter(|projection| {
            if projection.intended_utc_instant < earliest {
                dropped.push((projection.clone(), DropReason::EXPIRED));
                false
            } else {
                true
            }
        })
        .collect::<Vec<_>>();
    let count = eligible.len();

    for (index, projection) in eligible.into_iter().enumerate() {
        let reason = match policy {
            MissedPolicy::SKIP | MissedPolicy::NEXT_REGULAR => Some(DropReason::POLICY),
            MissedPolicy::RUN_LATEST if index + 1 != count => Some(DropReason::POLICY),
            MissedPolicy::RUN_ALL_BOUNDED if index >= limit => Some(DropReason::CAPACITY),
            _ => None,
        };

        if let Some(reason) = reason {
            dropped.push((projection, reason));
        } else {
            selected.push(projection);
        }
    }

    Ok(CatchUpResult { selected, dropped })
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum OverlapPolicy {
    #[default]
    FORBID,
    QUEUE {
        capacity: usize,
    },
    PARALLEL {
        capacity: usize,
    },
}
