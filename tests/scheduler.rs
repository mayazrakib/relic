use chrono::{Duration, NaiveDate};
use chrono_tz::Australia::Sydney;
use relic::identity::{JobId, TriggerId};
use relic::scheduler::{
    CalendarProjection, CronSchedule, FoldPolicy, GapPolicy, MissedPolicy, ScheduleError,
    select_catch_up,
};

fn date(year: i32, month: u32, day: u32, hour: u32, minute: u32) -> chrono::NaiveDateTime {
    NaiveDate::from_ymd_opt(year, month, day)
        .unwrap()
        .and_hms_opt(hour, minute, 0)
        .unwrap()
}

fn projector() -> CalendarProjection {
    CalendarProjection {
        job_id: JobId("job_1".into()),
        schedule_revision: "1".into(),
        trigger_id: TriggerId("cron".into()),
        timezone: Sydney,
        timezone_database_version: "test".into(),
        gap_policy: GapPolicy::FIRST_VALID,
        fold_policy: FoldPolicy::FIRST,
    }
}

#[test]
fn sydney_gap_retains_distinct_nominal_identities() {
    let schedule = CronSchedule::parse("0,30 2 * * *").unwrap();
    let start = date(2026, 10, 4, 2, 0);
    let end = date(2026, 10, 4, 3, 0);
    let projection = projector().project(&schedule, start, end, 60, 10).unwrap();
    assert_eq!(projection.len(), 2);
    assert_eq!(
        projection[0].intended_utc_instant,
        projection[1].intended_utc_instant
    );
    assert_ne!(projection[0].occurrence_id, projection[1].occurrence_id);
    assert_eq!(
        projection,
        projector().project(&schedule, start, end, 60, 10).unwrap()
    );
    let mut skipped = projector();
    skipped.gap_policy = GapPolicy::SKIP;
    assert!(
        skipped
            .project(&schedule, start, end, 60, 10)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn sydney_fold_and_catch_up() {
    let schedule = CronSchedule::parse("30 2 * * *").unwrap();
    let mut projector = projector();
    projector.fold_policy = FoldPolicy::BOTH;
    let results = projector
        .project(
            &schedule,
            date(2026, 4, 5, 2, 0),
            date(2026, 4, 5, 3, 0),
            60,
            10,
        )
        .unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].fold_ordinal, 0);
    assert_eq!(results[1].fold_ordinal, 1);
    assert_eq!(
        results[1].intended_utc_instant - results[0].intended_utc_instant,
        Duration::hours(1)
    );
    let selected = select_catch_up(
        results.clone(),
        results[1].intended_utc_instant,
        Duration::hours(24),
        10,
        MissedPolicy::RUN_LATEST,
    )
    .unwrap();
    assert_eq!(selected.selected, vec![results[1].clone()]);
    assert_eq!(selected.dropped.len(), 1);
}

#[test]
fn cron_day_union_leap_day_and_bounds() {
    let cron = CronSchedule::parse("0 0 29 2 1").unwrap();
    assert!(cron.matches(date(2024, 2, 29, 0, 0)));
    assert!(cron.matches(date(2024, 2, 5, 0, 0)));
    assert!(!cron.matches(date(2024, 2, 6, 0, 0)));
    assert!(CronSchedule::parse("0 0 * * 7").is_err());
    assert!(CronSchedule::parse("0 0 * * * *").is_err());
    assert!(matches!(
        projector().project(
            &cron,
            date(2024, 2, 1, 0, 0),
            date(2024, 3, 1, 0, 0),
            10,
            10
        ),
        Err(ScheduleError::HorizonExceeded)
    ));
}

#[test]
fn limits_and_fold_choices_are_explicit() {
    let cron = CronSchedule::parse("* * * * *").unwrap();
    let start = date(2026, 1, 1, 0, 0);
    let end = date(2026, 1, 1, 0, 2);
    assert!(matches!(
        projector().project(&cron, start, end, 2, 1),
        Err(ScheduleError::ResultLimitExceeded)
    ));
    let fold = CronSchedule::parse("30 2 * * *").unwrap();
    let mut second = projector();
    second.fold_policy = FoldPolicy::SECOND;
    let results = second
        .project(&fold, date(2026, 4, 5, 2, 0), date(2026, 4, 5, 3, 0), 60, 1)
        .unwrap();
    assert_eq!(results[0].fold_ordinal, 1);
    let selected = select_catch_up(
        results.clone(),
        results[0].intended_utc_instant + Duration::hours(25),
        Duration::hours(24),
        10,
        MissedPolicy::RUN_ALL_BOUNDED,
    )
    .unwrap();
    assert!(selected.selected.is_empty());
    assert_eq!(selected.dropped.len(), 1);
}
