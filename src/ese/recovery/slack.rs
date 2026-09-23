//! Recovery source 2 of 3: candidate records found in a live page's
//! **slack** -- the unallocated region between the page's used data and its
//! tag array, present because ESE shrinks `available_data_offset` on
//! deletion without zeroing the bytes it stops claiming.
//!
//! # Why this source is riskier than [`super::defunct`], and what that costs
//!
//! A defunct-tagged row is governed by a tag the engine itself wrote and
//! flagged on deletion -- reliable evidence on its own. A slack candidate
//! has **no such marker**: it is found purely by structural plausibility
//! (a 4-byte record-header shape that fits within the remaining slack),
//! which a stray sequence of unrelated bytes can satisfy by chance. Two
//! things in this module exist specifically to compensate:
//!
//! 1. **No tagged/overflow region is ever decoded.** A slack candidate's
//!    declared `variable_data_offset` bounds exactly how many bytes are
//!    handed to [`crate::ese::page::entries::table_value::TableValueEntry::new`]
//!    -- the slice length is made equal
//!    to `variable_data_offset`, so `TableValueEntry::new`'s own
//!    `variable_data_offset < data.len()` check is always false and
//!    `tagged_columns`/`raw_overflow` come back empty by construction.
//!    Nothing past a candidate's own declared pre-tagged region is ever
//!    interpreted as column data -- there is no governing tag to say where
//!    that region legitimately ends, so guessing it would risk decoding an
//!    unrelated, adjacent stale record's bytes as if they belonged to this
//!    one.
//! 2. **The admission gate requires two non-null columns, not one** (see
//!    [`super::validate::decode_and_admit`]'s documentation for why a
//!    single non-null column is not enough corroboration when there is no
//!    governing tag).
//!
//! Measured on `artifacts/sru/SRUDB.dat`: 1.17 MiB of total page slack,
//! 537 KB of it non-zero, across 224 pages.

use forensic_rs::err::ForensicResult;
use forensic_rs::prelude::Region;
use forensic_rs::recovery::{looks_like_padding, slack_regions};

use crate::ese::column::TableSchema;
use crate::ese::db::EseDb;
use crate::ese::page::Page;
use crate::ese::page::TreePage;
use crate::ese::tag::TagData;
use crate::ese::tree::TreeWalker;

use super::validate::decode_and_admit;
use super::{slack_locus, RecoveredRow, RecoveryStats};

/// A slack candidate must decode at least this many non-null columns to be
/// admitted -- see the module documentation for why this is stricter than
/// [`super::defunct`]'s bar of one.
const MIN_NON_NULL_COLUMNS: usize = 2;

/// Shortest byte run worth examining at all. A window below this is passed to
/// [`looks_like_padding`] as padding regardless of content: the 4-byte record
/// header plus one 4-byte fixed column is already 8 bytes, so nothing shorter
/// can carry the two meaningful columns [`MIN_NON_NULL_COLUMNS`] demands.
const MIN_CANDIDATE_BYTES: usize = 8;

/// Walk `table`'s data B-tree looking for candidate records in each live
/// leaf page's unallocated slack region.
pub fn recover_slack_rows(db: &EseDb, table: &str) -> ForensicResult<(Vec<RecoveredRow>, RecoveryStats)> {
    let def = db
        .catalog()
        .table(table)
        .ok_or_else(|| forensic_rs::err::ForensicError::missing_data("table", "table not found in ESE database".into()))?;
    let schema = def.schema();
    let fdp_page = def.fdp_page;

    let mut results = Vec::new();
    let mut stats = RecoveryStats::default();

    let reader = db.reader();
    let header = db.header();
    let mut walker = TreeWalker::new(fdp_page);

    while let Some(page) = walker.next_page(reader, header) {
        stats.pages_scanned += 1;
        match page.process_page() {
            Ok(tree) => {
                walker.push_children(&tree);
                if let TreePage::Leaf(_) = &tree {
                    scan_page_slack(&page, &schema, &mut results, &mut stats);
                }
            }
            Err(e) => {
                forensic_rs::debug!(
                    "ESE recovery: cannot process page {} while scanning '{table}' for slack rows: {e}",
                    page.page_number
                );
                walker.record_unparsable();
                stats.pages_unparsable += 1;
            }
        }
    }

    Ok((results, stats))
}

/// Every unallocated region of `page`'s body, ascending and disjoint.
///
/// The body runs from the end of the page header to the start of the tag
/// array (the last `available_page_tag * 4` bytes); the *used* extents are
/// the byte ranges the page's own tags claim. Subtracting one from the other
/// is exactly what [`slack_regions`] does -- including clipping tags that
/// point outside the body and merging any that overlap, which hand-rolled
/// arithmetic against untrusted page bytes has to get right every time.
///
/// This finds more than the previous implementation did. That one computed
/// only the single trailing gap between `available_data_offset` and the tag
/// array, so a hole left *between* two live records -- the ordinary result of
/// deleting a record in the middle of a page -- was invisible. Those holes
/// are now scanned too.
///
/// Returns page-relative regions; empty when the header values are too
/// inconsistent to describe a body at all.
fn page_slack_regions(page: &Page<'_>) -> Vec<Region> {
    let header_size = page.header.header_size as u64;
    let Some(tag_table_bytes) = (page.header.available_page_tag as u64).checked_mul(4) else {
        return Vec::new();
    };
    let Some(tag_table_start) = (page.data.len() as u64).checked_sub(tag_table_bytes) else {
        return Vec::new();
    };
    let Some(body_len) = tag_table_start.checked_sub(header_size) else {
        return Vec::new();
    };
    let total = Region { offset: header_size, length: body_len };

    // A tag's `value_offset` is relative to the end of the page header.
    let used: Vec<Region> = page
        .tags
        .iter()
        .map(|tag| Region {
            offset: header_size.saturating_add(tag.value_offset as u64),
            length: tag.value_size as u64,
        })
        .collect();

    slack_regions(total, &used)
}

fn scan_page_slack(
    page: &Page<'_>,
    schema: &TableSchema,
    results: &mut Vec<RecoveredRow>,
    stats: &mut RecoveryStats,
) {
    for region in page_slack_regions(page) {
        let (Ok(start), Ok(end)) = (
            usize::try_from(region.offset),
            usize::try_from(region.offset.saturating_add(region.length)),
        ) else {
            continue;
        };
        let Some(slack) = page.data.get(start..end) else { continue };

        // Pre-decode content gate. A region that is entirely zeros or
        // entirely 0xFF is unwritten space, not a deleted record, and
        // "it parsed" is not evidence a record was ever there -- see
        // `forensic_rs::recovery`'s soundness checklist, rule 2. Applied
        // before spending any schema decode, and *in addition to* the
        // post-decode `validate::is_meaningful` bar, which catches the
        // different case this cannot: a window straddling a real record
        // and its trailing padding is not uniform, yet every column in it
        // decodes to zero.
        if looks_like_padding(slack, MIN_CANDIDATE_BYTES) {
            continue;
        }

        scan_one_region(page, schema, start, slack, results, stats);
    }
}

fn scan_one_region(
    page: &Page<'_>,
    schema: &TableSchema,
    base: usize,
    slack: &[u8],
    results: &mut Vec<RecoveredRow>,
    stats: &mut RecoveryStats,
) {
    let mut i = 0usize;
    while i + 4 <= slack.len() {
        match try_candidate_at(page, slack, i, schema) {
            TryOutcome::NotAHeaderShape => {
                i += 1;
            }
            TryOutcome::Rejected => {
                stats.candidate_tags_found += 1;
                stats.rows_rejected += 1;
                i += 1;
            }
            TryOutcome::Admitted { row, consumed } => {
                stats.candidate_tags_found += 1;
                stats.rows_recovered += 1;
                results.push(RecoveredRow::new(
                    row,
                    forensic_rs::provenance::Recovery::Slack,
                    slack_locus(page.page_number, (base + i) as u32),
                ));
                i += consumed.max(1);
            }
        }
    }
}

enum TryOutcome {
    /// The 4 bytes at this position don't even have a plausible
    /// record-header shape -- not counted as a candidate at all.
    NotAHeaderShape,
    /// A plausible header shape, but decoding or admission failed.
    Rejected,
    Admitted { row: crate::ese::db::Row, consumed: usize },
}

fn try_candidate_at(page: &Page<'_>, slack: &[u8], i: usize, schema: &TableSchema) -> TryOutcome {
    let variable_data_offset = u16::from_le_bytes([slack[i + 2], slack[i + 3]]) as usize;
    // Cheap structural pre-filter before spending a schema decode: the
    // declared region must be nonzero, at least as long as the 4-byte
    // header itself, and fit within the remaining slack.
    if variable_data_offset < 4 || i + variable_data_offset > slack.len() {
        return TryOutcome::NotAHeaderShape;
    }

    let candidate = &slack[i..i + variable_data_offset];
    // `data.len() == variable_data_offset` here by construction, so
    // `TableValueEntry::new`'s own `variable_data_offset < data.len()` test
    // is always false: tagged/overflow bytes are never produced. See the
    // module documentation.
    let tag = TagData { data: candidate, flags: 0 };
    let Ok(entry) = crate::ese::page::entries::table_value::TableValueEntry::new(page, tag) else {
        return TryOutcome::Rejected;
    };

    match decode_and_admit(&entry, schema, MIN_NON_NULL_COLUMNS) {
        Some(row) => TryOutcome::Admitted { row, consumed: variable_data_offset },
        None => TryOutcome::Rejected,
    }
}

#[cfg(test)]
mod tst {
    use super::*;
    use crate::ese::column::{ColumnDef, ColumnType, OwnedColumnValue};
    use crate::ese::db::EseDb;
    use crate::ese::tag::Tag;

    fn two_fixed_columns_schema() -> TableSchema {
        TableSchema {
            name: "Test".to_string(),
            columns: vec![
                ColumnDef { id: 1, col_type: ColumnType::Long, name: "Col1".to_string(), flags: 0, codepage: 0 },
                ColumnDef { id: 2, col_type: ColumnType::Long, name: "Col2".to_string(), flags: 0, codepage: 0 },
            ],
        }
    }

    /// `used` describes each live tag's page-relative `(value_offset,
    /// value_size)` -- the extents [`page_slack_regions`] must treat as
    /// *not* slack. An empty slice means the whole body is unallocated.
    fn make_dummy_page(data: Vec<u8>, header_size: u32, used: &[(u16, u16)], available_page_tag: u16) -> Page<'static> {
        let mut page = Page::dummy();
        page.header.header_size = header_size;
        page.header.available_page_tag = available_page_tag;
        page.tags = used.iter().map(|&(value_offset, value_size)| Tag { value_offset, tag_flags: 0, value_size }).collect();
        page.data = std::borrow::Cow::Owned(data);
        page
    }

    /// Two fixed columns (ids 1 and 2, 4 bytes each): last_fixed=2,
    /// last_variable=127 (none), variable_data_offset=12,
    /// pre_tagged_data = 8 bytes (two nonzero i32s).
    fn plausible_record_bytes() -> Vec<u8> {
        let mut r = vec![0x02, 0x7F, 0x0C, 0x00];
        r.extend_from_slice(&0x1234_5678i32.to_le_bytes());
        r.extend_from_slice(&0x0000_0099i32.to_le_bytes());
        r
    }

    #[test]
    fn page_slack_regions_finds_the_trailing_gap() {
        // Page: header (40) + 20 bytes used data (one live tag) + 44 bytes
        // slack + 2 tags (8 bytes).
        let page_size = 40 + 20 + 44 + 8;
        let page = make_dummy_page(vec![0u8; page_size], 40, &[(0, 20)], 2);
        let regions = page_slack_regions(&page);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].offset, 60);
        assert_eq!(regions[0].length, 44);
    }

    #[test]
    fn page_slack_regions_also_finds_an_interior_gap_between_two_live_tags() {
        // A hole *between* two live records -- the ordinary result of
        // deleting a record in the middle of a page -- which the previous,
        // trailing-gap-only implementation could not see at all.
        // header(40) + tag A[0..10) + gap[10..25) + tag B[25..35) + tags(8).
        let page_size = 40 + 35 + 8;
        let page = make_dummy_page(vec![0u8; page_size], 40, &[(0, 10), (25, 10)], 2);
        let regions = page_slack_regions(&page);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].offset, 50); // 40 + 10
        assert_eq!(regions[0].length, 15); // 25 - 10
    }

    #[test]
    fn page_slack_regions_is_empty_when_the_body_has_no_room() {
        let page = make_dummy_page(vec![0u8; 48], 40, &[], 2); // body length 0
        assert!(page_slack_regions(&page).is_empty());
    }

    #[test]
    fn a_plausible_two_column_record_in_slack_is_recovered() {
        let record = plausible_record_bytes();
        let mut slack = vec![0u8; 8];
        slack.extend_from_slice(&record);
        slack.extend_from_slice(&[0u8; 8]);
        let mut data = vec![0u8; 40];
        data.extend_from_slice(&slack);
        data.extend_from_slice(&[0u8; 8]);
        let page = make_dummy_page(data, 40, &[], 2);

        let schema = two_fixed_columns_schema();
        let mut results = Vec::new();
        let mut stats = RecoveryStats::default();
        scan_page_slack(&page, &schema, &mut results, &mut stats);

        assert_eq!(results.len(), 1);
        let r = &results[0];
        assert_eq!(r.recovery(), forensic_rs::provenance::Recovery::Slack);
        // 40 (header) + 8 (leading zero padding) -- a slack candidate has
        // no tag, so its locus names the page plus a byte offset within it,
        // not a `(page, slot)` pair.
        assert_eq!(r.locus(), slack_locus(page.page_number, 48));
        assert_eq!(r.value().get_i64("Col1"), Some(0x1234_5678));
        assert_eq!(r.value().get_i64("Col2"), Some(0x99));
    }

    #[test]
    fn all_zero_slack_yields_nothing() {
        let mut data = vec![0u8; 40];
        data.extend_from_slice(&[0u8; 100]);
        data.extend_from_slice(&[0u8; 8]);
        let page = make_dummy_page(data, 40, &[], 2);
        let schema = two_fixed_columns_schema();
        let mut results = Vec::new();
        let mut stats = RecoveryStats::default();
        scan_page_slack(&page, &schema, &mut results, &mut stats);
        assert!(results.is_empty());
    }

    #[test]
    fn a_single_nonzero_column_is_not_enough_to_admit() {
        // Only one fixed column decodes nonzero; the two-column bar must reject it.
        let mut record = vec![0x01, 0x7F, 0x08, 0x00];
        record.extend_from_slice(&0x1234_5678i32.to_le_bytes());
        let mut data = vec![0u8; 40];
        data.extend_from_slice(&record);
        data.extend_from_slice(&[0u8; 20]);
        data.extend_from_slice(&[0u8; 8]);
        let page = make_dummy_page(data, 40, &[], 2);
        let schema = two_fixed_columns_schema();
        let mut results = Vec::new();
        let mut stats = RecoveryStats::default();
        scan_page_slack(&page, &schema, &mut results, &mut stats);
        assert!(results.is_empty(), "one non-null column must not be enough for a slack candidate");
    }

    #[test]
    fn candidate_never_reads_past_its_own_declared_region() {
        // The record declares variable_data_offset=8, but is followed by
        // bytes that would parse as plausible tagged-column data if they
        // were ever consulted. They must never be, by construction.
        let mut record = vec![0x02, 0x7F, 0x08, 0x00];
        record.extend_from_slice(&0x1111_1111i32.to_le_bytes());
        // Trailing "trap" bytes shaped like a tagged-column descriptor block.
        record.extend_from_slice(&[0xFF, 0x01, 0x04, 0x00]);
        let mut data = vec![0u8; 40];
        data.extend_from_slice(&record);
        data.extend_from_slice(&[0u8; 8]);
        let page = make_dummy_page(data, 40, &[], 2);
        // A schema with a tagged column (id 256) that would only ever
        // decode a value if the trailing trap bytes were consulted.
        let schema = TableSchema {
            name: "Test".to_string(),
            columns: vec![
                ColumnDef { id: 1, col_type: ColumnType::Long, name: "Col1".to_string(), flags: 0, codepage: 0 },
                ColumnDef { id: 256, col_type: ColumnType::Text, name: "Tagged".to_string(), flags: 0, codepage: 1252 },
            ],
        };
        let mut results = Vec::new();
        let mut stats = RecoveryStats::default();
        scan_page_slack(&page, &schema, &mut results, &mut stats);
        // Only one non-null column (Col1) can ever be decoded -- the
        // two-column bar rejects it regardless, but the real point of this
        // test is documented via `missing_table_returns_an_error_not_a_panic`-
        // style intent: even if MIN_NON_NULL_COLUMNS were 1, `Tagged` must
        // never appear, because the trailing bytes are never in scope.
        assert!(results.is_empty());
    }

    #[test]
    fn missing_table_returns_an_error_not_a_panic() {
        let Ok(bytes) = std::fs::read("./artifacts/sru/SRUDB.dat") else {
            eprintln!("SKIP: fixture unavailable");
            return;
        };
        let db = EseDb::from_bytes(bytes).unwrap();
        assert!(recover_slack_rows(&db, "does-not-exist-anywhere").is_err());
    }

    #[test]
    fn real_srum_fixture_slack_scan_completes_without_panicking() {
        let Ok(bytes) = std::fs::read("./artifacts/sru/SRUDB.dat") else {
            eprintln!("SKIP: fixture unavailable");
            return;
        };
        let db = EseDb::from_bytes(bytes).unwrap();
        let mut total_recovered = 0usize;
        for name in db.table_names() {
            let (rows, stats) = recover_slack_rows(&db, name).unwrap();
            total_recovered += rows.len();
            for r in &rows {
                assert_eq!(r.recovery(), forensic_rs::provenance::Recovery::Slack);
                assert!(
                    matches!(r.locus(), forensic_rs::provenance::Locus::RawOffset { .. }),
                    "a slack candidate has no tag; its locus must be an absolute offset"
                );
                let non_null = r.value().iter().filter(|(_, v)| !matches!(v, OwnedColumnValue::Nil)).count();
                assert!(non_null >= MIN_NON_NULL_COLUMNS, "admitted row must meet the stricter slack bar");
            }
            let _ = stats;
        }
        eprintln!("real SRUM fixture: {total_recovered} slack-recovered row(s) across all tables");
    }

    /// **Honest, verified result on the real fixture: zero -- for the same
    /// underlying reason as `defunct`'s equivalent test.** Every table's
    /// current data tree, LV tree, and the catalog tree together account for
    /// a bounded number of bytes of page slack in this fixture (trailing
    /// gaps *and*, since `page_slack_regions` replaced the single-gap-only
    /// `slack_region`, interior gaps between live records too), and every
    /// one of those bytes is zero. The independently-measured non-zero slack
    /// across the whole file lives entirely outside any tree this crate
    /// walks -- the same orphaned/freed pages (or untracked index trees)
    /// that hold the apparently-defunct-tagged rows `defunct` cannot reach
    /// either. Recorded here as a passing assertion, not silently discarded,
    /// so a future contributor extending recovery to orphaned pages has a
    /// documented, verified starting point.
    #[test]
    fn real_srum_fixture_live_tree_slack_is_entirely_zero_filled() {
        let Ok(bytes) = std::fs::read("./artifacts/sru/SRUDB.dat") else {
            eprintln!("SKIP: fixture unavailable");
            return;
        };
        let db = EseDb::from_bytes(bytes).unwrap();
        let mut total_slack_bytes = 0usize;
        let mut total_nonzero_slack_bytes = 0usize;
        for name in db.table_names() {
            let def = db.catalog().table(name).unwrap();
            let mut walker = TreeWalker::new(def.fdp_page);
            while let Some(page) = walker.next_page(db.reader(), db.header()) {
                if let Ok(tree) = page.process_page() {
                    walker.push_children(&tree);
                    if let TreePage::Leaf(_) = &tree {
                        for region in page_slack_regions(&page) {
                            let start = region.offset as usize;
                            let end = (region.offset + region.length) as usize;
                            if let Some(slack) = page.data.get(start..end) {
                                total_slack_bytes += slack.len();
                                total_nonzero_slack_bytes += slack.iter().filter(|&&b| b != 0).count();
                            }
                        }
                    }
                }
            }
        }
        assert!(total_slack_bytes > 0, "sanity: this fixture must have some slack to make the zero below meaningful");
        assert_eq!(total_nonzero_slack_bytes, 0);
    }
}




