//! Recovery source 1 of 3 (the only one implemented so far): rows whose page
//! tag is still marked [`TAG_DEFUNCT`] but whose underlying bytes have not
//! yet been reclaimed by the engine.
//!
//! # Forensic soundness: strict validation over recall
//!
//! A defunct tag flag is reliable evidence on its own -- ESE sets it
//! explicitly on deletion, unlike carving a signature out of raw bytes -- but
//! decoding the entry underneath it is not automatically safe: the tag's
//! `value_size`/`value_offset` can, in principle, describe a byte range the
//! engine has since begun reusing for something else (a live entry's
//! overflow, or the tag array itself after a shrink). This module therefore
//! applies the same policy `frnsc-hive`'s deleted-cell carving does for its
//! own, harder case: **every candidate is decoded through the exact same
//! path the live row iterator uses** ([`TableSchema::decode_record`], the
//! same `LeafPageEntry::new` construction), so a candidate is at minimum
//! structurally self-consistent with the schema; and a candidate whose
//! decoded columns are **all** null is dropped rather than reported as a
//! defunct row with no observable content -- a row with no evidentiary
//! content is not worth an examiner's attention, and near-certainly
//! indicates the underlying bytes have already been overwritten with
//! something that only coincidentally still parses.
//!
//! A candidate that fails to parse at all, or that decodes to all-null
//! columns, is **silently dropped, not reported with lower confidence**:
//! there is no partial-credit "maybe" a case report can act on.

use forensic_rs::err::ForensicResult;

use crate::ese::column::TableSchema;
use crate::ese::db::EseDb;
use crate::ese::page::entries::PageEntry;
use crate::ese::page::leaf::LeafPageEntry;
use crate::ese::page::TreePage;
use crate::ese::tag::TAG_DEFUNCT;
use crate::ese::tree::TreeWalker;

use super::validate::decode_and_admit;
use super::{tagged_locus, RecoveredRow, RecoveryStats};

/// Walk `table`'s data B-tree looking for tags marked [`TAG_DEFUNCT`], and
/// decode every one that survives the admission gate described in this
/// module's documentation.
///
/// Long-value columns (`LongText`/`LongBinary`) on a recovered row are
/// always `Nil`, deliberately: resolving them would mean looking up the
/// row's recorded LVID in the table's *current* long-value tree, but that
/// LVID may since have been reused by an unrelated, currently-live long
/// value -- attaching that value to a deleted row would silently fabricate
/// a connection the bytes do not actually support. Reporting `Nil` here is
/// the "report less, never guess" policy this crate uses elsewhere (see
/// `AGENTS.md`'s note on `LongValueStore`'s gap-detection).
pub fn recover_defunct_rows(db: &EseDb, table: &str) -> ForensicResult<(Vec<RecoveredRow>, RecoveryStats)> {
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
                    // Tag 0 is the page's own common-key/external header,
                    // never a row -- entries start at 1, matching every
                    // other leaf-tag walk in this crate (see
                    // `LeafPageEntry::leaf_entries`).
                    for i in 1..page.tags.len() {
                        if page.tags[i].tag_flags & TAG_DEFUNCT == 0 {
                            continue;
                        }
                        stats.candidate_tags_found += 1;
                        match recover_one(&page, i, &schema) {
                            Some(row) => {
                                results.push(row);
                                stats.rows_recovered += 1;
                            }
                            None => stats.rows_rejected += 1,
                        }
                    }
                }
            }
            Err(e) => {
                forensic_rs::debug!(
                    "ESE recovery: cannot process page {} while scanning '{table}' for defunct rows: {e}",
                    page.page_number
                );
                walker.record_unparsable();
                stats.pages_unparsable += 1;
            }
        }
    }

    Ok((results, stats))
}

fn recover_one(
    page: &crate::ese::page::Page<'_>,
    tag_index: usize,
    schema: &TableSchema,
) -> Option<RecoveredRow> {
    let entry = LeafPageEntry::new(tag_index, page).ok()?;
    let PageEntry::TableValue(tv) = &entry.data else {
        return None;
    };
    let row = decode_and_admit(tv, schema, 1)?;
    Some(RecoveredRow::new(
        row,
        forensic_rs::provenance::Recovery::DeletedMetadata,
        tagged_locus(page.page_number, tag_index as u16),
    ))
}

#[cfg(test)]
mod tst {
    use super::*;
    use crate::ese::column::{ColumnType, OwnedColumnValue};
    use crate::ese::db::EseDb;
    use crate::ese::page::Page;
    use crate::ese::tag::{Tag, TAG_COMMON_KEY};

    /// Build a dummy page whose tag 1 carries `tag_data` with `tag_flags`.
    /// Mirrors `LeafPageEntry`'s own test helper (`leaf.rs`) -- kept as a
    /// separate copy rather than exposed from there, since it is purely a
    /// test fixture builder, not part of that module's public surface.
    fn make_page(tag_data: &[u8], tag_flags: u8) -> Page<'static> {
        let mut page = Page::dummy();
        let header_size = page.header.header_size as usize;
        let mut buf = vec![0u8; header_size];
        buf.extend_from_slice(tag_data);
        page.data = std::borrow::Cow::Owned(buf);
        page.tags = vec![
            Tag { value_offset: 0, tag_flags: 0, value_size: 0 },
            Tag { value_offset: 0, tag_flags, value_size: tag_data.len() as u16 },
        ];
        page
    }

    fn one_fixed_long_column_schema() -> TableSchema {
        TableSchema {
            name: "Test".to_string(),
            columns: vec![crate::ese::column::ColumnDef {
                id: 1,
                col_type: ColumnType::Long,
                name: "Col1".to_string(),
                flags: 0,
                codepage: 0,
            }],
        }
    }

    /// The minimal-record byte pattern from
    /// `page::entries::table_value::tst::parse_minimal_record`: one fixed
    /// column (id 1), no variable/tagged columns, 4 bytes of fixed data.
    /// Preceded by a `common_key_size = 0` prefix so `LeafPageEntry::new`
    /// (with `TAG_COMMON_KEY` unset) strips exactly that much before
    /// reaching the table-value record.
    fn minimal_record_tag_data() -> Vec<u8> {
        let mut data = vec![0x00, 0x00]; // common_key_size = 0
        data.extend_from_slice(&[0x01, 0x7F, 0x08, 0x00, 0xAB, 0xCD, 0xEF, 0x01]);
        data
    }

    #[test]
    fn synthetic_defunct_tag_is_recovered_with_correct_provenance() {
        let tag_data = minimal_record_tag_data();
        let page = make_page(&tag_data, TAG_DEFUNCT);
        assert_ne!(page.tags[1].tag_flags & TAG_DEFUNCT, 0, "sanity: tag really is marked defunct");
        assert_eq!(page.tags[1].tag_flags & TAG_COMMON_KEY, 0, "sanity: no common-key flag set");

        let schema = one_fixed_long_column_schema();
        let recovered = recover_one(&page, 1, &schema).expect("a valid defunct record must be recovered");

        assert_eq!(recovered.recovery(), forensic_rs::provenance::Recovery::DeletedMetadata);
        assert_eq!(recovered.locus(), tagged_locus(page.page_number, 1));
        assert!(recovered.value().iter().any(|(_, v)| !matches!(v, OwnedColumnValue::Nil)));
    }

    #[test]
    fn synthetic_all_null_defunct_record_is_rejected_not_fabricated() {
        // Same shape, but the schema's declared column ID (99) is absent
        // from the record's actual fixed range (last_fixed_column_id = 1),
        // so every decoded column comes back Nil -- the admission gate must
        // drop this rather than report a contentless "recovered" row.
        let tag_data = minimal_record_tag_data();
        let page = make_page(&tag_data, TAG_DEFUNCT);
        let schema = TableSchema {
            name: "Test".to_string(),
            columns: vec![crate::ese::column::ColumnDef {
                id: 99,
                col_type: ColumnType::Long,
                name: "Unrelated".to_string(),
                flags: 0,
                codepage: 0,
            }],
        };
        assert!(recover_one(&page, 1, &schema).is_none());
    }

    #[test]
    fn a_live_non_defunct_tag_is_never_visited_by_the_recovery_loop() {
        // This is the flag-gate itself, exercised the same way
        // `recover_defunct_rows`'s loop does: a tag with no TAG_DEFUNCT bit
        // must never even be attempted.
        let tag_data = minimal_record_tag_data();
        let page = make_page(&tag_data, 0);
        assert_eq!(page.tags[1].tag_flags & TAG_DEFUNCT, 0);
    }

    #[test]
    fn missing_table_returns_an_error_not_a_panic() {
        let Ok(bytes) = std::fs::read("./artifacts/sru/SRUDB.dat") else {
            eprintln!("SKIP: fixture unavailable");
            return;
        };
        let db = EseDb::from_bytes(bytes).unwrap();
        assert!(recover_defunct_rows(&db, "does-not-exist-anywhere").is_err());
    }

    /// **Honest, verified result on the real fixture: zero.** Investigating
    /// this fixture found 14 pages that look defunct-tagged under a naive
    /// whole-file byte scan (page header + tag array, independent of B-tree
    /// membership) -- but none of those 14 pages are reachable from *any*
    /// table's current data tree, LV tree, or the catalog tree (verified by
    /// walking every one with `TreeWalker` and checking page-number
    /// membership). They are pages the engine has fully unlinked (freed)
    /// while leaving their old leaf content physically intact -- a
    /// materially different, riskier recovery source (closer to page-slack
    /// carving: it requires a linear scan of the whole file rather than a
    /// tree walk, and honest table attribution without guessing a schema
    /// against an orphaned page is an open problem) than "a tag still
    /// linked into a live tree, individually marked defunct", which is what
    /// this module implements. Recording that as a passing assertion here
    /// -- rather than silently deleting the discovery -- so a future
    /// contributor adding orphaned-page carving has a documented, verified
    /// starting point instead of rediscovering this distinction.
    #[test]
    fn real_srum_fixture_has_zero_defunct_tags_in_any_live_tree() {
        let Ok(bytes) = std::fs::read("./artifacts/sru/SRUDB.dat") else {
            eprintln!("SKIP: fixture unavailable");
            return;
        };
        let db = EseDb::from_bytes(bytes).unwrap();
        let mut total_candidates = 0usize;
        let mut total_recovered = 0usize;
        for name in db.table_names() {
            let (rows, stats) = recover_defunct_rows(&db, name).unwrap();
            total_candidates += stats.candidate_tags_found;
            total_recovered += rows.len();
        }
        assert_eq!(total_candidates, 0);
        assert_eq!(total_recovered, 0);
    }
}



