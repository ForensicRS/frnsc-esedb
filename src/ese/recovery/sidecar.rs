//! Opt-in export of recovered rows, with real provenance.
//!
//! Nothing in this crate writes anything unless [`export_recovered`] (or its
//! path-taking convenience [`export_recovered_to_files`]) is called by the
//! caller -- no default location, no temp directory, never invoked implicitly
//! by `EseDb::open` or any recovery function. This mirrors the framework's
//! own stated policy for `SpillStore`/`FactStore`/`TimelineStore`: *"writing
//! evidence-derived bytes to disk is a decision an examiner must own, not a
//! library default"*. The primary entry point takes **writers**, not paths,
//! so the caller owns the sink entirely.
//!
//! # Format
//!
//! [`forensic_rs::pipeline::sinks::ProvenanceJsonlSink`] does the writing:
//! one JSON object per line, `{"record": {...}, "provenance": <u32>,
//! "confidence": "...", "anomalies": [...]}`, plus a matching
//! `ProvenanceSideTable` written to the sidecar writer at `finalize()`. The
//! `provenance` index on each line resolves into that side table. Output is
//! byte-identical across runs.
//!
//! # Provenance
//!
//! Earlier versions of this module hand-rolled JSONL with a structured
//! `source` field, because `EseDb` held no `ProvenanceStore` and this crate
//! would not invent a `ProvenanceId`-shaped string. That constraint is now
//! resolved rather than worked around: every row gets a real
//! [`forensic_rs::provenance::ProvenanceId`] minted from a real store, and
//! [`forensic_rs::provenance::Confidence`] is graded from
//! `(Acquisition, Recovery)` by the framework instead of being asserted here.
//!
//! Re-locatability is preserved and is still the property that matters: each
//! record carries its [`forensic_rs::provenance::Locus`] as explicit fields
//! ([`FIELD_PAGE`]/[`FIELD_SLOT`] for a defunct-tagged row, [`FIELD_PAGE`]/
//! [`FIELD_OFFSET`] for a slack candidate), so a second examiner can seek
//! straight to the bytes. [`FIELD_EVENT_ID`] carries a deterministic
//! [`forensic_rs::pipeline::timeline::EventId`] so the same row re-hashes
//! identically across runs, and a recovered row is distinguishable from the
//! allocated read of the same structure.
//!
//! # Column type fidelity
//!
//! `forensic_rs::field::Field` has no binary variant, so `GUID`/`Binary`/
//! `LongBinary` columns all render as `Field::Text` (see [`column_field`]).
//! A GUID's dashed form is visually distinct from bare hex, but `Binary` and
//! a `Text` column that happens to contain hex-looking bytes render
//! identically -- a consumer should never have to guess the real ESE type
//! from the exported string's shape. For exactly those three variants, a
//! sibling `{FIELD_COLUMN_TYPE_PREFIX}<column name>` field names the real
//! type; `Text`/`LongText` need no tag (the string *is* the value, no
//! encoding transform occurred), and every numeric/`Date` column already
//! carries its real type in the `Field` variant itself.

use std::io::Write;
use std::path::Path;

use forensic_rs::data::ForensicData;
use forensic_rs::err::{ForensicError, ForensicResult};
use forensic_rs::pipeline::sinks::ProvenanceJsonlSink;
use forensic_rs::pipeline::timeline::EventId;
use forensic_rs::pipeline::traits::TriageSink;
use forensic_rs::prelude::Artifact;
use forensic_rs::provenance::{Acquisition, Locus, ProvenanceStore, SourceKey};

use super::RecoveredRow;
use crate::ese::column::OwnedColumnValue;

/// Page number a defunct-tagged row was recovered from.
pub const FIELD_PAGE: &str = "ese.page";
/// Tag (slot) index within [`FIELD_PAGE`].
pub const FIELD_SLOT: &str = "ese.slot";
/// Byte offset within [`FIELD_PAGE`] a slack candidate was carved from.
pub const FIELD_OFFSET: &str = "ese.offset";
/// The table the row belongs to.
pub const FIELD_TABLE: &str = "ese.table";
/// Deterministic timeline identity -- see [`EventId`].
pub const FIELD_EVENT_ID: &str = "ese.event_id";

/// The `projection_kind` tag for a recovered ESE row.
///
/// A stable string, not a type: `ProjectionKind` does not exist in the
/// framework -- [`EventId::new`] takes a plain `&str`. Changing this value
/// changes every emitted [`EventId`], so treat it as part of the output
/// format.
pub const PROJECTION_RECOVERED_ROW: &str = "ese_recovered_row";

/// Prefix for the per-column type-disambiguation field
/// `{FIELD_COLUMN_TYPE_PREFIX}<column name>` -- see the module documentation
/// on column type fidelity. Present only for a `GUID`/`Binary`/`LongBinary`
/// column; see [`ambiguous_binary_type`].
pub const FIELD_COLUMN_TYPE_PREFIX: &str = "ese.column_type.";

/// Column values that decoded to nothing are omitted rather than emitted as
/// an explicit null: an absent column and a column that decoded to `Nil` are
/// the same observation here, and writing one out as a value invites reading
/// it as a recorded empty.
fn column_field(value: &OwnedColumnValue) -> Option<forensic_rs::field::Field> {
    use forensic_rs::field::Field;
    Some(match value {
        OwnedColumnValue::Nil => return None,
        OwnedColumnValue::Bit(v) => Field::from(*v),
        OwnedColumnValue::UnsignedByte(v) => Field::U64(*v as u64),
        OwnedColumnValue::UnsignedShort(v) => Field::U64(*v as u64),
        OwnedColumnValue::UnsignedLong(v) => Field::U64(*v as u64),
        OwnedColumnValue::Short(v) => Field::I64(*v as i64),
        OwnedColumnValue::Long(v) => Field::I64(*v as i64),
        OwnedColumnValue::Currency(v) => Field::I64(*v),
        OwnedColumnValue::LongLong(v) => Field::I64(*v),
        OwnedColumnValue::IEEESingle(v) => Field::F64(*v as f64),
        OwnedColumnValue::IEEEDouble(v) => Field::F64(*v),
        OwnedColumnValue::DateTime(v) => Field::Date(*v),
        // GUID/Binary formatting (hex, GUID braces-and-dashes) already lives
        // in `OwnedColumnValue`'s own `Display` impl -- reuse it rather than
        // duplicate it here. `ambiguous_binary_type` is what keeps this from
        // being a silent type-flattening: see the module documentation.
        OwnedColumnValue::GUID(_) | OwnedColumnValue::Binary(_) | OwnedColumnValue::LongBinary(_) => {
            Field::Text(value.to_string().into())
        }
        OwnedColumnValue::Text(b) | OwnedColumnValue::LongText(b) => {
            Field::Text(crate::ese::column::bytes_to_string(b).into())
        }
    })
}

/// The real ESE type for a value whose export as `Field::Text` would
/// otherwise be indistinguishable from an ordinary text column -- `None` for
/// every variant that doesn't need disambiguating (see the module
/// documentation on column type fidelity).
fn ambiguous_binary_type(value: &OwnedColumnValue) -> Option<&'static str> {
    match value {
        OwnedColumnValue::GUID(_) => Some("GUID"),
        OwnedColumnValue::Binary(_) => Some("Binary"),
        OwnedColumnValue::LongBinary(_) => Some("LongBinary"),
        _ => None,
    }
}

/// Summary of one export. A non-zero `dropped` is not fatal but is never
/// silent: [`ProvenanceJsonlSink`] swallows a per-record serialization
/// failure into a counter rather than returning an error, so the count is
/// surfaced here for the caller to act on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExportSummary {
    pub written: u64,
    pub dropped: u64,
}

/// Write `rows` (all belonging to `table`) to `records` as provenance-bearing
/// JSONL, and the matching provenance side table to `sidecar`.
///
/// `evidence_id` identifies the host or case the database came from;
/// `source_key` identifies the database itself (normally
/// [`SourceKey::Path`]); `acquisition` states how the evidence was obtained,
/// which together with each row's `Recovery` is what the framework grades
/// [`forensic_rs::provenance::Confidence`] from.
///
/// Returns the two writers back (via [`ProvenanceJsonlSink::into_inner`])
/// alongside the summary, so a caller exporting into an in-memory buffer can
/// get its content back without this function needing to know it is a
/// buffer.
pub fn export_recovered<W: Write + 'static, S: Write + 'static>(
    records: W,
    sidecar: S,
    evidence_id: &str,
    source_key: SourceKey,
    acquisition: Acquisition,
    table: &str,
    rows: &[RecoveredRow],
) -> ForensicResult<(W, S, ExportSummary)> {
    // The store handed to the sink must be the same one the ids were minted
    // from: `ProvenanceId` is a dense index, so an id from a foreign store
    // does not merely degrade to `Unknown`, it can silently resolve to a
    // different record.
    let store = ProvenanceStore::new();
    let source = store.register_source(source_key.clone());

    let mut sink = ProvenanceJsonlSink::new(records, sidecar, store.clone())
        // This crate's version, not forensic-rs's (which is the default).
        .with_tool_version(env!("CARGO_PKG_VERSION"));

    for recovered in rows {
        let locus = recovered.locus();
        let id = source.mint(acquisition, recovered.recovery());
        let mut data = ForensicData::new(evidence_id, Artifact::Unknown, id);

        data.insert(FIELD_TABLE.into(), forensic_rs::field::Field::Text(table.to_string().into()));
        match locus {
            Locus::Record { page, slot } => {
                data.insert(FIELD_PAGE.into(), forensic_rs::field::Field::U64(page));
                data.insert(FIELD_SLOT.into(), forensic_rs::field::Field::U64(slot as u64));
            }
            Locus::PageOffset { page, offset } => {
                data.insert(FIELD_PAGE.into(), forensic_rs::field::Field::U64(page));
                data.insert(FIELD_OFFSET.into(), forensic_rs::field::Field::U64(offset as u64));
            }
            Locus::RawOffset { offset } => {
                data.insert(FIELD_OFFSET.into(), forensic_rs::field::Field::U64(offset));
            }
            // Every locus this crate mints is one of the three above; a
            // future recovery source adding another should extend this
            // match rather than let the address silently vanish from the
            // export.
            other => {
                forensic_rs::debug!("ESE sidecar: unmodelled locus {other:?} emitted without address fields");
            }
        }
        data.insert(
            FIELD_EVENT_ID.into(),
            forensic_rs::field::Field::U64(
                EventId::new(evidence_id, &source_key, locus, PROJECTION_RECOVERED_ROW).as_u64(),
            ),
        );

        for (name, value) in recovered.value().iter() {
            if let Some(field) = column_field(value) {
                if let Some(ese_type) = ambiguous_binary_type(value) {
                    data.insert(
                        format!("{FIELD_COLUMN_TYPE_PREFIX}{name}").into(),
                        forensic_rs::field::Field::Text(ese_type.into()),
                    );
                }
                data.insert(name.to_string().into(), field);
            }
        }

        sink.on_data(&data)?;
    }

    sink.finalize()?;
    let summary = ExportSummary { written: sink.record_count(), dropped: sink.error_count() };
    let (records, sidecar) = sink.into_inner();
    Ok((records, sidecar, summary))
}

/// Convenience wrapper over [`export_recovered`] that creates (or truncates)
/// the two files itself. Still fully opt-in -- both paths are the caller's.
#[allow(clippy::too_many_arguments)]
pub fn export_recovered_to_files(
    records_path: impl AsRef<Path>,
    sidecar_path: impl AsRef<Path>,
    evidence_id: &str,
    source_key: SourceKey,
    acquisition: Acquisition,
    table: &str,
    rows: &[RecoveredRow],
) -> ForensicResult<ExportSummary> {
    let records = std::fs::File::create(records_path.as_ref())
        .map_err(|e| ForensicError::io_error_with_source(e, "Cannot create recovery records file"))?;
    let sidecar = std::fs::File::create(sidecar_path.as_ref())
        .map_err(|e| ForensicError::io_error_with_source(e, "Cannot create recovery sidecar file"))?;
    let (_, _, summary) = export_recovered(records, sidecar, evidence_id, source_key, acquisition, table, rows)?;
    Ok(summary)
}

#[cfg(test)]
mod tst {
    use super::*;
    use crate::ese::db::Row;
    use crate::ese::recovery::{slack_locus, tagged_locus};
    use forensic_rs::provenance::Recovery;

    fn sample_rows() -> Vec<RecoveredRow> {
        vec![
            RecoveredRow::new(
                Row::from_pairs(vec![
                    ("Name".to_string(), OwnedColumnValue::Text(b"He said \"hi\"".to_vec())),
                    ("Count".to_string(), OwnedColumnValue::Long(42)),
                    ("Absent".to_string(), OwnedColumnValue::Nil),
                ]),
                Recovery::DeletedMetadata,
                tagged_locus(7, 3),
            ),
            RecoveredRow::new(
                Row::from_pairs(vec![("Count".to_string(), OwnedColumnValue::Long(9))]),
                Recovery::Slack,
                slack_locus(9, 0x4000),
            ),
        ]
    }

    fn export_to_vecs(rows: &[RecoveredRow]) -> (String, String, ExportSummary) {
        let (records, sidecar, summary) = export_recovered(
            Vec::new(),
            Vec::new(),
            "host1",
            SourceKey::Path("C:/db.dat".to_string()),
            Acquisition::ImageRead,
            "Test\"Table",
            rows,
        )
        .unwrap();
        (String::from_utf8(records).unwrap(), String::from_utf8(sidecar).unwrap(), summary)
    }

    #[test]
    fn each_row_carries_its_address_and_a_real_provenance_index() {
        let (records, sidecar, summary) = export_to_vecs(&sample_rows());
        assert_eq!(summary, ExportSummary { written: 2, dropped: 0 });

        let lines: Vec<&str> = records.lines().collect();
        assert_eq!(lines.len(), 2, "one line per row, no manifest line");

        // A defunct-tagged row reports its (page, tag) home.
        assert!(lines[0].contains("\"ese.page\":7"));
        assert!(lines[0].contains("\"ese.slot\":3"));
        assert!(!lines[0].contains("ese.offset"));
        // The embedded quote must be escaped by the serializer, not left to
        // break the surrounding JSON.
        assert!(lines[0].contains(r#"He said \"hi\""#));
        assert!(lines[0].contains(r#"Test\"Table"#));
        // A column that decoded to Nil is omitted, not written as a null.
        assert!(!lines[0].contains("Absent"));

        // A slack candidate reports its page plus an offset within it, and
        // no slot -- there is no tag, and claiming one would mis-seek.
        assert!(lines[1].contains("\"ese.page\":9"));
        assert!(lines[1].contains("\"ese.offset\":16384"));
        assert!(!lines[1].contains("ese.slot"));

        // Confidence is graded by the framework from (Acquisition, Recovery),
        // not asserted by this crate: DeletedMetadata from an image is
        // Medium, Slack is Low regardless.
        assert!(lines[0].contains("\"confidence\":\"Medium\""));
        assert!(lines[1].contains("\"confidence\":\"Low\""));

        // Every record's provenance index resolves in the side table.
        assert!(sidecar.contains("\"records\""));
        assert!(sidecar.contains("DeletedMetadata"));
        assert!(sidecar.contains("Slack"));
        assert!(sidecar.contains("C:/db.dat"));
        assert!(sidecar.contains(env!("CARGO_PKG_VERSION")));
    }

    /// `Field` has no binary variant, so GUID/Binary/LongBinary all render
    /// as `Field::Text` -- without a type tag a consumer could not tell one
    /// from a Text column that happens to contain hex-looking bytes. Text
    /// itself needs no tag: it *is* a string, no encoding transform ran.
    #[test]
    fn ambiguous_binary_types_carry_a_disambiguating_sibling_field() {
        let row = RecoveredRow::new(
            Row::from_pairs(vec![
                ("Id".to_string(), OwnedColumnValue::GUID([0x01; 16])),
                ("Blob".to_string(), OwnedColumnValue::Binary(vec![0xde, 0xad, 0xbe, 0xef])),
                ("Big".to_string(), OwnedColumnValue::LongBinary(vec![0xca, 0xfe])),
                ("Label".to_string(), OwnedColumnValue::Text(b"plain string".to_vec())),
            ]),
            Recovery::DeletedMetadata,
            tagged_locus(1, 1),
        );
        let (records, _, _) = export_to_vecs(&[row]);
        let line = records.lines().next().unwrap();

        assert!(line.contains(r#""ese.column_type.Id":"GUID""#));
        assert!(line.contains(r#""ese.column_type.Blob":"Binary""#));
        assert!(line.contains(r#""ese.column_type.Big":"LongBinary""#));
        // Text gets no tag at all -- not even a "Text" one.
        assert!(!line.contains("ese.column_type.Label"));
    }

    #[test]
    fn export_is_byte_identical_across_runs() {
        let rows = sample_rows();
        assert_eq!(export_to_vecs(&rows), export_to_vecs(&rows));
    }

    #[test]
    fn the_same_locus_rehashes_to_the_same_event_id_and_differs_by_address() {
        let (records, _, _) = export_to_vecs(&sample_rows());
        let (records_again, _, _) = export_to_vecs(&sample_rows());
        assert_eq!(records, records_again);

        let key = SourceKey::Path("C:/db.dat".to_string());
        let tagged = EventId::new("host1", &key, tagged_locus(7, 3), PROJECTION_RECOVERED_ROW);
        let carved = EventId::new("host1", &key, slack_locus(9, 0x4000), PROJECTION_RECOVERED_ROW);
        assert_ne!(tagged.as_u64(), carved.as_u64());
        assert_eq!(
            tagged.as_u64(),
            EventId::new("host1", &key, tagged_locus(7, 3), PROJECTION_RECOVERED_ROW).as_u64()
        );
    }

    #[test]
    fn an_empty_export_still_writes_a_resolvable_side_table() {
        let (records, sidecar, summary) = export_to_vecs(&[]);
        assert_eq!(summary, ExportSummary { written: 0, dropped: 0 });
        assert!(records.is_empty());
        // finalize() must still have run: without the side table every
        // record line in a later append would be unreadable.
        assert!(sidecar.contains("\"records\""));
    }
}
