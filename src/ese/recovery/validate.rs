//! The single admission gate every recovery source funnels through.
//!
//! Shared by [`super::defunct`] and [`super::slack`] (and, when it exists,
//! any future log-borne recovery source): decode via the schema the live
//! read path uses, then reject a result with too little observable content.
//! See [`super::defunct`]'s module documentation for the full soundness
//! rationale — copied from this crate's closest precedent, `frnsc-hive`'s
//! deleted-cell carving, which puts it best: **a candidate that fails any
//! check is silently dropped, not reported with lower confidence — there is
//! no partial-credit "maybe" a case report can act on.**

use crate::ese::column::{ColumnValue, OwnedColumnValue, TableSchema};
use crate::ese::db::Row;
use crate::ese::page::entries::table_value::TableValueEntry;

/// Decode `tv` against `schema` and admit it only if at least `min_non_null`
/// columns decode to a **meaningful** value -- see [`is_meaningful`].
///
/// `min_non_null` is deliberately a caller-chosen parameter rather than a
/// fixed constant: a candidate governed by a tag the engine itself wrote
/// (defunct-tagged, [`super::defunct`]) is reliable evidence on its own, and
/// one meaningful column is enough corroboration that real bytes, not
/// noise, were decoded. A candidate found by pure structural plausibility
/// with no governing tag ([`super::slack`]) has no such backing — one
/// meaningful column reinterpreted from a stray byte sequence can pass by
/// pure chance, so that source requires a higher bar. Long-value columns
/// are never resolved here (every caller passes `lv_store: None`) — see the
/// callers for source-specific reasoning on exactly why.
pub fn decode_and_admit(tv: &TableValueEntry<'_>, schema: &TableSchema, min_non_null: usize) -> Option<Row> {
    let pairs = schema.decode_record(tv, None);
    if pairs.is_empty() {
        return None;
    }
    let non_null = pairs.iter().filter(|(_, v)| is_meaningful(v)).count();
    if non_null < min_non_null.max(1) {
        return None;
    }
    let owned: Vec<(String, OwnedColumnValue)> = pairs.into_iter().map(|(n, v)| (n, v.into())).collect();
    Some(Row::from_pairs(owned))
}

/// `Nil` is obviously not meaningful. Less obviously: a decoded numeric
/// zero, or all-zero bytes, is **also** not counted as meaningful content.
/// A zero-valued integer/float column is byte-for-byte indistinguishable
/// from unwritten/padding memory reinterpreted as that column type — for a
/// tag-governed record that ambiguity doesn't matter (the tag itself is the
/// evidence), but for a structurally-plausibility-only candidate ([`super::slack`]),
/// letting an all-zero decode count toward the admission threshold was
/// verified to admit exactly the kind of coincidental match this gate
/// exists to reject: a byte window straddling a real record and its
/// trailing zero padding, reinterpreted as a *second*, all-zero "record".
/// `Bit(false)` is deliberately excluded from this rule (a boolean's only
/// two values are both equally meaningful; there is no "unwritten" reading
/// of a bit column the way there is for a wide integer).
pub fn is_meaningful(value: &ColumnValue<'_>) -> bool {
    match value {
        ColumnValue::Nil => false,
        ColumnValue::UnsignedByte(0)
        | ColumnValue::Short(0)
        | ColumnValue::Long(0)
        | ColumnValue::Currency(0)
        | ColumnValue::UnsignedLong(0)
        | ColumnValue::LongLong(0)
        | ColumnValue::UnsignedShort(0) => false,
        ColumnValue::IEEESingle(f) if *f == 0.0 => false,
        ColumnValue::IEEEDouble(f) if *f == 0.0 => false,
        ColumnValue::GUID(bytes) if *bytes == [0u8; 16] => false,
        ColumnValue::Binary(bytes) | ColumnValue::Text(bytes) if bytes.iter().all(|&b| b == 0) => false,
        ColumnValue::LongBinary(bytes) | ColumnValue::LongText(bytes) if bytes.iter().all(|&b| b == 0) => false,
        _ => true,
    }
}
