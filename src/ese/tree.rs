//! Shared B-tree traversal for ESE databases.
//!
//! Every ESE B-tree (the catalog, a table's data tree, a table's long-value
//! tree) is walked the same way: load a page, dispatch on `Root`/`Branch`/
//! `Leaf`, and recurse into branch children. This module implements that walk
//! exactly once, with cycle protection a naive recursive implementation
//! cannot have: a `depth` counter (as the original three copies each had)
//! bounds the *recursion depth* but not the *number of pages visited* — a
//! branch page that points back at an already-visited page within the depth
//! bound still causes exponential-time re-exploration of the same subtree.
//! [`TreeWalker`] tracks visited pages directly, so each page is loaded and
//! processed at most once.

use std::collections::HashSet;

use forensic_rs::err::ForensicResult;

use super::{
    header::Header,
    page::{entries::PageEntry, leaf::LeafPageEntry, root::RootEntry, Page, TreePage},
    reader::PageReader,
};

/// Load a single page via the reader. Shared by every B-tree consumer
/// (catalog, table data, long-value store).
pub fn load_page<'r>(reader: &'r dyn PageReader, header: &Header, page_n: u32) -> ForensicResult<Page<'r>> {
    let offset = header.page_to_file_offset(page_n as u64)? as usize;
    let size = header.page_size as usize;
    let data = reader.read_page(offset, size)?;
    Page::new(data, page_n, header)
}

/// Diagnostic counters accumulated while walking one B-tree. Not fatal on
/// their own — surfaced via `forensic_rs::debug!`/`warn!` at the call sites
/// that drive a [`TreeWalker`], rather than through a dedicated diagnostics
/// type.
#[derive(Debug, Default, Clone, Copy)]
pub struct TreeStats {
    /// Pages that failed to load (I/O error, corrupt header, wrong size).
    pub pages_unreadable: u64,
    /// Pages that loaded but failed `Page::valid_page()`, or were empty.
    pub pages_invalid: u64,
    /// Pages that were about to be visited again — the cycle guard fired.
    pub pages_revisited: u64,
    /// Pages whose `process_page()` (branch/leaf/root dispatch) failed.
    pub pages_unparsable: u64,
}

/// Cycle-safe DFS cursor over one B-tree.
///
/// Every page number is pushed onto `stack` at most once: a page number is
/// recorded into `visited` the moment it is queued (`push`/`push_children`),
/// not when it is popped, so a branch page that names an already-queued
/// child (including itself) never gets queued twice.
pub struct TreeWalker {
    stack: Vec<u32>,
    visited: HashSet<u32>,
    stats: TreeStats,
}

impl TreeWalker {
    /// Start a walk rooted at `root_page`.
    pub fn new(root_page: u32) -> Self {
        let mut visited = HashSet::new();
        visited.insert(root_page);
        Self {
            stack: vec![root_page],
            visited,
            stats: TreeStats::default(),
        }
    }

    /// Queue `page_n` for a future visit, unless it has already been queued.
    fn push(&mut self, page_n: u32) {
        if self.visited.insert(page_n) {
            self.stack.push(page_n);
        } else {
            self.stats.pages_revisited += 1;
        }
    }

    /// Queue every child page number named by an already-parsed branch/root
    /// page. Call this after dispatching on the page returned by
    /// [`TreeWalker::next_page`].
    pub fn push_children(&mut self, tree: &TreePage<'_>) {
        match tree {
            TreePage::Branch(branch) => {
                for entry in &branch.entries {
                    self.push(entry.child_page_number);
                }
            }
            TreePage::Root(root) => {
                for entry in &root.entries {
                    if let RootEntry::Branch(b) = entry {
                        self.push(b.child_page_number);
                    }
                }
            }
            TreePage::Leaf(_) => {}
        }
    }

    /// Pop and load the next unvisited, valid page, skipping (and counting)
    /// any page that fails to load or fails structural validation. Returns
    /// `None` once the walk is exhausted.
    pub fn next_page<'r>(&mut self, reader: &'r dyn PageReader, header: &Header) -> Option<Page<'r>> {
        loop {
            let page_n = self.stack.pop()?;
            let page = match load_page(reader, header, page_n) {
                Ok(p) => p,
                Err(e) => {
                    forensic_rs::debug!("ESE: cannot load page {page_n}: {e}");
                    self.stats.pages_unreadable += 1;
                    continue;
                }
            };
            if !page.valid_page() || page.empty_page() {
                self.stats.pages_invalid += 1;
                continue;
            }
            return Some(page);
        }
    }

    pub fn stats(&self) -> TreeStats {
        self.stats
    }

    /// Record that `page`'s `process_page()` call failed, for diagnostics.
    pub fn record_unparsable(&mut self) {
        self.stats.pages_unparsable += 1;
    }
}

/// Invoke `f` once per leaf entry found in `tree` — collapses the
/// `TreePage::Leaf` and `TreePage::Root`-with-leaf-entries arms that every
/// consumer previously duplicated.
///
/// Yields the whole [`LeafPageEntry`], so a caller can see each entry's
/// `tag_index`/`defunct` alongside its decoded data. Callers that only need
/// the payload should use [`for_each_leaf_entry`].
pub fn for_each_leaf_page_entry<'e>(tree: &TreePage<'e>, mut f: impl FnMut(&LeafPageEntry<'e>)) {
    match tree {
        TreePage::Leaf(leaf) => {
            for entry in &leaf.entries {
                f(entry);
            }
        }
        TreePage::Root(root) => {
            for entry in &root.entries {
                if let RootEntry::Leaf(leaf_entry) = entry {
                    f(leaf_entry);
                }
            }
        }
        TreePage::Branch(_) => {}
    }
}

/// Invoke `f` once per leaf entry's decoded payload. See
/// [`for_each_leaf_page_entry`] when the entry's tag index or defunct flag
/// matters.
pub fn for_each_leaf_entry<'e>(tree: &TreePage<'e>, mut f: impl FnMut(&PageEntry<'e>)) {
    for_each_leaf_page_entry(tree, |entry| f(&entry.data));
}

/// Eagerly walk every leaf entry of the B-tree rooted at `root_page`,
/// invoking `visit` for each. Used by the two consumers (catalog, long-value
/// store) that need the whole tree collected up front rather than streamed
/// lazily (`EseDb`'s row cursor stays lazy and drives a [`TreeWalker`]
/// directly instead).
pub fn visit_leaves(
    reader: &dyn PageReader,
    header: &Header,
    root_page: u32,
    mut visit: impl FnMut(&PageEntry<'_>),
) -> ForensicResult<TreeStats> {
    let mut walker = TreeWalker::new(root_page);
    while let Some(page) = walker.next_page(reader, header) {
        match page.process_page() {
            Ok(tree) => {
                walker.push_children(&tree);
                for_each_leaf_entry(&tree, &mut visit);
            }
            Err(e) => {
                forensic_rs::debug!("ESE: cannot process page {}: {e}", page.page_number);
                walker.record_unparsable();
            }
        }
    }
    Ok(walker.stats())
}

#[cfg(test)]
mod tst {
    use super::*;
    use crate::ese::page::branch::{BranchPage, BranchPageEntry, BranchPageHeader};

    #[test]
    fn self_referencing_branch_page_terminates() {
        // A single page whose only child is itself. Without cycle protection
        // this would push the same page number forever.
        let mut walker = TreeWalker::new(1);
        let page_n = walker_pop_page_n(&mut walker);
        assert_eq!(Some(1), page_n);

        let entry = BranchPageEntry {
            page_key_size: 0,
            page_key: &[],
            child_page_number: 1, // points back at itself
        };
        let branch = BranchPage {
            header: BranchPageHeader::new(&[]),
            entries: vec![entry],
        };
        let tree = TreePage::Branch(branch);
        walker.push_children(&tree);

        // The self-reference must be rejected as a revisit, not re-queued.
        assert!(walker.stack.is_empty(), "self-referencing child must not be queued");
        assert_eq!(1, walker.stats().pages_revisited);
    }

    #[test]
    fn two_page_cycle_terminates() {
        let mut walker = TreeWalker::new(1);
        walker.push(2);
        walker.push(1); // cycle back to the root — must not be re-queued
        assert_eq!(1, walker.stats().pages_revisited);
        assert_eq!(vec![1u32, 2u32], walker.stack, "page 1 must appear only once");
    }

    fn walker_pop_page_n(walker: &mut TreeWalker) -> Option<u32> {
        walker.stack.pop()
    }
}
