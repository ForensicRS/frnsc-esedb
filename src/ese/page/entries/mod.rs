use index::IndexEntry;

pub mod index;
pub mod long_value;
pub mod space_tree;
pub mod table_value;

#[derive(Debug, Clone)]
pub enum PageEntry<'a> {
    Index(IndexEntry<'a>),
    LongValue(long_value::LongValueEntry<'a>),
    SpaceTree(space_tree::SpaceTreeEntry<'a>),
    TableValue
}