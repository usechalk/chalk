//! OneRoster 1.1 CSV import/export support.
//!
//! Provides reading and writing of OneRoster CSV bulk data files including
//! manifest.csv parsing, per-entity CSV row types, and round-trip conversion
//! between CSV rows and domain models.

pub mod manifest;
pub mod reader;
pub mod rows;
pub mod writer;

pub use reader::read_oneroster_csv;
pub use writer::write_oneroster_csv;
