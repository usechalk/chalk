//! Report-builder-lite (SS-5): a saved asset report is a name, the
//! inventory's own filter query string, and one group-by dimension. The
//! query string is exactly what the devices page would put in the URL — a
//! saved view with a page of its own.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The dimensions a report may group by. A closed enum: the variant becomes
/// a `GROUP BY` column, and request text must never reach SQL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportDimension {
    School,
    Status,
    AssetType,
    Source,
    MatchState,
}

impl ReportDimension {
    pub const ALL: &'static [ReportDimension] = &[
        ReportDimension::School,
        ReportDimension::Status,
        ReportDimension::AssetType,
        ReportDimension::Source,
        ReportDimension::MatchState,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            ReportDimension::School => "school",
            ReportDimension::Status => "status",
            ReportDimension::AssetType => "asset_type",
            ReportDimension::Source => "source",
            ReportDimension::MatchState => "match_state",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|d| d.as_str() == s)
    }

    /// The whitelisted SQL column this dimension groups on.
    pub fn sql_column(&self) -> &'static str {
        match self {
            ReportDimension::School => "school_org_sourced_id",
            ReportDimension::Status => "status",
            ReportDimension::AssetType => "asset_type",
            ReportDimension::Source => "source",
            ReportDimension::MatchState => "match_state",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            ReportDimension::School => "School",
            ReportDimension::Status => "Status",
            ReportDimension::AssetType => "Type",
            ReportDimension::Source => "Source",
            ReportDimension::MatchState => "Assignment state",
        }
    }
}

/// A saved report definition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssetReport {
    /// UUID.
    pub id: String,
    pub name: String,
    /// The devices page's own filter query string (may be empty = everything).
    pub query: String,
    pub group_by: ReportDimension,
    pub actor: String,
    pub created_at: DateTime<Utc>,
}

/// One row of a run report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportBucket {
    /// The group value as stored; `None` is a real bucket (e.g. no school).
    pub group_value: Option<String>,
    pub count: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dimensions_round_trip_and_junk_is_refused() {
        for d in ReportDimension::ALL {
            assert_eq!(ReportDimension::parse(d.as_str()), Some(*d));
        }
        assert_eq!(ReportDimension::parse("password"), None);
    }
}
