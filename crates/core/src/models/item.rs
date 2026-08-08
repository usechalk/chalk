//! Quantity item classes (SS-4): accessories and consumables.
//!
//! Devices are serialized — one row, one serial, one holder. Everything else
//! a district hands out is counted: chargers, hotspots, styluses, screen
//! protectors. One table, two rules: an **accessory** comes back (its holding
//! stays open until returned), a **consumable** is consumed at issue and its
//! holding is the permanent record of where stock went.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemType {
    Accessory,
    Consumable,
}

impl ItemType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ItemType::Accessory => "accessory",
            ItemType::Consumable => "consumable",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "accessory" => Some(ItemType::Accessory),
            "consumable" => Some(ItemType::Consumable),
            _ => None,
        }
    }
}

/// One counted stock line.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Item {
    /// UUID.
    pub id: String,
    pub name: String,
    pub item_type: ItemType,
    pub notes: Option<String>,
    /// Total stock the district owns, issued or not.
    pub quantity_total: i64,
    pub school_org_sourced_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// One issue of some quantity to one person.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ItemHolding {
    /// UUID.
    pub id: String,
    pub item_id: String,
    pub user_sourced_id: String,
    pub quantity: i64,
    pub issued_at: DateTime<Utc>,
    /// `None` while held. A consumable's holding never closes — consumption
    /// is permanent, and the row is the ledger of where stock went.
    pub returned_at: Option<DateTime<Utc>>,
    pub actor: String,
}

impl ItemHolding {
    pub fn open(&self) -> bool {
        self.returned_at.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn item_types_round_trip_and_junk_is_refused() {
        for t in [ItemType::Accessory, ItemType::Consumable] {
            assert_eq!(ItemType::parse(t.as_str()), Some(t));
        }
        assert_eq!(ItemType::parse("device"), None);
    }
}
