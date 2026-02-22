//! Changeset building utilities for webhook events.
//!
//! Provides helpers to construct [`EntityChange`] records from OneRoster
//! model types by serializing them to `serde_json::Value`.

use serde::Serialize;

use crate::error::{ChalkError, Result};

use super::models::{ChangeAction, EntityChange, EntityType, SyncChangeset};

/// Build an [`EntityChange`] from any serializable OneRoster model.
///
/// The `sourced_id` is extracted separately because the entity is serialized
/// to a generic `serde_json::Value`.
pub fn build_entity_change<T: Serialize>(
    entity_type: EntityType,
    action: ChangeAction,
    sourced_id: &str,
    entity: &T,
) -> Result<EntityChange> {
    let value = serde_json::to_value(entity)
        .map_err(|e| ChalkError::Webhook(format!("failed to serialize entity: {e}")))?;

    Ok(EntityChange {
        entity_type,
        action,
        sourced_id: sourced_id.to_string(),
        entity: value,
    })
}

/// Builder for constructing a [`SyncChangeset`] incrementally.
pub struct ChangesetBuilder {
    changes: Vec<EntityChange>,
    sync_run_id: i64,
}

impl ChangesetBuilder {
    /// Create a new builder for the given sync run.
    pub fn new(sync_run_id: i64) -> Self {
        Self {
            changes: Vec::new(),
            sync_run_id,
        }
    }

    /// Add an entity change from a serializable model.
    pub fn add_change<T: Serialize>(
        &mut self,
        entity_type: EntityType,
        action: ChangeAction,
        sourced_id: &str,
        entity: &T,
    ) -> Result<&mut Self> {
        let change = build_entity_change(entity_type, action, sourced_id, entity)?;
        self.changes.push(change);
        Ok(self)
    }

    /// Add a pre-built [`EntityChange`].
    pub fn add_raw_change(&mut self, change: EntityChange) -> &mut Self {
        self.changes.push(change);
        self
    }

    /// Return the number of changes accumulated so far.
    pub fn len(&self) -> usize {
        self.changes.len()
    }

    /// Return whether the builder has no changes.
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// Consume the builder and produce a [`SyncChangeset`].
    pub fn build(self) -> SyncChangeset {
        SyncChangeset {
            changes: self.changes,
            sync_run_id: self.sync_run_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::common::{RoleType, Status};
    use crate::models::user::{User, UserIdentifier};
    use crate::models::org::Org;
    use crate::models::common::OrgType;
    use chrono::{TimeZone, Utc};

    fn sample_user() -> User {
        User {
            sourced_id: "user-001".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            username: "jdoe".to_string(),
            user_ids: vec![UserIdentifier {
                type_: "LDAP".to_string(),
                identifier: "jdoe@example.com".to_string(),
            }],
            enabled_user: true,
            given_name: "John".to_string(),
            family_name: "Doe".to_string(),
            middle_name: None,
            role: RoleType::Student,
            identifier: None,
            email: Some("jdoe@example.com".to_string()),
            sms: None,
            phone: None,
            agents: vec![],
            orgs: vec!["org-001".to_string()],
            grades: vec!["09".to_string()],
        }
    }

    fn sample_org() -> Org {
        Org {
            sourced_id: "org-001".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            name: "Springfield School District".to_string(),
            org_type: OrgType::District,
            identifier: None,
            parent: None,
            children: vec![],
        }
    }

    #[test]
    fn build_entity_change_from_user() {
        let user = sample_user();
        let change = build_entity_change(
            EntityType::User,
            ChangeAction::Created,
            &user.sourced_id,
            &user,
        )
        .unwrap();

        assert_eq!(change.entity_type, EntityType::User);
        assert_eq!(change.action, ChangeAction::Created);
        assert_eq!(change.sourced_id, "user-001");
        assert_eq!(change.entity["givenName"], "John");
        assert_eq!(change.entity["familyName"], "Doe");
        assert_eq!(change.entity["role"], "student");
    }

    #[test]
    fn build_entity_change_from_org() {
        let org = sample_org();
        let change = build_entity_change(
            EntityType::Org,
            ChangeAction::Created,
            &org.sourced_id,
            &org,
        )
        .unwrap();

        assert_eq!(change.entity_type, EntityType::Org);
        assert_eq!(change.sourced_id, "org-001");
        assert_eq!(change.entity["name"], "Springfield School District");
    }

    #[test]
    fn changeset_builder_accumulates_changes() {
        let user = sample_user();
        let org = sample_org();

        let mut builder = ChangesetBuilder::new(42);
        builder
            .add_change(
                EntityType::User,
                ChangeAction::Created,
                &user.sourced_id,
                &user,
            )
            .unwrap();
        builder
            .add_change(
                EntityType::Org,
                ChangeAction::Created,
                &org.sourced_id,
                &org,
            )
            .unwrap();

        assert_eq!(builder.len(), 2);
        assert!(!builder.is_empty());

        let changeset = builder.build();
        assert_eq!(changeset.sync_run_id, 42);
        assert_eq!(changeset.changes.len(), 2);
        assert_eq!(changeset.changes[0].entity_type, EntityType::User);
        assert_eq!(changeset.changes[1].entity_type, EntityType::Org);
    }

    #[test]
    fn changeset_builder_empty() {
        let builder = ChangesetBuilder::new(1);
        assert!(builder.is_empty());
        assert_eq!(builder.len(), 0);

        let changeset = builder.build();
        assert!(changeset.changes.is_empty());
        assert_eq!(changeset.sync_run_id, 1);
    }

    #[test]
    fn changeset_builder_add_raw_change() {
        let mut builder = ChangesetBuilder::new(10);
        let change = EntityChange {
            entity_type: EntityType::Course,
            action: ChangeAction::Deleted,
            sourced_id: "crs-1".to_string(),
            entity: serde_json::json!({"title": "Algebra I"}),
        };
        builder.add_raw_change(change);

        let changeset = builder.build();
        assert_eq!(changeset.changes.len(), 1);
        assert_eq!(changeset.changes[0].action, ChangeAction::Deleted);
    }

    #[test]
    fn build_entity_change_preserves_camel_case() {
        let user = sample_user();
        let change = build_entity_change(
            EntityType::User,
            ChangeAction::Updated,
            &user.sourced_id,
            &user,
        )
        .unwrap();

        // OneRoster models use camelCase serialization
        assert!(change.entity.get("sourcedId").is_some());
        assert!(change.entity.get("givenName").is_some());
        assert!(change.entity.get("familyName").is_some());
        assert!(change.entity.get("dateLastModified").is_some());
    }

    #[test]
    fn build_entity_change_includes_orgs_array() {
        let user = sample_user();
        let change = build_entity_change(
            EntityType::User,
            ChangeAction::Created,
            &user.sourced_id,
            &user,
        )
        .unwrap();

        let orgs = change.entity.get("orgs").unwrap().as_array().unwrap();
        assert_eq!(orgs.len(), 1);
        assert_eq!(orgs[0], "org-001");
    }

    #[test]
    fn changeset_builder_mixed_actions() {
        let user = sample_user();
        let mut builder = ChangesetBuilder::new(99);

        builder
            .add_change(
                EntityType::User,
                ChangeAction::Created,
                &user.sourced_id,
                &user,
            )
            .unwrap();
        builder
            .add_change(
                EntityType::User,
                ChangeAction::Updated,
                &user.sourced_id,
                &user,
            )
            .unwrap();
        builder.add_raw_change(EntityChange {
            entity_type: EntityType::User,
            action: ChangeAction::Deleted,
            sourced_id: "user-002".to_string(),
            entity: serde_json::json!({"sourcedId": "user-002"}),
        });

        let changeset = builder.build();
        assert_eq!(changeset.changes.len(), 3);
        assert_eq!(changeset.changes[0].action, ChangeAction::Created);
        assert_eq!(changeset.changes[1].action, ChangeAction::Updated);
        assert_eq!(changeset.changes[2].action, ChangeAction::Deleted);
    }
}
