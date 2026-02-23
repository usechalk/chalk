//! Webhook scoping engine for filtering entity changes.
//!
//! Applies [`WebhookScoping`] filters to a set of [`EntityChange`] records,
//! producing only the changes relevant to a given webhook endpoint.

use super::models::{EntityChange, EntityType, WebhookScoping};

/// Apply scoping filters to a set of entity changes.
///
/// Returns a new `Vec` containing only the changes that pass all configured
/// filters. Empty filter fields are treated as "allow all".
///
/// Filters are applied in order:
/// 1. Entity type filter
/// 2. Org filter (checks `orgs` for Users, `school` for Classes/Enrollments)
/// 3. Role filter (checks `role` for Users and Enrollments)
/// 4. Field exclusions (removes specified dot-path fields from the entity JSON)
pub fn apply_scoping(scoping: &WebhookScoping, changes: &[EntityChange]) -> Vec<EntityChange> {
    changes
        .iter()
        .filter(|c| matches_entity_type(scoping, c))
        .filter(|c| matches_org(scoping, c))
        .filter(|c| matches_role(scoping, c))
        .cloned()
        .map(|mut c| {
            apply_field_exclusions(scoping, &mut c);
            c
        })
        .collect()
}

/// Check if the change's entity type is in the allowed set.
/// Empty means all types are allowed.
fn matches_entity_type(scoping: &WebhookScoping, change: &EntityChange) -> bool {
    scoping.entity_types.is_empty() || scoping.entity_types.contains(&change.entity_type)
}

/// Check if the change is associated with an allowed org.
/// Empty means all orgs are allowed.
///
/// Org association is determined by entity type:
/// - **User**: `orgs` array in the entity JSON
/// - **Class** / **Enrollment**: `school` field in the entity JSON
/// - **Org**: `sourcedId` field (the org itself)
/// - All other types: always pass (no org association)
fn matches_org(scoping: &WebhookScoping, change: &EntityChange) -> bool {
    if scoping.org_sourced_ids.is_empty() {
        return true;
    }

    match change.entity_type {
        EntityType::User => {
            // Users have an "orgs" array of sourced IDs
            if let Some(orgs) = change.entity.get("orgs").and_then(|v| v.as_array()) {
                orgs.iter().any(|o| {
                    o.as_str()
                        .map(|s| scoping.org_sourced_ids.contains(&s.to_string()))
                        .unwrap_or(false)
                })
            } else {
                false
            }
        }
        EntityType::Class | EntityType::Enrollment => {
            // Classes and Enrollments have a "school" field
            if let Some(school) = change.entity.get("school").and_then(|v| v.as_str()) {
                scoping.org_sourced_ids.contains(&school.to_string())
            } else {
                false
            }
        }
        EntityType::Org => {
            // For Org entities, check if their own sourcedId is in the list
            if let Some(sid) = change.entity.get("sourcedId").and_then(|v| v.as_str()) {
                scoping.org_sourced_ids.contains(&sid.to_string())
            } else {
                // Fall back to the change's sourced_id
                scoping.org_sourced_ids.contains(&change.sourced_id)
            }
        }
        // Other entity types (AcademicSession, Course, Demographics) have no
        // direct org association, so they always pass the org filter.
        _ => true,
    }
}

/// Check if the change matches the allowed roles.
/// Empty means all roles are allowed.
///
/// Role is only relevant for Users and Enrollments.
fn matches_role(scoping: &WebhookScoping, change: &EntityChange) -> bool {
    if scoping.roles.is_empty() {
        return true;
    }

    match change.entity_type {
        EntityType::User | EntityType::Enrollment => {
            if let Some(role) = change.entity.get("role").and_then(|v| v.as_str()) {
                scoping.roles.contains(&role.to_string())
            } else {
                false
            }
        }
        // Other entity types have no role concept
        _ => true,
    }
}

/// Remove excluded fields from the entity JSON using dot-path notation.
///
/// For example, `"demographics.birthDate"` removes the `birthDate` key from
/// the nested `demographics` object.
fn apply_field_exclusions(scoping: &WebhookScoping, change: &mut EntityChange) {
    for path in &scoping.excluded_fields {
        remove_field_by_path(&mut change.entity, path);
    }
}

/// Remove a field from a JSON value using dot-path notation.
///
/// Given path `"a.b.c"`, navigates into `value["a"]["b"]` and removes key `"c"`.
fn remove_field_by_path(value: &mut serde_json::Value, path: &str) {
    let parts: Vec<&str> = path.split('.').collect();
    if parts.is_empty() {
        return;
    }

    if parts.len() == 1 {
        // Top-level field removal
        if let Some(obj) = value.as_object_mut() {
            obj.remove(parts[0]);
        }
        return;
    }

    // Navigate to the parent object
    let mut current = value;
    for &part in &parts[..parts.len() - 1] {
        match current.get_mut(part) {
            Some(next) => current = next,
            None => return, // Path doesn't exist, nothing to remove
        }
    }

    // Remove the final key
    if let Some(obj) = current.as_object_mut() {
        obj.remove(parts[parts.len() - 1]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webhooks::models::ChangeAction;

    fn make_user_change(sourced_id: &str, role: &str, orgs: Vec<&str>) -> EntityChange {
        EntityChange {
            entity_type: EntityType::User,
            action: ChangeAction::Created,
            sourced_id: sourced_id.to_string(),
            entity: serde_json::json!({
                "sourcedId": sourced_id,
                "role": role,
                "orgs": orgs,
                "givenName": "Test",
                "familyName": "User",
            }),
        }
    }

    fn make_enrollment_change(sourced_id: &str, role: &str, school: &str) -> EntityChange {
        EntityChange {
            entity_type: EntityType::Enrollment,
            action: ChangeAction::Created,
            sourced_id: sourced_id.to_string(),
            entity: serde_json::json!({
                "sourcedId": sourced_id,
                "role": role,
                "school": school,
                "user": "user-1",
                "class": "class-1",
            }),
        }
    }

    fn make_class_change(sourced_id: &str, school: &str) -> EntityChange {
        EntityChange {
            entity_type: EntityType::Class,
            action: ChangeAction::Updated,
            sourced_id: sourced_id.to_string(),
            entity: serde_json::json!({
                "sourcedId": sourced_id,
                "school": school,
                "title": "Math 101",
            }),
        }
    }

    fn make_org_change(sourced_id: &str) -> EntityChange {
        EntityChange {
            entity_type: EntityType::Org,
            action: ChangeAction::Created,
            sourced_id: sourced_id.to_string(),
            entity: serde_json::json!({
                "sourcedId": sourced_id,
                "name": "Test Org",
            }),
        }
    }

    fn make_course_change(sourced_id: &str) -> EntityChange {
        EntityChange {
            entity_type: EntityType::Course,
            action: ChangeAction::Created,
            sourced_id: sourced_id.to_string(),
            entity: serde_json::json!({
                "sourcedId": sourced_id,
                "title": "Algebra I",
            }),
        }
    }

    // --- Entity type filtering ---

    #[test]
    fn empty_scoping_passes_everything_through() {
        let scoping = WebhookScoping::default();
        let changes = vec![
            make_user_change("u1", "student", vec!["org-1"]),
            make_enrollment_change("e1", "student", "org-1"),
            make_class_change("c1", "org-1"),
            make_org_change("org-1"),
            make_course_change("crs-1"),
        ];
        let result = apply_scoping(&scoping, &changes);
        assert_eq!(result.len(), 5);
    }

    #[test]
    fn entity_type_filter_includes_only_specified_types() {
        let scoping = WebhookScoping {
            entity_types: vec![EntityType::User, EntityType::Enrollment],
            ..WebhookScoping::default()
        };
        let changes = vec![
            make_user_change("u1", "student", vec!["org-1"]),
            make_enrollment_change("e1", "student", "org-1"),
            make_class_change("c1", "org-1"),
            make_org_change("org-1"),
        ];
        let result = apply_scoping(&scoping, &changes);
        assert_eq!(result.len(), 2);
        assert!(result
            .iter()
            .all(|c| c.entity_type == EntityType::User || c.entity_type == EntityType::Enrollment));
    }

    #[test]
    fn entity_type_filter_excludes_all_when_no_match() {
        let scoping = WebhookScoping {
            entity_types: vec![EntityType::Demographics],
            ..WebhookScoping::default()
        };
        let changes = vec![
            make_user_change("u1", "student", vec!["org-1"]),
            make_class_change("c1", "org-1"),
        ];
        let result = apply_scoping(&scoping, &changes);
        assert!(result.is_empty());
    }

    // --- Role filtering ---

    #[test]
    fn role_filter_includes_matching_users() {
        let scoping = WebhookScoping {
            roles: vec!["student".to_string()],
            ..WebhookScoping::default()
        };
        let changes = vec![
            make_user_change("u1", "student", vec!["org-1"]),
            make_user_change("u2", "teacher", vec!["org-1"]),
        ];
        let result = apply_scoping(&scoping, &changes);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].sourced_id, "u1");
    }

    #[test]
    fn role_filter_includes_matching_enrollments() {
        let scoping = WebhookScoping {
            roles: vec!["teacher".to_string()],
            ..WebhookScoping::default()
        };
        let changes = vec![
            make_enrollment_change("e1", "student", "org-1"),
            make_enrollment_change("e2", "teacher", "org-1"),
        ];
        let result = apply_scoping(&scoping, &changes);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].sourced_id, "e2");
    }

    #[test]
    fn role_filter_does_not_affect_non_role_entities() {
        let scoping = WebhookScoping {
            roles: vec!["student".to_string()],
            ..WebhookScoping::default()
        };
        let changes = vec![
            make_class_change("c1", "org-1"),
            make_org_change("org-1"),
            make_course_change("crs-1"),
        ];
        let result = apply_scoping(&scoping, &changes);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn role_filter_multiple_roles() {
        let scoping = WebhookScoping {
            roles: vec!["student".to_string(), "teacher".to_string()],
            ..WebhookScoping::default()
        };
        let changes = vec![
            make_user_change("u1", "student", vec!["org-1"]),
            make_user_change("u2", "teacher", vec!["org-1"]),
            make_user_change("u3", "administrator", vec!["org-1"]),
        ];
        let result = apply_scoping(&scoping, &changes);
        assert_eq!(result.len(), 2);
    }

    // --- Org filtering ---

    #[test]
    fn org_filter_includes_matching_user_orgs() {
        let scoping = WebhookScoping {
            org_sourced_ids: vec!["org-1".to_string()],
            ..WebhookScoping::default()
        };
        let changes = vec![
            make_user_change("u1", "student", vec!["org-1"]),
            make_user_change("u2", "student", vec!["org-2"]),
            make_user_change("u3", "student", vec!["org-1", "org-2"]),
        ];
        let result = apply_scoping(&scoping, &changes);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].sourced_id, "u1");
        assert_eq!(result[1].sourced_id, "u3");
    }

    #[test]
    fn org_filter_includes_matching_class_school() {
        let scoping = WebhookScoping {
            org_sourced_ids: vec!["org-1".to_string()],
            ..WebhookScoping::default()
        };
        let changes = vec![
            make_class_change("c1", "org-1"),
            make_class_change("c2", "org-2"),
        ];
        let result = apply_scoping(&scoping, &changes);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].sourced_id, "c1");
    }

    #[test]
    fn org_filter_includes_matching_enrollment_school() {
        let scoping = WebhookScoping {
            org_sourced_ids: vec!["org-1".to_string()],
            ..WebhookScoping::default()
        };
        let changes = vec![
            make_enrollment_change("e1", "student", "org-1"),
            make_enrollment_change("e2", "student", "org-2"),
        ];
        let result = apply_scoping(&scoping, &changes);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].sourced_id, "e1");
    }

    #[test]
    fn org_filter_matches_org_entity_by_sourced_id() {
        let scoping = WebhookScoping {
            org_sourced_ids: vec!["org-1".to_string()],
            ..WebhookScoping::default()
        };
        let changes = vec![make_org_change("org-1"), make_org_change("org-2")];
        let result = apply_scoping(&scoping, &changes);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].sourced_id, "org-1");
    }

    #[test]
    fn org_filter_does_not_affect_course_or_session() {
        let scoping = WebhookScoping {
            org_sourced_ids: vec!["org-1".to_string()],
            ..WebhookScoping::default()
        };
        let changes = vec![make_course_change("crs-1")];
        let result = apply_scoping(&scoping, &changes);
        assert_eq!(result.len(), 1);
    }

    // --- Field exclusions ---

    #[test]
    fn field_exclusion_removes_top_level_field() {
        let scoping = WebhookScoping {
            excluded_fields: vec!["givenName".to_string()],
            ..WebhookScoping::default()
        };
        let changes = vec![make_user_change("u1", "student", vec!["org-1"])];
        let result = apply_scoping(&scoping, &changes);
        assert_eq!(result.len(), 1);
        assert!(result[0].entity.get("givenName").is_none());
        // Other fields should still be present
        assert!(result[0].entity.get("familyName").is_some());
    }

    #[test]
    fn field_exclusion_removes_nested_field() {
        let scoping = WebhookScoping {
            excluded_fields: vec!["demographics.birthDate".to_string()],
            ..WebhookScoping::default()
        };
        let change = EntityChange {
            entity_type: EntityType::User,
            action: ChangeAction::Created,
            sourced_id: "u1".to_string(),
            entity: serde_json::json!({
                "sourcedId": "u1",
                "demographics": {
                    "birthDate": "2005-01-15",
                    "sex": "male"
                }
            }),
        };
        let result = apply_scoping(&scoping, &[change]);
        assert_eq!(result.len(), 1);
        let demo = result[0].entity.get("demographics").unwrap();
        assert!(demo.get("birthDate").is_none());
        assert!(demo.get("sex").is_some());
    }

    #[test]
    fn field_exclusion_ignores_nonexistent_path() {
        let scoping = WebhookScoping {
            excluded_fields: vec!["nonexistent.field".to_string()],
            ..WebhookScoping::default()
        };
        let changes = vec![make_user_change("u1", "student", vec!["org-1"])];
        let result = apply_scoping(&scoping, &changes);
        assert_eq!(result.len(), 1);
        // Original entity should be unchanged
        assert_eq!(result[0].entity.get("givenName").unwrap(), "Test");
    }

    #[test]
    fn field_exclusion_multiple_fields() {
        let scoping = WebhookScoping {
            excluded_fields: vec!["givenName".to_string(), "familyName".to_string()],
            ..WebhookScoping::default()
        };
        let changes = vec![make_user_change("u1", "student", vec!["org-1"])];
        let result = apply_scoping(&scoping, &changes);
        assert_eq!(result.len(), 1);
        assert!(result[0].entity.get("givenName").is_none());
        assert!(result[0].entity.get("familyName").is_none());
        assert!(result[0].entity.get("role").is_some());
    }

    // --- Combined filters ---

    #[test]
    fn combined_entity_type_and_role_filter() {
        let scoping = WebhookScoping {
            entity_types: vec![EntityType::User],
            roles: vec!["student".to_string()],
            ..WebhookScoping::default()
        };
        let changes = vec![
            make_user_change("u1", "student", vec!["org-1"]),
            make_user_change("u2", "teacher", vec!["org-1"]),
            make_enrollment_change("e1", "student", "org-1"),
            make_class_change("c1", "org-1"),
        ];
        let result = apply_scoping(&scoping, &changes);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].sourced_id, "u1");
    }

    #[test]
    fn combined_org_and_role_filter() {
        let scoping = WebhookScoping {
            org_sourced_ids: vec!["org-1".to_string()],
            roles: vec!["student".to_string()],
            ..WebhookScoping::default()
        };
        let changes = vec![
            make_user_change("u1", "student", vec!["org-1"]),
            make_user_change("u2", "student", vec!["org-2"]),
            make_user_change("u3", "teacher", vec!["org-1"]),
        ];
        let result = apply_scoping(&scoping, &changes);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].sourced_id, "u1");
    }

    #[test]
    fn all_filters_combined() {
        let scoping = WebhookScoping {
            entity_types: vec![EntityType::User],
            org_sourced_ids: vec!["org-1".to_string()],
            roles: vec!["student".to_string()],
            excluded_fields: vec!["givenName".to_string()],
        };
        let changes = vec![
            make_user_change("u1", "student", vec!["org-1"]),
            make_user_change("u2", "teacher", vec!["org-1"]),
            make_user_change("u3", "student", vec!["org-2"]),
            make_class_change("c1", "org-1"),
        ];
        let result = apply_scoping(&scoping, &changes);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].sourced_id, "u1");
        assert!(result[0].entity.get("givenName").is_none());
    }

    #[test]
    fn empty_changes_returns_empty() {
        let scoping = WebhookScoping {
            entity_types: vec![EntityType::User],
            ..WebhookScoping::default()
        };
        let result = apply_scoping(&scoping, &[]);
        assert!(result.is_empty());
    }

    #[test]
    fn does_not_mutate_original_changes() {
        let scoping = WebhookScoping {
            excluded_fields: vec!["givenName".to_string()],
            ..WebhookScoping::default()
        };
        let changes = vec![make_user_change("u1", "student", vec!["org-1"])];
        let _result = apply_scoping(&scoping, &changes);
        // Original should still have the field
        assert!(changes[0].entity.get("givenName").is_some());
    }
}
