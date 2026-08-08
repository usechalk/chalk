//! Grammar and semantics tests for the OneRoster list-query layer. The
//! stakes: a filter that half-works imports the wrong students into a
//! vendor's product, so every operator and every refusal is pinned here.

use super::*;
use serde_json::json;

fn student(id: &str, family: &str, role: &str, grade: i64) -> Value {
    json!({
        "sourcedId": id,
        "familyName": family,
        "role": role,
        "grades": [grade.to_string()],
        "gradeNumber": grade,
        "status": "active",
        "email": format!("{}@school.test", family.to_lowercase()),
    })
}

#[test]
fn every_operator_means_what_the_spec_says() {
    let s = student("u-1", "Chen", "student", 5);
    for (filter, expect) in [
        ("role='student'", true),
        ("role='teacher'", false),
        ("role!='teacher'", true),
        ("gradeNumber>4", true),
        ("gradeNumber>5", false),
        ("gradeNumber>=5", true),
        ("gradeNumber<6", true),
        ("gradeNumber<=4", false),
        ("familyName~'che'", true),
        ("familyName~'xyz'", false),
    ] {
        let f = parse_filter(filter).unwrap();
        assert_eq!(matches(&s, &f), expect, "filter {filter:?}");
    }
}

#[test]
fn and_or_combine_and_never_mix() {
    let s = student("u-1", "Chen", "student", 5);
    let f = parse_filter("role='student' AND gradeNumber=5").unwrap();
    assert!(matches(&s, &f));
    let f = parse_filter("role='teacher' AND gradeNumber=5").unwrap();
    assert!(!matches(&s, &f));
    let f = parse_filter("role='teacher' OR gradeNumber=5").unwrap();
    assert!(matches(&s, &f));
    // Lowercase keywords are the same keywords.
    let f = parse_filter("role='teacher' or gradeNumber=5").unwrap();
    assert!(matches(&s, &f));
    assert!(
        parse_filter("a='1' AND b='2' OR c='3'").is_err(),
        "no mixing"
    );
}

#[test]
fn malformed_filters_are_refused_not_emptied() {
    for bad in ["", "role", "role='student' AND", "AND role='student'"] {
        assert!(parse_filter(bad).is_err(), "{bad:?} should not parse");
    }
}

#[test]
fn a_quoted_value_may_contain_the_things_the_grammar_eats() {
    // An apostrophe-free quoted AND, and an operator inside quotes.
    let f = parse_filter("familyName='van AND allen'").unwrap();
    let s = json!({"familyName": "van AND allen"});
    assert!(matches(&s, &f));
    let f = parse_filter("email~'a=b'").unwrap();
    let s = json!({"email": "xa=by"});
    assert!(matches(&s, &f));
}

#[test]
fn a_missing_field_matches_nothing_even_negated() {
    let s = student("u-1", "Chen", "student", 5);
    let f = parse_filter("nonexistent!='x'").unwrap();
    assert!(
        !matches(&s, &f),
        "absent field must not satisfy != — that selects everything"
    );
}

#[test]
fn dotted_paths_reach_into_nested_objects() {
    let s = json!({"sourcedId": "u-1", "metadata": {"homeroom": "5B"}});
    let f = parse_filter("metadata.homeroom='5B'").unwrap();
    assert!(matches(&s, &f));
}

#[test]
fn sorting_orders_and_parks_missing_values_last_both_ways() {
    let mut items = vec![
        json!({"sourcedId": "b", "familyName": "Baker"}),
        json!({"sourcedId": "x"}),
        json!({"sourcedId": "a", "familyName": "Abel"}),
    ];
    sort_items(&mut items, "familyName", false);
    let ids: Vec<_> = items.iter().map(|v| v["sourcedId"].clone()).collect();
    assert_eq!(ids, vec![json!("a"), json!("b"), json!("x")]);
    sort_items(&mut items, "familyName", true);
    let ids: Vec<_> = items.iter().map(|v| v["sourcedId"].clone()).collect();
    assert_eq!(ids, vec![json!("b"), json!("a"), json!("x")]);
}

#[test]
fn field_selection_keeps_sourced_id_always() {
    let mut s = student("u-1", "Chen", "student", 5);
    select_fields(&mut s, &parse_fields("email, role"));
    let obj = s.as_object().unwrap();
    let mut keys: Vec<_> = obj.keys().collect();
    keys.sort();
    assert_eq!(keys, vec!["email", "role", "sourcedId"]);
}
