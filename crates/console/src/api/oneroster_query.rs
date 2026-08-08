//! OneRoster 1.1 list-query parameters: `filter`, `sort`, `orderBy`,
//! `fields`.
//!
//! Vendors integrating against a OneRoster endpoint send these reflexively —
//! `filter=role='student'`, `sort=familyName`, `fields=sourcedId,email` — and
//! an endpoint that silently ignores them returns *wrong* data, not just
//! unsorted data: a consumer asking for students and receiving everyone will
//! import everyone.
//!
//! Applied to the serialized JSON of each item (the camelCase shapes the API
//! actually returns), after scope redaction and before pagination, so
//! `X-Total-Count` counts what the filter matched. The grammar is the spec's:
//! predicates joined by a single `AND` or `OR` (no mixed precedence in
//! OneRoster 1.1), values single-quoted, operators `= != > >= < <= ~`.
//! A filter that does not parse is a 400, not an empty result — an integrator
//! typo'ing a field name must hear about it, not sync zero rows.

use std::cmp::Ordering;

use serde_json::Value;

/// One comparison in a filter.
#[derive(Debug, Clone, PartialEq)]
pub struct Predicate {
    pub field: String,
    pub op: FilterOp,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterOp {
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
    /// `~` — case-insensitive contains.
    Contains,
}

/// A parsed OneRoster filter: predicates under one logical operator.
#[derive(Debug, Clone, PartialEq)]
pub enum Filter {
    And(Vec<Predicate>),
    Or(Vec<Predicate>),
}

/// Parse the spec grammar. `AND`/`OR` are case-insensitive; a single
/// predicate parses as an `And` of one.
pub fn parse_filter(input: &str) -> Result<Filter, String> {
    let input = input.trim();
    if input.is_empty() {
        return Err("empty filter".to_string());
    }
    // Split on the logical operator outside quotes. OneRoster 1.1 allows one
    // kind per filter, so finding both is an error.
    let parts_and = split_logical(input, " and ");
    let parts_or = split_logical(input, " or ");
    let (parts, is_or) = match (parts_and.len(), parts_or.len()) {
        (a, o) if a > 1 && o > 1 => {
            return Err("a OneRoster 1.1 filter uses either AND or OR, not both".to_string())
        }
        (a, _) if a > 1 => (parts_and, false),
        (_, o) if o > 1 => (parts_or, true),
        _ => (vec![input.to_string()], false),
    };
    let predicates = parts
        .iter()
        .map(|p| parse_predicate(p))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(if is_or {
        Filter::Or(predicates)
    } else {
        Filter::And(predicates)
    })
}

/// Split on a logical keyword, case-insensitively, outside single quotes.
fn split_logical(input: &str, keyword: &str) -> Vec<String> {
    let lower = input.to_lowercase();
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    let kw_len = keyword.len();
    let bytes = lower.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\'' {
            in_quotes = !in_quotes;
            i += 1;
            continue;
        }
        if !in_quotes && i + kw_len <= bytes.len() && &lower[i..i + kw_len] == keyword {
            parts.push(input[start..i].trim().to_string());
            start = i + kw_len;
            i += kw_len;
            continue;
        }
        i += 1;
    }
    parts.push(input[start..].trim().to_string());
    parts
}

fn parse_predicate(input: &str) -> Result<Predicate, String> {
    let input = input.trim();
    // Two-char operators first so `>=` does not parse as `>` + `=…`.
    for (symbol, op) in [
        ("!=", FilterOp::Ne),
        (">=", FilterOp::Ge),
        ("<=", FilterOp::Le),
        ("=", FilterOp::Eq),
        (">", FilterOp::Gt),
        ("<", FilterOp::Lt),
        ("~", FilterOp::Contains),
    ] {
        if let Some(idx) = find_outside_quotes(input, symbol) {
            let field = input[..idx].trim();
            let raw = input[idx + symbol.len()..].trim();
            // A field is a dotted identifier; anything else (say, a stray
            // logical keyword) is a malformed filter, not a field name.
            if field.is_empty()
                || !field
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
            {
                return Err(format!("filter predicate {input:?} has no valid field"));
            }
            let value = match (raw.starts_with('\''), raw.len() >= 2 && raw.ends_with('\'')) {
                (true, true) => &raw[1..raw.len() - 1],
                // A quote that opens must close — a dangling keyword after
                // the closing quote means the filter is malformed.
                (true, false) | (false, true) => {
                    return Err(format!("filter predicate {input:?} has unbalanced quotes"))
                }
                (false, false) => raw,
            };
            if value.is_empty() && !raw.starts_with('\'') {
                return Err(format!("filter predicate {input:?} has no value"));
            }
            return Ok(Predicate {
                field: field.to_string(),
                op,
                value: value.to_string(),
            });
        }
    }
    Err(format!(
        "filter predicate {input:?} has no operator (= != > >= < <= ~)"
    ))
}

fn find_outside_quotes(input: &str, symbol: &str) -> Option<usize> {
    let bytes = input.as_bytes();
    let mut in_quotes = false;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\'' {
            in_quotes = !in_quotes;
        } else if !in_quotes && input[i..].starts_with(symbol) {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Look up a possibly-dotted field in the item's JSON (`metadata.grade`).
fn lookup<'a>(item: &'a Value, field: &str) -> Option<&'a Value> {
    let mut current = item;
    for part in field.split('.') {
        current = current.get(part)?;
    }
    Some(current)
}

/// Compare a JSON value against a filter string: numerically when both sides
/// are numbers, as strings otherwise (ISO dates order correctly as strings).
fn compare(actual: &Value, expected: &str) -> Option<Ordering> {
    match actual {
        Value::Number(n) => {
            let a = n.as_f64()?;
            let b: f64 = expected.parse().ok()?;
            a.partial_cmp(&b)
        }
        Value::Bool(b) => {
            let e: bool = expected.parse().ok()?;
            Some(b.cmp(&e))
        }
        Value::String(s) => Some(s.as_str().cmp(expected)),
        _ => None,
    }
}

fn predicate_matches(item: &Value, p: &Predicate) -> bool {
    let Some(actual) = lookup(item, &p.field) else {
        // A field the entity does not carry matches nothing — `!=` included,
        // because "every org, since none of them has a familyName" is never
        // what an integrator meant.
        return false;
    };
    if p.op == FilterOp::Contains {
        return match actual {
            Value::String(s) => s.to_lowercase().contains(&p.value.to_lowercase()),
            _ => false,
        };
    }
    let Some(ordering) = compare(actual, &p.value) else {
        return false;
    };
    match p.op {
        FilterOp::Eq => ordering == Ordering::Equal,
        FilterOp::Ne => ordering != Ordering::Equal,
        FilterOp::Gt => ordering == Ordering::Greater,
        FilterOp::Ge => ordering != Ordering::Less,
        FilterOp::Lt => ordering == Ordering::Less,
        FilterOp::Le => ordering != Ordering::Greater,
        FilterOp::Contains => unreachable!("handled above"),
    }
}

pub fn matches(item: &Value, filter: &Filter) -> bool {
    match filter {
        Filter::And(ps) => ps.iter().all(|p| predicate_matches(item, p)),
        Filter::Or(ps) => ps.iter().any(|p| predicate_matches(item, p)),
    }
}

/// Sort by one field. Items missing the field sort last either way — a
/// vendor paging through sorted output must meet every row exactly once, so
/// absent values need a stable home.
pub fn sort_items(items: &mut [Value], field: &str, descending: bool) {
    items.sort_by(|a, b| {
        let ordering = match (lookup(a, field), lookup(b, field)) {
            (Some(x), Some(y)) => json_cmp(x, y),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        };
        if descending && matches!((lookup(a, field), lookup(b, field)), (Some(_), Some(_))) {
            ordering.reverse()
        } else {
            ordering
        }
    });
}

fn json_cmp(a: &Value, b: &Value) -> Ordering {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x
            .as_f64()
            .partial_cmp(&y.as_f64())
            .unwrap_or(Ordering::Equal),
        (Value::String(x), Value::String(y)) => x.cmp(y),
        (Value::Bool(x), Value::Bool(y)) => x.cmp(y),
        _ => Ordering::Equal,
    }
}

/// Keep only the requested top-level fields. `sourcedId` is always kept —
/// a row a consumer cannot re-identify is useless, and every real-world
/// OneRoster client assumes it.
pub fn select_fields(item: &mut Value, fields: &[String]) {
    let Value::Object(map) = item else { return };
    map.retain(|k, _| k == "sourcedId" || fields.iter().any(|f| f == k));
}

/// Parse the comma-separated `fields` parameter.
pub fn parse_fields(input: &str) -> Vec<String> {
    input
        .split(',')
        .map(str::trim)
        .filter(|f| !f.is_empty())
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests;
