//! Organizational Unit path resolution for Active Directory.

/// Escape special characters in an LDAP DN component value.
///
/// Characters `,`, `+`, `"`, `\`, `<`, `>`, and `;` are escaped with a backslash
/// per RFC 4514 to prevent DN injection or malformed distinguished names.
pub fn escape_dn_value(val: &str) -> String {
    val.replace('\\', "\\\\")
        .replace(',', "\\,")
        .replace('+', "\\+")
        .replace('"', "\\\"")
        .replace('<', "\\<")
        .replace('>', "\\>")
        .replace(';', "\\;")
}

/// Resolve an OU path template by replacing `{school}` and `{grade}` placeholders.
///
/// Templates like `/Students/{school}/{grade}` become `/Students/Lincoln HS/09`.
/// Placeholder values are DN-escaped before substitution.
pub fn resolve_ou_path(template: &str, school_name: &str, grade: &str) -> String {
    template
        .replace("{school}", &escape_dn_value(school_name))
        .replace("{grade}", &escape_dn_value(grade))
}

/// Convert a slash-delimited OU path to a proper AD Distinguished Name.
///
/// For example, `/Students/Lincoln HS/09` with base DN `DC=example,DC=com`
/// becomes `OU=09,OU=Lincoln HS,OU=Students,DC=example,DC=com`.
///
/// OU component values are DN-escaped to handle special characters.
pub fn template_to_dn(ou_path: &str, base_dn: &str) -> String {
    let parts: Vec<&str> = ou_path.split('/').filter(|p| !p.is_empty()).collect();

    if parts.is_empty() {
        return base_dn.to_string();
    }

    // AD DNs are leaf-first, so reverse the path components
    let ou_components: Vec<String> = parts
        .iter()
        .rev()
        .map(|p| format!("OU={}", escape_dn_value(p)))
        .collect();
    format!("{},{}", ou_components.join(","), base_dn)
}

/// Build a user's full DN from their common name and OU DN.
///
/// The CN value is DN-escaped to handle special characters in names.
pub fn user_dn(cn: &str, ou_dn: &str) -> String {
    format!("CN={},{ou_dn}", escape_dn_value(cn))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_template_with_school_and_grade() {
        let result = resolve_ou_path("/Students/{school}/{grade}", "Lincoln HS", "09");
        assert_eq!(result, "/Students/Lincoln HS/09");
    }

    #[test]
    fn resolve_template_school_only() {
        let result = resolve_ou_path("/Teachers/{school}", "Lincoln HS", "");
        assert_eq!(result, "/Teachers/Lincoln HS");
    }

    #[test]
    fn resolve_template_no_placeholders() {
        let result = resolve_ou_path("/Staff", "Lincoln HS", "09");
        assert_eq!(result, "/Staff");
    }

    #[test]
    fn resolve_template_multiple_occurrences() {
        let result = resolve_ou_path("/{school}/{school}", "Test", "09");
        assert_eq!(result, "/Test/Test");
    }

    #[test]
    fn template_to_dn_single_level() {
        let dn = template_to_dn("/Students", "DC=example,DC=com");
        assert_eq!(dn, "OU=Students,DC=example,DC=com");
    }

    #[test]
    fn template_to_dn_multi_level() {
        let dn = template_to_dn("/Students/Lincoln HS/09", "DC=example,DC=com");
        assert_eq!(dn, "OU=09,OU=Lincoln HS,OU=Students,DC=example,DC=com");
    }

    #[test]
    fn template_to_dn_empty_path() {
        let dn = template_to_dn("", "DC=example,DC=com");
        assert_eq!(dn, "DC=example,DC=com");
    }

    #[test]
    fn template_to_dn_just_slash() {
        let dn = template_to_dn("/", "DC=example,DC=com");
        assert_eq!(dn, "DC=example,DC=com");
    }

    #[test]
    fn user_dn_basic() {
        let dn = user_dn("John Doe", "OU=Students,DC=example,DC=com");
        assert_eq!(dn, "CN=John Doe,OU=Students,DC=example,DC=com");
    }

    #[test]
    fn user_dn_deep_ou() {
        let dn = user_dn(
            "Jane Smith",
            "OU=09,OU=Lincoln HS,OU=Students,DC=example,DC=com",
        );
        assert_eq!(
            dn,
            "CN=Jane Smith,OU=09,OU=Lincoln HS,OU=Students,DC=example,DC=com"
        );
    }

    // --- DN escaping tests ---

    #[test]
    fn escape_dn_value_no_special_chars() {
        assert_eq!(escape_dn_value("Lincoln HS"), "Lincoln HS");
    }

    #[test]
    fn escape_dn_value_comma() {
        assert_eq!(escape_dn_value("Smith, Jr."), "Smith\\, Jr.");
    }

    #[test]
    fn escape_dn_value_plus() {
        assert_eq!(escape_dn_value("A+B"), "A\\+B");
    }

    #[test]
    fn escape_dn_value_double_quote() {
        assert_eq!(escape_dn_value(r#"He said "hi""#), r#"He said \"hi\""#);
    }

    #[test]
    fn escape_dn_value_backslash() {
        assert_eq!(escape_dn_value(r"path\to"), r"path\\to");
    }

    #[test]
    fn escape_dn_value_angle_brackets() {
        assert_eq!(escape_dn_value("<admin>"), "\\<admin\\>");
    }

    #[test]
    fn escape_dn_value_semicolon() {
        assert_eq!(escape_dn_value("a;b"), "a\\;b");
    }

    #[test]
    fn escape_dn_value_multiple_special() {
        assert_eq!(escape_dn_value("a,b+c"), "a\\,b\\+c");
    }

    #[test]
    fn resolve_ou_path_escapes_school_with_comma() {
        let result = resolve_ou_path("/Students/{school}/{grade}", "Lincoln, HS", "09");
        assert_eq!(result, "/Students/Lincoln\\, HS/09");
    }

    #[test]
    fn template_to_dn_escapes_special_chars() {
        let dn = template_to_dn("/Students/Lincoln, HS", "DC=example,DC=com");
        assert_eq!(dn, "OU=Lincoln\\, HS,OU=Students,DC=example,DC=com");
    }

    #[test]
    fn user_dn_escapes_cn_with_comma() {
        let dn = user_dn("Doe, John Jr.", "OU=Students,DC=example,DC=com");
        assert_eq!(dn, "CN=Doe\\, John Jr.,OU=Students,DC=example,DC=com");
    }
}
