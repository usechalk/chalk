//! DTO structs for LDAP operations (not the DB models -- those live in chalk-core).

/// Attributes for an AD user account.
#[derive(Debug, Clone)]
pub struct AdUserAttrs {
    pub dn: String,
    pub sam_account_name: String,
    pub upn: Option<String>,
    pub display_name: String,
    pub given_name: String,
    pub surname: String,
    pub email: Option<String>,
    pub ou: String,
    /// userAccountControl flags (e.g. 512 = normal, 514 = disabled).
    pub user_account_control: u32,
}

/// Attributes for an AD Organizational Unit.
#[derive(Debug, Clone)]
pub struct AdOuAttrs {
    pub dn: String,
    pub name: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ad_user_attrs_debug() {
        let attrs = AdUserAttrs {
            dn: "CN=John Doe,OU=Students,DC=example,DC=com".to_string(),
            sam_account_name: "jdoe".to_string(),
            upn: Some("jdoe@example.com".to_string()),
            display_name: "John Doe".to_string(),
            given_name: "John".to_string(),
            surname: "Doe".to_string(),
            email: Some("jdoe@example.com".to_string()),
            ou: "OU=Students,DC=example,DC=com".to_string(),
            user_account_control: 512,
        };
        let debug = format!("{:?}", attrs);
        assert!(debug.contains("jdoe"));
        assert!(debug.contains("512"));
    }

    #[test]
    fn ad_user_attrs_clone() {
        let attrs = AdUserAttrs {
            dn: "CN=Test,OU=Users,DC=test,DC=com".to_string(),
            sam_account_name: "test".to_string(),
            upn: None,
            display_name: "Test User".to_string(),
            given_name: "Test".to_string(),
            surname: "User".to_string(),
            email: None,
            ou: "OU=Users,DC=test,DC=com".to_string(),
            user_account_control: 514,
        };
        let cloned = attrs.clone();
        assert_eq!(cloned.dn, attrs.dn);
        assert_eq!(cloned.sam_account_name, attrs.sam_account_name);
        assert_eq!(cloned.user_account_control, attrs.user_account_control);
    }

    #[test]
    fn ad_ou_attrs_debug() {
        let ou = AdOuAttrs {
            dn: "OU=Students,DC=example,DC=com".to_string(),
            name: "Students".to_string(),
        };
        let debug = format!("{:?}", ou);
        assert!(debug.contains("Students"));
    }

    #[test]
    fn ad_ou_attrs_clone() {
        let ou = AdOuAttrs {
            dn: "OU=Teachers,DC=example,DC=com".to_string(),
            name: "Teachers".to_string(),
        };
        let cloned = ou.clone();
        assert_eq!(cloned.dn, ou.dn);
        assert_eq!(cloned.name, ou.name);
    }
}
