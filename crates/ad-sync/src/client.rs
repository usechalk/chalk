//! LDAP client wrapper for Active Directory operations.

use std::collections::HashSet;

use chalk_core::config::AdConnectionConfig;
use chalk_core::error::{ChalkError, Result};
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, Mod, Scope, SearchEntry};
use tracing::{debug, info};

use crate::models::AdUserAttrs;

/// Normal active account flag.
const UAC_NORMAL_ACCOUNT: u32 = 512;
/// Disabled account flag.
const UAC_DISABLED_ACCOUNT: u32 = 514;

/// LDAP client for Active Directory operations.
pub struct AdClient {
    server: String,
    bind_dn: String,
    bind_password: String,
    base_dn: String,
    tls_verify: bool,
}

impl AdClient {
    /// Create a new AD client from connection configuration.
    pub fn new(config: &AdConnectionConfig) -> Self {
        Self {
            server: config.server.clone(),
            bind_dn: config.bind_dn.clone(),
            bind_password: config.bind_password.clone(),
            base_dn: config.base_dn.clone(),
            tls_verify: config.tls_verify,
        }
    }

    /// Return the configured base DN.
    pub fn base_dn(&self) -> &str {
        &self.base_dn
    }

    async fn connect(&self) -> Result<Ldap> {
        let settings = LdapConnSettings::new().set_no_tls_verify(!self.tls_verify);
        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &self.server)
            .await
            .map_err(|e| ChalkError::AdSync(format!("LDAP connect failed: {e}")))?;

        ldap3::drive!(conn);

        ldap.simple_bind(&self.bind_dn, &self.bind_password)
            .await
            .map_err(|e| ChalkError::AdSync(format!("LDAP bind failed: {e}")))?
            .success()
            .map_err(|e| ChalkError::AdSync(format!("LDAP bind rejected: {e}")))?;

        debug!(server = %self.server, "LDAP bind successful");
        Ok(ldap)
    }

    /// Test the LDAP connection by binding and unbinding.
    pub async fn test_connection(&self) -> Result<()> {
        let mut ldap = self.connect().await?;
        ldap.unbind()
            .await
            .map_err(|e| ChalkError::AdSync(format!("LDAP unbind failed: {e}")))?;
        info!("AD connection test successful");
        Ok(())
    }

    /// Search for users matching the given LDAP filter.
    pub async fn search_users(&self, filter: &str) -> Result<Vec<AdUserAttrs>> {
        let mut ldap = self.connect().await?;
        let (results, _) = ldap
            .search(
                &self.base_dn,
                Scope::Subtree,
                filter,
                vec![
                    "dn",
                    "sAMAccountName",
                    "userPrincipalName",
                    "displayName",
                    "givenName",
                    "sn",
                    "mail",
                    "userAccountControl",
                    "distinguishedName",
                ],
            )
            .await
            .map_err(|e| ChalkError::AdSync(format!("LDAP search failed: {e}")))?
            .success()
            .map_err(|e| ChalkError::AdSync(format!("LDAP search error: {e}")))?;

        let users = results
            .into_iter()
            .map(|entry| {
                let se = SearchEntry::construct(entry);
                let dn = se.dn.clone();
                let sam = first_attr(&se, "sAMAccountName");
                let upn = optional_attr(&se, "userPrincipalName");
                let display = first_attr(&se, "displayName");
                let given = first_attr(&se, "givenName");
                let sn = first_attr(&se, "sn");
                let email = optional_attr(&se, "mail");
                let uac: u32 = first_attr(&se, "userAccountControl")
                    .parse()
                    .unwrap_or(UAC_NORMAL_ACCOUNT);
                let ou = extract_ou_from_dn(&dn);

                AdUserAttrs {
                    dn,
                    sam_account_name: sam,
                    upn,
                    display_name: display,
                    given_name: given,
                    surname: sn,
                    email,
                    ou,
                    user_account_control: uac,
                }
            })
            .collect();

        ldap.unbind().await.ok();
        Ok(users)
    }

    /// Create a new user in AD.
    pub async fn create_user(&self, user: &AdUserAttrs, password: &str) -> Result<()> {
        let mut ldap = self.connect().await?;

        let uac_str = user.user_account_control.to_string();
        let mut attrs: Vec<(&str, HashSet<&str>)> = vec![
            (
                "objectClass",
                HashSet::from(["top", "person", "organizationalPerson", "user"]),
            ),
            (
                "sAMAccountName",
                HashSet::from([user.sam_account_name.as_str()]),
            ),
            ("displayName", HashSet::from([user.display_name.as_str()])),
            ("givenName", HashSet::from([user.given_name.as_str()])),
            ("sn", HashSet::from([user.surname.as_str()])),
            ("userAccountControl", HashSet::from([uac_str.as_str()])),
        ];

        if let Some(ref upn) = user.upn {
            attrs.push(("userPrincipalName", HashSet::from([upn.as_str()])));
        }

        if let Some(ref email) = user.email {
            attrs.push(("mail", HashSet::from([email.as_str()])));
        }

        // AD requires the password in a specific UTF-16LE format
        let password_bytes = encode_ad_password(password);
        let password_str = String::from_utf8_lossy(&password_bytes).to_string();
        attrs.push(("unicodePwd", HashSet::from([password_str.as_str()])));

        ldap.add(&user.dn, attrs)
            .await
            .map_err(|e| ChalkError::AdSync(format!("LDAP add user failed: {e}")))?
            .success()
            .map_err(|e| ChalkError::AdSync(format!("LDAP add user rejected: {e}")))?;

        info!(dn = %user.dn, sam = %user.sam_account_name, "AD user created");
        ldap.unbind().await.ok();
        Ok(())
    }

    /// Modify attributes on an existing user.
    pub async fn modify_user(&self, dn: &str, mods: Vec<(String, Vec<String>)>) -> Result<()> {
        let mut ldap = self.connect().await?;

        let ldap_mods: Vec<Mod<String>> = mods
            .into_iter()
            .map(|(attr, vals)| Mod::Replace(attr, vals.into_iter().collect::<HashSet<String>>()))
            .collect();

        ldap.modify(dn, ldap_mods)
            .await
            .map_err(|e| ChalkError::AdSync(format!("LDAP modify failed: {e}")))?
            .success()
            .map_err(|e| ChalkError::AdSync(format!("LDAP modify rejected: {e}")))?;

        debug!(dn = %dn, "AD user modified");
        ldap.unbind().await.ok();
        Ok(())
    }

    /// Disable a user by setting userAccountControl to disabled.
    pub async fn disable_user(&self, dn: &str) -> Result<()> {
        self.modify_user(
            dn,
            vec![(
                "userAccountControl".to_string(),
                vec![UAC_DISABLED_ACCOUNT.to_string()],
            )],
        )
        .await?;
        info!(dn = %dn, "AD user disabled");
        Ok(())
    }

    /// Move a user to a different OU by performing an LDAP modifyDN.
    pub async fn move_user(&self, old_dn: &str, new_parent_dn: &str) -> Result<()> {
        let mut ldap = self.connect().await?;

        // Extract the RDN (first component) from the old DN
        let rdn = old_dn
            .split(',')
            .next()
            .ok_or_else(|| ChalkError::AdSync(format!("invalid DN: {old_dn}")))?;

        ldap.modifydn(old_dn, rdn, true, Some(new_parent_dn))
            .await
            .map_err(|e| ChalkError::AdSync(format!("LDAP modifyDN failed: {e}")))?
            .success()
            .map_err(|e| ChalkError::AdSync(format!("LDAP modifyDN rejected: {e}")))?;

        info!(old_dn = %old_dn, new_parent = %new_parent_dn, "AD user moved");
        ldap.unbind().await.ok();
        Ok(())
    }

    /// Delete a user from AD.
    pub async fn delete_user(&self, dn: &str) -> Result<()> {
        let mut ldap = self.connect().await?;
        ldap.delete(dn)
            .await
            .map_err(|e| ChalkError::AdSync(format!("LDAP delete failed: {e}")))?
            .success()
            .map_err(|e| ChalkError::AdSync(format!("LDAP delete rejected: {e}")))?;

        info!(dn = %dn, "AD user deleted");
        ldap.unbind().await.ok();
        Ok(())
    }

    /// Check whether a group exists at the given DN.
    pub async fn group_exists(&self, dn: &str) -> Result<bool> {
        let mut ldap = self.connect().await?;
        let search_result = ldap
            .search(dn, Scope::Base, "(objectClass=group)", vec!["dn"])
            .await
            .map_err(|e| ChalkError::AdSync(format!("LDAP search group failed: {e}")))?;
        let (results, _) = search_result
            .success()
            .map_err(|e| ChalkError::AdSync(format!("LDAP search group error: {e}")))?;
        ldap.unbind().await.ok();
        Ok(!results.is_empty())
    }

    /// Create a new security group in AD.
    pub async fn create_group(&self, dn: &str, name: &str) -> Result<()> {
        let mut ldap = self.connect().await?;
        let attrs: Vec<(&str, HashSet<&str>)> = vec![
            ("objectClass", HashSet::from(["top", "group"])),
            ("cn", HashSet::from([name])),
            ("sAMAccountName", HashSet::from([name])),
            // groupType: Global security group
            ("groupType", HashSet::from(["-2147483646"])),
        ];
        ldap.add(dn, attrs)
            .await
            .map_err(|e| ChalkError::AdSync(format!("LDAP create group failed: {e}")))?
            .success()
            .map_err(|e| ChalkError::AdSync(format!("LDAP create group rejected: {e}")))?;
        info!(dn = %dn, name = %name, "AD group created");
        ldap.unbind().await.ok();
        Ok(())
    }

    /// Add a user to a group by modifying the group's `member` attribute.
    pub async fn add_user_to_group(&self, group_dn: &str, user_dn: &str) -> Result<()> {
        let mut ldap = self.connect().await?;
        let mods = vec![Mod::Add(
            "member".to_string(),
            HashSet::from([user_dn.to_string()]),
        )];
        ldap.modify(group_dn, mods)
            .await
            .map_err(|e| ChalkError::AdSync(format!("LDAP add to group failed: {e}")))?
            .success()
            .map_err(|e| ChalkError::AdSync(format!("LDAP add to group rejected: {e}")))?;
        debug!(group = %group_dn, user = %user_dn, "user added to group");
        ldap.unbind().await.ok();
        Ok(())
    }

    /// Remove a user from a group by modifying the group's `member` attribute.
    pub async fn remove_user_from_group(&self, group_dn: &str, user_dn: &str) -> Result<()> {
        let mut ldap = self.connect().await?;
        let mods = vec![Mod::Delete(
            "member".to_string(),
            HashSet::from([user_dn.to_string()]),
        )];
        ldap.modify(group_dn, mods)
            .await
            .map_err(|e| ChalkError::AdSync(format!("LDAP remove from group failed: {e}")))?
            .success()
            .map_err(|e| ChalkError::AdSync(format!("LDAP remove from group rejected: {e}")))?;
        debug!(group = %group_dn, user = %user_dn, "user removed from group");
        ldap.unbind().await.ok();
        Ok(())
    }

    /// List all member DNs of a group.
    pub async fn list_group_members(&self, group_dn: &str) -> Result<Vec<String>> {
        let mut ldap = self.connect().await?;
        let (results, _) = ldap
            .search(group_dn, Scope::Base, "(objectClass=group)", vec!["member"])
            .await
            .map_err(|e| ChalkError::AdSync(format!("LDAP list group members failed: {e}")))?
            .success()
            .map_err(|e| ChalkError::AdSync(format!("LDAP list group members error: {e}")))?;

        let members: Vec<String> = results
            .into_iter()
            .flat_map(|entry| {
                let se = SearchEntry::construct(entry);
                se.attrs.get("member").cloned().unwrap_or_default()
            })
            .collect();

        ldap.unbind().await.ok();
        Ok(members)
    }

    /// Ensure an OU exists, creating it if necessary.
    pub async fn ensure_ou_exists(&self, ou_dn: &str) -> Result<()> {
        let mut ldap = self.connect().await?;

        // Check if OU already exists
        let search_result = ldap
            .search(
                ou_dn,
                Scope::Base,
                "(objectClass=organizationalUnit)",
                vec!["dn"],
            )
            .await
            .map_err(|e| ChalkError::AdSync(format!("LDAP search OU failed: {e}")))?;
        let (results, _) = search_result
            .success()
            .map_err(|e| ChalkError::AdSync(format!("LDAP search OU error: {e}")))?;

        if !results.is_empty() {
            ldap.unbind().await.ok();
            return Ok(());
        }

        // Extract the OU name from the DN
        let ou_name = ou_dn
            .split(',')
            .next()
            .and_then(|rdn| rdn.strip_prefix("OU="))
            .unwrap_or("Unknown");

        let attrs: Vec<(&str, HashSet<&str>)> = vec![
            ("objectClass", HashSet::from(["top", "organizationalUnit"])),
            ("ou", HashSet::from([ou_name])),
        ];

        ldap.add(ou_dn, attrs)
            .await
            .map_err(|e| ChalkError::AdSync(format!("LDAP create OU failed: {e}")))?
            .success()
            .map_err(|e| ChalkError::AdSync(format!("LDAP create OU rejected: {e}")))?;

        info!(ou_dn = %ou_dn, "AD OU created");
        ldap.unbind().await.ok();
        Ok(())
    }
}

/// Encode a password in the format AD expects for unicodePwd: UTF-16LE of `"password"`.
fn encode_ad_password(password: &str) -> Vec<u8> {
    let quoted = format!("\"{}\"", password);
    quoted
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect()
}

/// Extract the first value of an attribute, returning empty string if missing.
fn first_attr(entry: &SearchEntry, attr: &str) -> String {
    entry
        .attrs
        .get(attr)
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_default()
}

/// Extract the first value of an attribute as Option.
fn optional_attr(entry: &SearchEntry, attr: &str) -> Option<String> {
    entry.attrs.get(attr).and_then(|v| v.first()).cloned()
}

/// Extract the OU portion from a DN.
/// E.g. `CN=John Doe,OU=Students,DC=example,DC=com` -> `OU=Students,DC=example,DC=com`
fn extract_ou_from_dn(dn: &str) -> String {
    let parts: Vec<&str> = dn.split(',').collect();
    parts
        .iter()
        .skip(1) // Skip the CN= component
        .copied()
        .collect::<Vec<&str>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_password_format() {
        let encoded = encode_ad_password("Password1!");
        // Should be UTF-16LE of "\"Password1!\""
        let expected: Vec<u8> = "\"Password1!\""
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        assert_eq!(encoded, expected);
    }

    #[test]
    fn extract_ou_from_user_dn() {
        let ou = extract_ou_from_dn("CN=John Doe,OU=Students,DC=example,DC=com");
        assert_eq!(ou, "OU=Students,DC=example,DC=com");
    }

    #[test]
    fn extract_ou_from_deep_dn() {
        let ou = extract_ou_from_dn("CN=Jane,OU=09,OU=Lincoln HS,OU=Students,DC=example,DC=com");
        assert_eq!(ou, "OU=09,OU=Lincoln HS,OU=Students,DC=example,DC=com");
    }

    #[test]
    fn extract_ou_from_simple_dn() {
        let ou = extract_ou_from_dn("CN=Admin,DC=example,DC=com");
        assert_eq!(ou, "DC=example,DC=com");
    }

    #[test]
    fn client_new_from_config() {
        let config = AdConnectionConfig {
            server: "ldaps://dc01.example.com:636".to_string(),
            bind_dn: "CN=svc,DC=example,DC=com".to_string(),
            bind_password: "secret".to_string(),
            base_dn: "DC=example,DC=com".to_string(),
            tls_verify: true,
            tls_ca_cert: None,
        };
        let client = AdClient::new(&config);
        assert_eq!(client.server, "ldaps://dc01.example.com:636");
        assert_eq!(client.base_dn, "DC=example,DC=com");
        assert!(client.tls_verify);
    }

    #[test]
    fn uac_constants() {
        assert_eq!(UAC_NORMAL_ACCOUNT, 512);
        assert_eq!(UAC_DISABLED_ACCOUNT, 514);
    }
}
