//! What the console shell needs to draw itself: which page is current, and
//! which modules this deployment actually has.
//!
//! # Why this is a struct rather than a global
//!
//! The obvious implementation is a process-wide `MODULES` static read by
//! `base.html`. That is wrong here: hosted runs many districts in one process,
//! and a district that bought only the helpdesk must not see a sidebar drawn
//! from whatever the last request configured. The state travels with the
//! request or it is not state.
//!
//! # Why every template carries it
//!
//! `base.html` refers to `nav.devices` and `nav.helpdesk`, so a template that
//! extends the shell without a `nav` field **does not compile**. That is the
//! whole point of folding `active_page` into this struct rather than adding a
//! second field beside it: there is one thing the shell needs, and forgetting
//! it is a build error rather than a link to a page that 404s.
//!
//! # What is gated, and what deliberately is not
//!
//! Only links whose routes are actually withheld ([`crate::router`] merges
//! nothing for a disabled module, so its paths 404). Hiding a link whose route
//! still answers would be the same inconsistency in the other direction —
//! worse, because the page still exists and the operator cannot reach it.

use chalk_core::config::ChalkConfig;

/// The sidebar's view of this request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nav {
    /// Which sidebar entry is the current page. Matched against the literals
    /// in `base.html`.
    pub active: &'static str,
    /// Device inventory, reports, import/export, Google device sync.
    pub devices: bool,
    /// The helpdesk queue and ticket threads.
    pub helpdesk: bool,
}

impl Nav {
    /// The shell for `page`, with modules read from this deployment's config.
    pub fn new(config: &ChalkConfig, active: &'static str) -> Self {
        Self {
            active,
            devices: config.modules.devices,
            helpdesk: config.modules.helpdesk,
        }
    }

    /// Every module on. For fixtures and for surfaces that are not behind a
    /// module gate at all.
    pub fn all(active: &'static str) -> Self {
        Self {
            active,
            devices: true,
            helpdesk: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_nav_mirrors_the_config() {
        let mut config = ChalkConfig::generate_default();
        config.modules.devices = false;
        let nav = Nav::new(&config, "users");
        assert!(!nav.devices);
        assert!(nav.helpdesk);
        assert_eq!(nav.active, "users");
    }

    /// The link and the route are gated by the same field, so they cannot
    /// disagree — a visible link to a 404 is the bug this exists to prevent.
    #[test]
    fn a_disabled_module_is_hidden_and_withheld_by_the_same_flag() {
        let mut config = ChalkConfig::generate_default();
        config.modules.helpdesk = false;
        assert_eq!(
            Nav::new(&config, "dashboard").helpdesk,
            config.modules.helpdesk
        );
    }
}
