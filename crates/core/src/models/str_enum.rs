//! `str_enum!` — declares a closed enum together with its single canonical
//! string mapping.
//!
//! Existing entities (e.g. [`crate::models::common::Status`]) carry their
//! database-string mapping as hand-written `parse_x` / `x_to_str` free
//! functions duplicated in `db/sqlite.rs` *and* `db/postgres.rs`. That is two
//! copies per enum that can silently diverge — the exact failure mode where a
//! value written by one driver is unreadable by the other.
//!
//! The device/asset entities introduce fifteen such enums, so they declare the
//! mapping once, here, and both drivers call `as_str` / `parse`. Serde renames
//! are generated from the same literals, so the API surface and the stored
//! representation cannot drift either.
//!
//! Unknown stored values fail closed with a `Serialization` error rather than
//! silently coercing to a default: a device whose status we cannot read must
//! not render as `active`.

/// Declare an enum plus its canonical string form.
///
/// ```ignore
/// str_enum! {
///     /// Doc comment.
///     pub enum Color {
///         Red => "red",
///         Blue => "blue",
///     }
/// }
/// ```
///
/// Add a trailing `with_default` and mark one variant `#[default]` to also
/// derive [`Default`]. The trailing token is required because a macro cannot
/// see whether a caller-supplied attribute is `#[default]`, and deriving
/// `Default` unconditionally would force a meaningless default onto enums like
/// `ChangeSetOp` that genuinely have none:
///
/// ```ignore
/// str_enum! {
///     pub enum Color {
///         #[default]
///         Red => "red",
///         Blue => "blue",
///     }
///     with_default
/// }
/// ```
macro_rules! str_enum {
    // With `Default`. Exactly one variant must carry `#[default]`.
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $( $(#[$vmeta:meta])* $variant:ident => $lit:literal ),+ $(,)?
        }
        with_default
    ) => {
        $(#[$meta])*
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, Hash, Default,
            ::serde::Serialize, ::serde::Deserialize
        )]
        $vis enum $name {
            $(
                $(#[$vmeta])*
                #[serde(rename = $lit)]
                $variant,
            )+
        }

        $crate::models::str_enum::str_enum!(@impls $name { $( $variant => $lit ),+ });
    };

    // Without `Default`.
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $( $(#[$vmeta:meta])* $variant:ident => $lit:literal ),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, Hash,
            ::serde::Serialize, ::serde::Deserialize
        )]
        $vis enum $name {
            $(
                $(#[$vmeta])*
                #[serde(rename = $lit)]
                $variant,
            )+
        }

        $crate::models::str_enum::str_enum!(@impls $name { $( $variant => $lit ),+ });
    };

    // Internal: the string mapping, shared by both arms above.
    (@impls $name:ident { $( $variant:ident => $lit:literal ),+ }) => {
        impl $name {
            /// Every variant, in declaration order.
            pub const ALL: &'static [$name] = &[ $( $name::$variant ),+ ];

            /// The canonical string stored in the database and emitted by serde.
            pub fn as_str(&self) -> &'static str {
                match self {
                    $( $name::$variant => $lit ),+
                }
            }

            /// Parse the canonical string. Fails closed on anything else.
            pub fn parse(s: &str) -> $crate::error::Result<Self> {
                match s {
                    $( $lit => Ok($name::$variant), )+
                    other => Err($crate::error::ChalkError::Serialization(format!(
                        concat!("unknown ", stringify!($name), " value: {}"),
                        other
                    ))),
                }
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl ::std::str::FromStr for $name {
            type Err = $crate::error::ChalkError;
            fn from_str(s: &str) -> ::std::result::Result<Self, Self::Err> {
                $name::parse(s)
            }
        }
    };
}

pub(crate) use str_enum;

#[cfg(test)]
mod tests {
    str_enum! {
        /// Fixture enum for the macro's own tests.
        pub enum Fixture {
            Alpha => "alpha",
            BetaTwo => "beta_two",
        }
    }

    str_enum! {
        /// Fixture for the `with_default` arm.
        pub enum DefaultedFixture {
            First => "first",
            #[default]
            Second => "second",
        }
        with_default
    }

    #[test]
    fn as_str_matches_declaration() {
        assert_eq!(Fixture::Alpha.as_str(), "alpha");
        assert_eq!(Fixture::BetaTwo.as_str(), "beta_two");
    }

    #[test]
    fn parse_round_trips_every_variant() {
        for variant in Fixture::ALL {
            assert_eq!(&Fixture::parse(variant.as_str()).unwrap(), variant);
        }
    }

    #[test]
    fn parse_fails_closed_on_unknown() {
        let err = Fixture::parse("gamma").unwrap_err();
        assert!(err.to_string().contains("unknown Fixture value: gamma"));
    }

    #[test]
    fn serde_uses_the_same_literals() {
        assert_eq!(
            serde_json::to_string(&Fixture::BetaTwo).unwrap(),
            "\"beta_two\""
        );
        assert_eq!(
            serde_json::from_str::<Fixture>("\"alpha\"").unwrap(),
            Fixture::Alpha
        );
    }

    #[test]
    fn display_and_from_str_agree() {
        use std::str::FromStr;
        assert_eq!(Fixture::Alpha.to_string(), "alpha");
        assert_eq!(Fixture::from_str("beta_two").unwrap(), Fixture::BetaTwo);
    }

    #[test]
    fn with_default_arm_honours_the_marked_variant() {
        assert_eq!(DefaultedFixture::default(), DefaultedFixture::Second);
        // The mapping impls are generated identically on both arms.
        assert_eq!(DefaultedFixture::default().as_str(), "second");
        assert_eq!(DefaultedFixture::ALL.len(), 2);
        assert_eq!(
            DefaultedFixture::parse("first").unwrap(),
            DefaultedFixture::First
        );
    }
}
