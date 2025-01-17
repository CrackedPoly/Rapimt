//! Action encoding and decoding, and match encoding.
pub mod action;
pub mod r#match;

#[allow(missing_docs)]
#[doc(hidden)]
pub mod prelude {
    pub use crate::{
        action::{
            fwd::FwdActionType,
            acl::AclActionType,
            Action, ActionEncoder, UncodedAction, CodedAction, Dimension, Multiple, Single, Actions
        },
        r#match::{
            family::{constant, MatchFamily},
            raw_match::macros::*,
            predicate::{Predicate, PredicateInner},
            raw_match::{FieldMatch, MaskedValue, Match},
            engine::{MatchEncoder, PredicateEngine, RuddyPredicateEngine, RuddyPredicate, OxiddPredicateEngine, OxiddPredicate},
        },
    };
}
