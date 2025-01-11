//! This module provides action encoding/decoding and action matching utilities.
pub mod action;
pub mod r#match;

#[allow(missing_docs)]
pub mod prelude {
    #[doc(hidden)]
    pub use crate::{
        action::{
            fwd::FwdActionType,
            acl::AclActionType,
            seq_action, Action, ActionEncoder, CodedAction, CodedActions, Dimension,
            Multiple, Single, UncodedAction,
        },
        r#match::{
            family::{constant, MatchFamily},
            raw_match::macros::*,
            predicate::{Predicate, PredicateInner},
            raw_match::{FieldMatch, MaskedValue, Match},
            rule::{Rule, UncodedRule},
            engine::{MatchEncoder, PredicateEngine, RuddyPredicateEngine, RuddyPredicate},
        },
    };
}
