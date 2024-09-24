//! This module provides action encoding/decoding and action matching utilities.
pub mod action;
pub mod r#match;

pub use crate::r#match::macros::*;

#[allow(missing_docs)]
pub mod prelude {
    #[doc(hidden)]
    pub use crate::{
        action::{
            seq_action, Action, ActionEncoder, ActionType, CodedAction, CodedActions, Dimension,
            Multiple, Single, UncodedAction,
        },
        r#match::{
            engine::{RuddyPredicate, RuddyPredicateEngine},
            family::{constant, MatchFamily},
            macros::ipv4_to_match,
            FieldMatch, MaskedValue, Match, MatchEncoder, Predicate, PredicateEngine,
            PredicateInner, Rule, UncodedRule,
        },
    };
}
