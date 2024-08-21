//! This module provides action encoding/decoding and action matching utilities.
pub mod action;
pub mod r#match;

// these are compile-run parameters
pub use crate::r#match::{
    family::{HeaderBitOrder, HeaderBitStore, HEADERSTORENUM, MAX_POS},
    macros::ipv4_to_match,
};

#[allow(missing_docs)]
pub mod prelude {
    #[doc(hidden)]
    pub use crate::{
        action::{
            seq_action, ActionEncoder, ActionType, CodedAction, CodedActions, ModelType, Multiple,
            Single, UncodedAction,
        },
        r#match::{
            engine::{RuddyPredicate, RuddyPredicateEngine},
            family::{HeaderBitOrder, HeaderBitStore, MatchFamily, HEADERSTORENUM, MAX_POS},
            macros::ipv4_to_match,
            FieldMatch, MaskedValue, Match, MatchEncoder, Predicate, PredicateEngine,
            PredicateInner, Rule, UncodedRule,
        },
    };
}
