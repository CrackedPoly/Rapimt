//! Action encoding and decoding, and match encoding.
#![feature(vec_into_raw_parts)]
#![feature(hasher_prefixfree_extras)]
pub mod action;
pub mod r#match;

#[allow(missing_docs)]
#[doc(hidden)]
pub mod prelude {
    pub use crate::{
        action::{
            acl::AclActionType, fwd::FwdActionType, Action, ActionEncoder, Actions, CodedAction,
            Dimension, Multiple, Single, UncodedAction,
        },
        r#match::{
            engine::{MatchEncoder, OxiddPredicateEngine, PredicateEngine, RuddyPredicateEngine},
            family::constant,
            predicate::{Predicate, PredicateInner},
            raw_match::macros::*,
            raw_match::{FieldMatch, MaskedValue, Match},
        },
    };
}
