pub mod action;
pub mod im;
pub mod r#match;

pub use r#match::engine::ruddy_engine::RuddyPredicateEngine;
pub use r#match::engine::{MatchEncoder, PredicateIO, PredicateOp};
pub use r#match::family::macros::ipv4_to_match;
pub use r#match::family::{FamilyDecl, FieldMatch, Match, MatchFamily};
use std::fmt::Display;

pub trait PredicateEngine<'a>: MatchEncoder<'a> + PredicateIO<'a> {}
pub trait Predicate: PredicateOp + Display {}
