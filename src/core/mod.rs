mod action;
mod im;
mod r#match;

pub use r#match::engine::ruddy_engine::RuddyPredicateEngine;
pub use r#match::engine::{MatchEncoder, PredicateIO, PredicateOp};
pub use r#match::family::{FamilyDecl, FieldValue, Match, MatchFamily};
use std::fmt::Display;

pub trait PredicateEngine<'a>: MatchEncoder<'a> + PredicateIO<'a> {}
pub trait Predicate: PredicateOp + Display {}
