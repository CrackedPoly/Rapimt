//! # Match
//!
//! ## Relations of important structs
//! ```text
//!                   FieldMatch(s)
//!                       |
//!                       v
//! MatchFamily -> PredicateEngine
//!                       |
//!                       v
//!                    Predicate
//! ```
//!
//! ## Example
//! ```no_run
//! use rapimt_core::fm_ipv4_from;
//! use rapimt_core::prelude::{
//!     ipv4_to_match,
//!     Predicate, PredicateEngine, MatchEncoder,
//!     RuddyPredicateEngine, FieldMatch, MatchFamily
//! };
//!
//! // Initialize the engine
//! let engine = RuddyPredicateEngine::init(1000, 100);
//!
//! // Encode
//! let matches1 = vec![fm_ipv4_from!("sip", "192.168.1.0/24"), fm_ipv4_from!("dip", "0.0.0.0/0")];
//! let (p1, _) = engine.encode_matches(matches1);
//! let matches2 = vec![fm_ipv4_from!("sip", "192.168.50.1/24"), fm_ipv4_from!("dip", "0.0.0.0/0")];
//! let (p2, _) = engine.encode_matches(matches2);
//!
//! // Operate
//! let p3 = p1 & p2;
//! ```

pub mod engine;
pub mod family;
pub mod raw_match;
pub mod predicate;
