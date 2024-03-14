//! # Match
//!
//! ## Relations of important structs
//! ```text
//!                   FieldMatch
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
//! use fast_imt::core::{MatchFamily, FieldMatch, MatchEncoder, PredicateOp,
//! RuddyPredicateEngine, ipv4_to_match};
//! use crate::fast_imt::fm_ipv4_from;
//!
//! // Initialize the engine
//! let mut engine = RuddyPredicateEngine::new();
//! let family = MatchFamily::TcpT4Family;
//! engine.init(1000, 100, family);
//!
//! // Encode
//! let matches1 = vec![fm_ipv4_from!("sip", "192.168.1.0/24"), fm_ipv4_from!("dip", "0.0.0.0/0")];
//! let (p1, _) = engine.encode_matches(matches1);
//! let matches2 = vec![fm_ipv4_from!("sip", "192.168.50.1/24"), fm_ipv4_from!("dip", "0.0.0.0/0")];
//! let (p2, _) = engine.encode_matches(matches2);
//!
//! // Operate
//! let p3 = p1 & p2;
//! p1.drop();
//! p2.drop();
//! ```

pub mod engine;
pub mod family;
