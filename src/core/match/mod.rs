//! # Match
//!
//! ## Relations of important structs
//! ```text
//!                   FieldValue
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
//! use fast_imt::core::{MatchFamily, FieldValue, MatchEncoder, PredicateOp,
//! RuddyPredicateEngine};
//! use crate::fast_imt::fv_from;
//!
//! // Initialize the engine
//! let mut engine = RuddyPredicateEngine::new();
//! let family = MatchFamily::TcpT4Family;
//! engine.init(1000, 100, family);
//!
//! // Encode
//! let matches1 = vec![fv_from!("sip", "192.168.1.0/24"), fv_from!("dip", "0.0.0.0/0")];
//! let p1 = engine.encode_values(matches1);
//! let matches2 = vec![fv_from!("sip", "192.168.50.1/24"), fv_from!("dip", "0.0.0.0/0")];
//! let p2 = engine.encode_values(matches2);
//!
//! // Operate
//! let p3 = p1 & p2;
//! p1.drop();
//! p2.drop();
//! ```

pub mod engine;
pub mod family;
