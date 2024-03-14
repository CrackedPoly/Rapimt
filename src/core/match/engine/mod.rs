//! # Engine module
//!
//! ## What is a match engine?
//! A match engine parses field values (like "dip=192.168.1.0/24, sport=80")
//! into a predicate that can perform logical operations (like AND, OR, NOT)
//! to express the match condition.
//!

pub mod ruddy_engine;
