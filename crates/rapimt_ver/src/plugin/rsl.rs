//! Requirement Specification Language (RSL) parser.
use std::{mem::MaybeUninit, ptr::addr_of_mut};

use fxhash::FxHashSet;
use pest::iterators::Pair;
use pest_derive::Parser;
use rapimt_core::r#match::{
    engine::MatchEncoder,
    predicate::{Predicate, PredicateInner},
    raw_match::{FieldMatch, Match},
};
use rapimt_io::ib::loader::{Guid, Lid};
use regex::Regex;

#[derive(Parser)]
#[grammar = "src/plugin/rsl.pest"]
pub struct RSLParser<'p, ME: MatchEncoder<'p>>(&'p ME);

pub struct Requirement<'a, P: PredicateInner> {
    pub predicate: Predicate<P>,
    pub matches: Vec<FieldMatch<'a, Lid>>,
    pub sources: FxHashSet<Guid>,
    pub path_regex: Regex,
}

impl<P: PredicateInner> std::fmt::Debug for Requirement<'_, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Requirement")
            .field("matches", &self.matches)
            .field("sources", &self.sources)
            .field("path_regex", &self.path_regex)
            .finish()
    }
}

#[derive(Default)]
enum OpKind {
    #[default]
    Contains,
    Matches,
}

impl<'p, ME: MatchEncoder<'p>> RSLParser<'p, ME> {
    fn parse_field_value(pair: Pair<'_, Rule>) -> FieldMatch<'_, Lid> {
        let mut field: &str = "";
        let mut cond: Match<Lid> = Match::ExactMatch { value: 0 };
        for p in pair.into_inner() {
            match p.as_rule() {
                Rule::field => field = p.as_str(),
                Rule::value => {
                    cond = Match::ExactMatch {
                        value: p.as_str().parse().unwrap(),
                    }
                }
                _ => unreachable!(),
            }
        }
        FieldMatch { field, cond }
    }

    /// [Rule::headerspace]
    fn parse_header_space<'a>(
        &'a self,
        pair: Pair<'a, Rule>,
    ) -> (Vec<FieldMatch<'a, Lid>>, Predicate<ME::P>) {
        let mut fms = Vec::new();
        for p in pair.into_inner() {
            match p.as_rule() {
                Rule::field_value => fms.push(Self::parse_field_value(p)),
                _ => unreachable!(),
            }
        }
        let mut pred = self.0.zero();
        for fm in fms.iter() {
            let p = self.0.encode_match_wo_mv(*fm);
            pred |= p;
        }
        (fms, pred)
    }

    /// [Rule::sources]
    fn parse_sources(pair: Pair<'_, Rule>) -> FxHashSet<Guid> {
        let mut sources = FxHashSet::default();
        for p in pair.into_inner() {
            match p.as_rule() {
                Rule::node_id => {
                    sources.insert(p.as_str().parse().unwrap());
                }
                _ => unreachable!(),
            }
        }
        sources
    }

    /// [Rule::cond]
    fn parse_op_value(pair: Pair<'_, Rule>) -> (OpKind, &str) {
        let mut op_kind = OpKind::Contains;
        let mut val = "";
        for p in pair.into_inner() {
            match p.as_rule() {
                Rule::label => assert_eq!(p.as_str(), "name"),
                Rule::MATCHES => op_kind = OpKind::Matches,
                Rule::CONTAINS => op_kind = OpKind::Contains,
                Rule::val => val = p.as_str(),
                _ => unreachable!(),
            }
        }
        (op_kind, val)
    }

    /// [Rule::path_expr]
    fn parse_path_expr(pair: Pair<'_, Rule>) -> Regex {
        let mut regex_builder = String::new();
        for p in pair.into_inner() {
            match p.as_rule() {
                Rule::node_id => {
                    regex_builder.push_str("\\(");
                    regex_builder.push_str(p.as_str());
                    regex_builder.push_str("\\)");
                }
                Rule::path_cons => regex_builder.push_str(p.as_str()),
                Rule::cond => {
                    regex_builder.push_str("\\(");
                    let (op, val) = Self::parse_op_value(p);
                    match op {
                        OpKind::Contains => {
                            regex_builder.push_str(".*");
                            regex_builder.push_str(val);
                            regex_builder.push_str(".*");
                        }
                        OpKind::Matches => regex_builder.push_str(val),
                    }
                    regex_builder.push_str("\\)");
                }
                _ => unreachable!(),
            }
        }
        Regex::new(&regex_builder).unwrap()
    }

    /// [Rule::req]
    fn parse_req<'a>(&'a self, pair: Pair<'a, Rule>) -> Requirement<'a, ME::P> {
        let mut req = MaybeUninit::<Requirement<'_, ME::P>>::uninit();
        let ptr = req.as_mut_ptr();
        for p in pair.into_inner() {
            match p.as_rule() {
                Rule::headerspace => {
                    let (fms, pred) = self.parse_header_space(p);
                    unsafe { addr_of_mut!((*ptr).predicate).write(pred) };
                    unsafe { addr_of_mut!((*ptr).matches).write(fms) };
                }
                Rule::sources => {
                    let sources = Self::parse_sources(p);
                    unsafe { addr_of_mut!((*ptr).sources).write(sources) };
                }
                Rule::path_expr => {
                    let path_regex = Self::parse_path_expr(p);
                    unsafe { addr_of_mut!((*ptr).path_regex).write(path_regex) };
                }
                _ => unreachable!(),
            }
        }
        unsafe { req.assume_init() }
    }

    /// [Rule::reqs]
    pub fn parse_reqs<'a>(&'a self, pair: Pair<'a, Rule>) -> Vec<Requirement<'a, ME::P>> {
        let mut reqs = Vec::new();
        for p in pair.into_inner() {
            if p.as_rule() == Rule::req {
                reqs.push(self.parse_req(p))
            }
        }
        reqs
    }
}

#[cfg(test)]
mod tests {
    use pest::Parser;
    use rapimt_core::r#match::engine::OxiddPredicateEngine;

    use super::*;

    static REQS: &str = r#"FOR lid=3379
                           FROM [12,23,34,45] 
                           GOES ^<1><2><name matches POD1-sw\d+><name contains POD2><3>$"#;

    #[test]
    fn test_parse() {
        let engine = OxiddPredicateEngine::init(10000, 5000);
        let parser = RSLParser(&engine);
        let pair = RSLParser::<OxiddPredicateEngine>::parse(Rule::reqs, REQS)
            .unwrap()
            .next()
            .unwrap();
        let reqs = parser.parse_reqs(pair);
        let req = &reqs[0];
        let path = "(1)(2)(POD1-sw1)(POD2-sw999)(3)";
        assert!(req.path_regex.is_match(path));
    }
}
