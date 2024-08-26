use std::{cell::RefCell, hash::Hash};

use fxhash::FxBuildHasher;
use indexmap::map::IndexMap;
use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::{multispace0, multispace1},
    combinator::{all_consuming, map, not},
    error::{ErrorKind, ParseError},
    multi::{separated_list0, separated_list1},
    sequence::{delimited, pair, preceded, separated_pair, tuple},
    IResult,
};

use rapimt_core::{
    action::{Action, ActionEncoder, ActionType, Single, UncodedAction},
    r#match::{FieldMatch, Match, PredicateEngine, Rule},
};

use crate::{
    basic::parser::{parse_digits, parse_ident, parse_ipv4_dotted, parse_ipv4_num},
    {FibLoader, InstanceLoader},
};

#[derive(Debug)]
struct NeighborInfo {
    name: String,
    #[allow(dead_code)]
    external: bool,
}

#[derive(Debug)]
struct PortInfo {
    name: String,
    mode: ActionType,
    p_ports: Vec<String>, // vector of physical port names
}

#[derive(Clone, Copy, Debug)]
pub struct TypedActionInner<'a> {
    idx: u32,
    origin: &'a PortInfoBase,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, Default)]
pub enum TypedAction<'a> {
    Typed(TypedActionInner<'a>),
    #[default]
    Default,
}

impl PartialEq for TypedActionInner<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.idx == other.idx && std::ptr::eq(self.origin, other.origin)
    }
}

impl Eq for TypedActionInner<'_> {}

impl Hash for TypedActionInner<'_> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.idx.hash(state);
    }
}

impl<'o> Action<Single> for TypedAction<'o> {
    type S = Self;
}

impl<'o> UncodedAction for TypedAction<'o> {
    fn get_type(&self) -> ActionType {
        match self {
            TypedAction::Default => ActionType::DROP,
            TypedAction::Typed(t) => {
                t.origin
                    .ports
                    .get_index(t.idx as usize - 1)
                    .unwrap()
                    .1
                    .mode
            }
        }
    }

    /// This method must return Vec because TypedAction::Default does not have any reference
    #[allow(refining_impl_trait_reachable)]
    fn get_next_hops(&self) -> Vec<&str> {
        match self {
            TypedAction::Default => vec![],
            TypedAction::Typed(t) => t
                .origin
                .ports
                .get_index(t.idx as usize - 1)
                .unwrap()
                .1
                .p_ports
                .iter()
                .map(|s| t.origin.nbrs.get(s).unwrap().name.as_str())
                .collect(),
        }
    }
}

#[derive(Debug)]
pub struct PortInfoBase {
    #[allow(dead_code)]
    dev: String,
    // port name -> neighbor info
    nbrs: IndexMap<String, NeighborInfo, FxBuildHasher>,
    // port name -> port info
    ports: IndexMap<String, PortInfo, FxBuildHasher>,
}

impl<'a> ActionEncoder<'a> for PortInfoBase {
    type UA = TypedAction<'a>;

    #[inline]
    fn encode(&'a self, action: Self::UA) -> u32 {
        match action {
            TypedAction::Default => 0,
            TypedAction::Typed(t) => t.idx,
        }
    }

    #[inline]
    fn decode(&'a self, coded_action: u32) -> Self::UA {
        match coded_action {
            0 => TypedAction::Default,
            _ => TypedAction::Typed(TypedActionInner {
                idx: coded_action,
                origin: self,
            }),
        }
    }

    fn get(&'a self, port_name: &str) -> Option<Self::UA> {
        // since A == 0 means no overwrite, we can't use 0 as CodedAction
        self.ports
            .get_full(port_name)
            .map(|(idx, _, _)| match idx {
                0 => TypedAction::Default,
                _ => TypedAction::Typed(TypedActionInner {
                    idx: idx as u32 + 1,
                    origin: self,
                }),
            })
    }
}

#[derive(Default)]
pub struct DefaultInstLoader {}

impl<'o> InstanceLoader<'o, PortInfoBase, TypedAction<'o>> for DefaultInstLoader {
    fn _load<'x, E: ParseError<&'x str>>(&self, content: &'x str) -> IResult<(), PortInfoBase, E> {
        let nbrs = RefCell::new(IndexMap::with_hasher(FxBuildHasher::default()));
        let ports = RefCell::new(IndexMap::with_hasher(FxBuildHasher::default()));
        ports.borrow_mut().insert(
            "self".to_owned(),
            PortInfo {
                name: "self".to_owned(),
                mode: ActionType::DROP,
                p_ports: vec![],
            },
        );

        let capture_nbr_info = |(port_name, nbr): (&str, NeighborInfo)| {
            ports.borrow_mut().insert(
                port_name.to_owned(),
                PortInfo {
                    name: port_name.to_owned(),
                    mode: ActionType::FORWARD,
                    p_ports: vec![port_name.to_owned()],
                },
            );
            nbrs.borrow_mut().insert(port_name.to_owned(), nbr);
        };
        let capture_port_info = |port: PortInfo| {
            ports.borrow_mut().insert(port.name.to_owned(), port);
        };

        let (rest, dev) = delimited(multispace0, parse_dev, multispace1)(content)?;
        let (rest, _) = separated_list0(
            multispace1,
            alt((
                map(parse_neighbor_info, capture_nbr_info),
                map(parse_port_info, capture_port_info),
            )),
        )(rest)?;
        let (_, _) = all_consuming(multispace0)(rest)?;
        Ok((
            (),
            PortInfoBase {
                dev: dev.to_string(),
                nbrs: nbrs.into_inner(),
                ports: ports.into_inner(),
            },
        ))
    }
}

fn parse_dev<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, &'a str, E> {
    preceded(pair(tag("name"), multispace1), parse_ident)(input)
}

fn parse_mode<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, ActionType, E> {
    let (rest, mode) = alt((tag("ecmp"), tag("flood")))(input)?;
    match mode {
        "ecmp" => Ok((rest, ActionType::ECMP)),
        "flood" => Ok((rest, ActionType::FLOOD)),
        _ => Err(nom::Err::Error(E::from_error_kind(input, ErrorKind::Tag))),
    }
}

fn parse_port<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, &'a str, E> {
    if not(alt((tag::<&str, &str, E>("port"), tag("neighbor"))))(input).is_ok() {
        return parse_ident(input);
    }
    Err(nom::Err::Error(E::from_error_kind(input, ErrorKind::Tag)))
}
fn parse_port_info<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, PortInfo, E> {
    let (rest, _) = pair(tag("port"), multispace1)(input)?;
    let (rest, (port, _, mode, _, ports)) = tuple((
        parse_port,
        multispace1,
        parse_mode,
        multispace1,
        separated_list1(multispace1, parse_port),
    ))(rest)?;
    return Ok((
        rest,
        PortInfo {
            name: port.to_owned(),
            mode,
            p_ports: ports.iter().map(|s| (*(*s)).to_owned()).collect(),
        },
    ));
}

fn parse_neighbor_info<'a, E: ParseError<&'a str>>(
    input: &'a str,
) -> IResult<&'a str, (&str, NeighborInfo), E> {
    let (rest, _) = pair(tag("neighbor"), multispace1)(input)?;
    let (rest, (port, nbr)) = separated_pair(parse_port, multispace1, parse_ident)(rest)?;
    Ok((
        rest,
        (
            port,
            NeighborInfo {
                name: nbr.to_owned(),
                external: false,
            },
        ),
    ))
}

impl<'a, 'p> FibLoader<'a, 'p, u32> for PortInfoBase {
    fn _load<'x, 's: 'p, PE, Err>(
        &'s self,
        engine: &'p PE,
        content: &'x str,
    ) -> IResult<(), (String, Vec<Rule<PE::P, u32>>), Err>
    where
        PE: PredicateEngine<'p>,
        Err: ParseError<&'x str>,
    {
        let (rest, dev) = delimited(multispace0, parse_dev, multispace1)(content)?;
        let (rest, rules) = separated_list0(multispace1, parse_ipv4_rule(engine, self))(rest)?;
        let (_, _) = all_consuming(multispace0)(rest)?;
        Ok(((), (dev.to_owned(), rules)))
    }
}

impl<'a, 'p: 'a> FibLoader<'a, 'p, TypedAction<'a>> for PortInfoBase {
    fn _load<'x, 's: 'p, PE, Err>(
        &'s self,
        engine: &'p PE,
        content: &'x str,
    ) -> IResult<(), (String, Vec<Rule<PE::P, TypedAction<'a>>>), Err>
    where
        PE: PredicateEngine<'p>,
        Err: ParseError<&'x str>,
    {
        let (rest, dev) = delimited(multispace0, parse_dev, multispace1)(content)?;
        let (rest, rules) =
            separated_list0(multispace1, parse_ipv4_rule_uncoded(engine, self))(rest)?;
        let (_, _) = all_consuming(multispace0)(rest)?;
        Ok(((), (dev.to_owned(), rules)))
    }
}

/// Returns a closure that parses an IPv4 rule and returns a [Rule] instance.
/// The closure have the lifetime of MatchEncoder's 'p and ActionEncoder's 'a,
/// where 'a == 'p.
fn parse_ipv4_rule<'x, 'a: 'p, 'p: 'a, PE, AE, E>(
    engine: &'p PE,
    action_encoder: &'a AE,
) -> impl Fn(&'x str) -> IResult<&'x str, Rule<PE::P, u32>, E> + 'p + 'a
where
    PE: PredicateEngine<'p>,
    AE: ActionEncoder<'a>,
    E: ParseError<&'x str>,
{
    move |input| {
        let (rest, (_, _, value, _, p_len, _, prio, _, port_name)) = tuple((
            tag("fw"),
            multispace1,
            alt((parse_ipv4_dotted, parse_ipv4_num)),
            multispace1,
            map(parse_digits, |s: &str| s.parse::<u32>().unwrap()),
            multispace1,
            map(parse_digits, |s: &str| s.parse::<i32>().unwrap()),
            multispace1,
            parse_port,
        ))(input)?;
        let value = value as u128;
        let mask: u128 = ((1 << p_len) - 1) << (32 - p_len);
        let fm = FieldMatch {
            field: "dip",
            cond: Match::TernaryMatch { value, mask },
        };
        let (pred, mvs) = engine.encode_match(fm);
        let action = action_encoder.encode(action_encoder.get(port_name).unwrap());
        Ok((
            rest,
            Rule {
                priority: prio,
                action,
                predicate: pred,
                origin: mvs,
            },
        ))
    }
}

fn parse_ipv4_rule_uncoded<'x, 'a: 'p, 'p: 'a, PE, AE, E>(
    engine: &'p PE,
    action_encoder: &'a AE,
) -> impl Fn(&'x str) -> IResult<&'x str, Rule<PE::P, AE::UA>, E> + 'p + 'a
where
    PE: PredicateEngine<'p>,
    AE: ActionEncoder<'a>,
    E: ParseError<&'x str>,
{
    move |input| {
        let (rest, (_, _, value, _, p_len, _, prio, _, port_name)) = tuple((
            tag("fw"),
            multispace1,
            alt((parse_ipv4_dotted, parse_ipv4_num)),
            multispace1,
            map(parse_digits, |s: &str| s.parse::<u32>().unwrap()),
            multispace1,
            map(parse_digits, |s: &str| s.parse::<i32>().unwrap()),
            multispace1,
            parse_port,
        ))(input)?;
        let value = value as u128;
        let mask: u128 = ((1 << p_len) - 1) << (32 - p_len);
        let fm = FieldMatch {
            field: "dip",
            cond: Match::TernaryMatch { value, mask },
        };
        let (pred, mvs) = engine.encode_match(fm);
        let action = action_encoder.get(port_name).unwrap();
        Ok((
            rest,
            Rule {
                priority: prio,
                action,
                predicate: pred,
                origin: mvs,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use rapimt_core::r#match::{engine::RuddyPredicateEngine, family::MatchFamily::Inet4Family};

    use super::*;

    #[test]
    fn test_loaders() {
        let loader = DefaultInstLoader::default();
        let spec = r#"
        name dev0
        neighbor ge0 dev1
        neighbor ge1 dev2
        port gi0 ecmp ge0 ge1
        port gi1 flood ge0 ge1
        "#;
        let base = loader.load(spec).unwrap();
        assert_eq!(base.dev, "dev0");
        assert_eq!(base.nbrs.len(), 2);
        assert_eq!(base.ports.len(), 5);

        let nbrs = &base.nbrs;
        let n1 = nbrs.get("ge0").unwrap();
        assert_eq!(n1.name, "dev1");
        assert!(!n1.external);
        let n2 = nbrs.get("ge1").unwrap();
        assert_eq!(n2.name, "dev2");
        assert!(!n2.external);

        let ports = &base.ports;

        let (_, p0) = ports.get_index(0).unwrap();
        assert_eq!(p0.name, "self");
        assert_eq!(p0.mode, ActionType::DROP);
        assert_eq!(p0.p_ports.len(), 0);
        let (_, p1) = ports.get_index(1).unwrap();
        assert_eq!(p1.name, "ge0");
        assert_eq!(p1.mode, ActionType::FORWARD);
        assert_eq!(p1.p_ports.len(), 1);
        assert_eq!(p1.p_ports[0], "ge0");
        let (_, p2) = ports.get_index(2).unwrap();
        assert_eq!(p2.name, "ge1");
        assert_eq!(p2.mode, ActionType::FORWARD);
        assert_eq!(p2.p_ports.len(), 1);
        assert_eq!(p2.p_ports[0], "ge1");
        let (_, p3) = ports.get_index(3).unwrap();
        assert_eq!(p3.name, "gi0");
        assert_eq!(p3.mode, ActionType::ECMP);
        assert_eq!(p3.p_ports.len(), 2);
        assert_eq!(p3.p_ports[0], "ge0");
        assert_eq!(p3.p_ports[1], "ge1");
        let (_, p4) = ports.get_index(4).unwrap();
        assert_eq!(p4.name, "gi1");
        assert_eq!(p4.mode, ActionType::FLOOD);
        assert_eq!(p4.p_ports.len(), 2);
        assert_eq!(p4.p_ports[0], "ge0");
        assert_eq!(p4.p_ports[1], "ge1");

        let fib = r#"
        name dev0
        fw 192.168.1.0 24 24 gi0
        fw 0.0.0.0 0 0 ge0
        "#;
        let engine = RuddyPredicateEngine::init(1000, 100, Inet4Family);
        let (dev, rules) = FibLoader::<u32>::load(&base, &engine, fib).unwrap();
        assert_eq!(dev, "dev0");
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].predicate.to_string(), "dip: 192.168.1.0/24");
        assert_eq!(rules[0].priority, 24);
        assert_eq!(rules[0].action, 4);
        assert_eq!(rules[1].predicate.to_string(), "dip: 0.0.0.0/0");
        assert_eq!(rules[1].priority, 0);
        assert_eq!(rules[1].action, 2);
        let (dev, rules) = FibLoader::<TypedAction>::load(&base, &engine, fib).unwrap();
        assert_eq!(dev, "dev0");
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].predicate.to_string(), "dip: 192.168.1.0/24");
        assert_eq!(rules[0].priority, 24);
        assert_eq!(base.encode(rules[0].action), 4);
        assert_eq!(rules[1].predicate.to_string(), "dip: 0.0.0.0/0");
        assert_eq!(rules[1].priority, 0);
        assert_eq!(base.encode(rules[1].action), 2);
    }

    #[test]
    fn test_action_encoder() {
        let loader = DefaultInstLoader::default();
        let content = r#"
        name dev0
        neighbor ge0 dev1
        neighbor ge1 dev2
        port gi0 ecmp ge0 ge1
        port gi1 flood ge0 ge1
        "#;
        let base = loader.load(content).unwrap();
        let a0 = base.encode(TypedAction::Default);
        let a1 = base.encode(TypedAction::Typed(TypedActionInner {
            idx: 1,
            origin: &base,
        }));
        let a2 = base.encode(TypedAction::Typed(TypedActionInner {
            idx: 2,
            origin: &base,
        }));
        let a3 = base.encode(TypedAction::Typed(TypedActionInner {
            idx: 3,
            origin: &base,
        }));
        let a4 = base.encode(TypedAction::Typed(TypedActionInner {
            idx: 4,
            origin: &base,
        }));
        assert_eq!(a0, 0);
        assert_eq!(a1, 1);
        assert_eq!(a2, 2);
        assert_eq!(a3, 3);
        assert_eq!(a4, 4);
        assert_eq!(base.decode(a0).get_type(), ActionType::DROP);
        assert_eq!(base.decode(a1).get_type(), ActionType::DROP);
        assert_eq!(base.decode(a2).get_type(), ActionType::FORWARD);
        assert_eq!(base.decode(a3).get_type(), ActionType::FORWARD);
        assert_eq!(base.decode(a4).get_type(), ActionType::ECMP);
        assert!(base.decode(a4).get_next_hops().contains(&"dev2"));
    }
}
