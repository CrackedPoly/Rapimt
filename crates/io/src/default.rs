use std::cell::RefCell;

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
    action::{ActionEncoder, ActionType, UncodedAction},
    r#match::{FieldMatch, Match, PredicateEngine, PredicateInner, Rule},
};

use crate::{
    basic::parser::{parse_digits, parse_ident, parse_ipv4_dotted, parse_ipv4_num},
    {FibLoader, InstanceLoader},
};

#[allow(dead_code)]
#[derive(Debug)]
struct NeighborInfo {
    name: String,
    external: bool,
}

#[derive(Debug)]
struct PortInfo {
    name: String,
    mode: ActionType,
    p_ports: Vec<String>, // vector of physical port names
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct PortInfoBase {
    dev: String,
    // port name -> neighbor info
    nbrs: IndexMap<String, NeighborInfo>,
    // port name -> port info
    ports: RefCell<IndexMap<String, PortInfo>>,
}

pub struct TypedAction<'a> {
    idx: u32,
    origin: &'a PortInfoBase,
}

impl<'o> UncodedAction for TypedAction<'o> {
    fn get_type(&self) -> ActionType {
        self.origin
            .ports
            .borrow()
            .get_index(self.idx as usize - 1)
            .unwrap()
            .1
            .mode
    }

    fn get_next_hops(&self) -> Vec<&str> {
        self.origin
            .ports
            .borrow()
            .get_index(self.idx as usize - 1)
            .unwrap()
            .1
            .p_ports
            .iter()
            .map(|s| self.origin.nbrs.get(s).unwrap().name.as_str())
            .collect()
    }
}

impl<'a> ActionEncoder<'a> for PortInfoBase {
    type UA = TypedAction<'a>;

    fn encode(&'a self, action: Self::UA) -> u32 {
        action.idx
    }

    fn decode(&'a self, coded_action: u32) -> Self::UA {
        TypedAction {
            idx: coded_action,
            origin: self,
        }
    }

    fn lookup(&'a self, port_name: &str) -> Self::UA {
        // since A == 0 means no overwrite, we can't use 0 as CodedAction
        let res = self
            .ports
            .borrow()
            .get_full(port_name)
            .map(|(idx, _, _)| TypedAction {
                idx: idx as u32 + 1,
                origin: self,
            });
        match res {
            Some(a) => a,
            None => {
                let idx = self
                    .ports
                    .borrow_mut()
                    .insert_full(
                        port_name.to_owned(),
                        PortInfo {
                            name: port_name.to_owned(),
                            mode: ActionType::FORWARD,
                            p_ports: vec![port_name.to_owned()],
                        },
                    )
                    .0;
                TypedAction {
                    idx: idx as u32 + 1,
                    origin: self,
                }
            }
        }
    }
}

#[derive(Default)]
pub struct DefaultInstLoader {}

impl<'o> InstanceLoader<'o, PortInfoBase, TypedAction<'o>> for DefaultInstLoader {
    fn _load<'x, E: ParseError<&'x str>>(&self, content: &'x str) -> IResult<(), PortInfoBase, E> {
        let nbrs = RefCell::new(IndexMap::new());
        let ports = RefCell::new(IndexMap::new());
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
                ports,
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

pub fn parse_port<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, &'a str, E> {
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

impl<'a, 'p, P: PredicateInner + 'p> FibLoader<'a, 'p, P> for PortInfoBase {
    fn _load<'x, 's: 'p, ME, Err>(
        &'s self,
        engine: &'p ME,
        content: &'x str,
    ) -> IResult<(), (String, Vec<Rule<P, u32>>), Err>
    where
        ME: PredicateEngine<'p, P>,
        Err: ParseError<&'x str>,
    {
        let (rest, dev) = delimited(multispace0, parse_dev, multispace1)(content)?;
        let (rest, rules) = separated_list0(multispace1, parse_ipv4_rule(engine, self))(rest)?;
        let (_, _) = all_consuming(multispace0)(rest)?;
        Ok(((), (dev.to_owned(), rules)))
    }
}

/// Returns a closure that parses an IPv4 rule and returns a [Rule] instance.
/// The closure have the lifetime of MatchEncoder's 'p and ActionEncoder's 'a,
/// where 'a == 'p.
fn parse_ipv4_rule<'x, 'a: 'p, 'p: 'a, ME, AE, P, E>(
    engine: &'p ME,
    action_encoder: &'a AE,
) -> impl Fn(&'x str) -> IResult<&'x str, Rule<P, u32>, E> + 'p + 'a
where
    P: PredicateInner + 'p,
    ME: PredicateEngine<'p, P>,
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
            field: "dip".to_owned(),
            cond: Match::TernaryMatch { value, mask },
        };
        let (pred, mvs) = engine.encode_match(fm);
        let action = action_encoder.encode(action_encoder.lookup(port_name));
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
    use std::borrow::Borrow;

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
        assert_eq!(base.ports.borrow().len(), 5);

        let n1 = base.nbrs.get("ge0").unwrap();
        assert_eq!(n1.name, "dev1");
        assert!(!n1.external);
        let n2 = base.nbrs.get("ge1").unwrap();
        assert_eq!(n2.name, "dev2");
        assert!(!n2.external);

        let bindings = base.ports.borrow();

        let p1 = bindings.borrow().get("ge0").unwrap();
        assert_eq!(p1.name, "ge0");
        assert_eq!(p1.mode, ActionType::FORWARD);
        assert_eq!(p1.p_ports.len(), 1);
        assert_eq!(p1.p_ports[0], "ge0");
        let p2 = bindings.borrow().get("ge1").unwrap();
        assert_eq!(p2.name, "ge1");
        assert_eq!(p2.mode, ActionType::FORWARD);
        assert_eq!(p2.p_ports.len(), 1);
        assert_eq!(p2.p_ports[0], "ge1");
        let p3 = bindings.borrow().get("gi0").unwrap();
        assert_eq!(p3.name, "gi0");
        assert_eq!(p3.mode, ActionType::ECMP);
        assert_eq!(p3.p_ports.len(), 2);
        assert_eq!(p3.p_ports[0], "ge0");
        assert_eq!(p3.p_ports[1], "ge1");
        let p4 = bindings.borrow().get("gi1").unwrap();
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
        let mut engine = RuddyPredicateEngine::default();
        engine.init(1000, 100, Inet4Family);
        let (dev, rules) = base.load(&engine, fib).unwrap();
        assert_eq!(dev, "dev0");
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].predicate.to_string(), "dip: 192.168.1.0/24");
        assert_eq!(rules[0].priority, 24);
        assert_eq!(rules[0].action, 4);
        assert_eq!(rules[1].predicate.to_string(), "dip: 0.0.0.0/0");
        assert_eq!(rules[1].priority, 0);
        assert_eq!(rules[1].action, 2);
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
        let a1 = base.encode(TypedAction {
            idx: 1,
            origin: &base,
        });
        let a2 = base.encode(TypedAction {
            idx: 2,
            origin: &base,
        });
        let a3 = base.encode(TypedAction {
            idx: 3,
            origin: &base,
        });
        let a4 = base.encode(TypedAction {
            idx: 4,
            origin: &base,
        });
        assert_eq!(a1, 1);
        assert_eq!(a2, 2);
        assert_eq!(a3, 3);
        assert_eq!(a4, 4);
        assert_eq!(base.decode(a1).idx, 1);
        assert_eq!(base.decode(a2).idx, 2);
        assert_eq!(base.decode(a3).idx, 3);
        assert_eq!(base.decode(a4).idx, 4);
        assert_eq!(base.decode(a1).get_type(), ActionType::DROP);
        assert_eq!(base.decode(a2).get_type(), ActionType::FORWARD);
        assert_eq!(base.decode(a3).get_type(), ActionType::FORWARD);
        assert_eq!(base.decode(a4).get_type(), ActionType::ECMP);
        assert!(base.decode(a4).get_next_hops().contains(&"dev2"));
    }
}
