use std::{
    borrow::Borrow,
    cell::{RefCell, UnsafeCell},
    collections::HashSet,
    fmt::Debug,
    hash::{Hash, Hasher},
    ptr::NonNull,
    rc::Rc,
};

use fxhash::FxBuildHasher;
use indexmap::IndexSet;
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

/// [NeighborInfo] keeps the mapping of the physical port to the neighbor device.
#[derive(Debug)]
struct NeighborInfo {
    p_port: Rc<str>,
    neighbor: Rc<str>,
    #[allow(dead_code)]
    external: bool,
}

impl PartialEq for NeighborInfo {
    fn eq(&self, other: &Self) -> bool {
        self.p_port == other.p_port
    }
}

impl Eq for NeighborInfo {}

impl Hash for NeighborInfo {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.p_port.hash(state);
    }
}

impl Borrow<str> for NeighborInfo {
    fn borrow(&self) -> &str {
        &self.p_port
    }
}

/// [PortInfo] keeps the mapping of a port to a group of physical ports and corresponding
/// neighbors.
#[derive(Debug)]
struct PortInfo {
    name: String,
    mode: ActionType,
    p_ports: Vec<Rc<str>>,   // physical port names, reference to NeighborInfo
    neighbors: Vec<Rc<str>>, // neighbor names, reference to NeighborInfo
}

impl PartialEq for PortInfo {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for PortInfo {}

impl Hash for PortInfo {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
    }
}

impl Borrow<str> for PortInfo {
    fn borrow(&self) -> &str {
        &self.name
    }
}

#[derive(Clone, Copy)]
pub struct TypedActionInner<'a> {
    idx: usize,
    origin: &'a PortInfoBase,
}

impl Debug for TypedActionInner<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TypedActionInner")
            .field("idx", &self.idx)
            .finish()
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum TypedAction<'a> {
    Typed(TypedActionInner<'a>),
    Drop,
    NonOverwrite,
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

impl<'a> Action<Single> for TypedAction<'a> {
    type S = Self;

    fn drop_action() -> Self {
        TypedAction::Drop
    }

    fn no_overwrite() -> Self {
        TypedAction::NonOverwrite
    }

    fn overwritten(&self, rhs: &Self) -> Self {
        match rhs {
            TypedAction::NonOverwrite => *self,
            _ => *rhs,
        }
    }
}

impl<'a> UncodedAction for TypedAction<'a> {
    fn get_type(&self) -> ActionType {
        match self {
            TypedAction::NonOverwrite => ActionType::DROP,
            TypedAction::Drop => ActionType::DROP,
            TypedAction::Typed(t) => t.origin.ports.borrow().get_index(t.idx).unwrap().mode,
        }
    }

    fn get_next_hops(&self) -> Option<impl IntoIterator<Item = &Rc<str>>> {
        match self {
            TypedAction::NonOverwrite => None,
            TypedAction::Drop => None,
            TypedAction::Typed(t) => {
                let ports = NonNull::new(t.origin.ports.as_ptr()).unwrap();
                let port_info = unsafe { ports.as_ref().get_index(t.idx).unwrap() };
                Some(port_info.p_ports.iter())
            }
        }
    }
}

/// [PortInfoBase] stores the information of a device's ports and neighbors.
///
/// Lifetime 'a is used to sync the lifetime of [PortInfo] and [NeighborInfo], bacause [PortInfo]
/// stores references to data inside [NeighborInfo] to avoid duplication.
#[derive(Debug)]
pub struct PortInfoBase {
    #[allow(dead_code)]
    dev: String,
    // port name -> neighbor info
    #[allow(dead_code)]
    nbrs: RefCell<HashSet<NeighborInfo, FxBuildHasher>>,
    // port name -> port info
    ports: RefCell<IndexSet<PortInfo, FxBuildHasher>>,
}

impl<'a> ActionEncoder<'a> for PortInfoBase {
    type A = usize;
    type UA = TypedAction<'a>;

    #[inline]
    fn encode(&'a self, action: Self::UA) -> usize {
        match action {
            TypedAction::NonOverwrite => 0,
            TypedAction::Drop => 1,
            TypedAction::Typed(t) => t.idx,
        }
    }

    #[inline]
    fn decode(&'a self, coded_action: usize) -> Self::UA {
        match coded_action {
            0 => TypedAction::NonOverwrite,
            1 => TypedAction::Drop,
            _ => TypedAction::Typed(TypedActionInner {
                idx: coded_action,
                origin: self,
            }),
        }
    }

    fn lookup(&'a self, port_name: &str) -> Option<Self::UA> {
        // since A == 0 means no overwrite, we can't use 0 as CodedAction
        match self.ports.borrow().get_full(port_name) {
            Some((idx, _)) => match idx {
                0 => Some(TypedAction::NonOverwrite),
                1 => Some(TypedAction::Drop),
                _ => Some(TypedAction::Typed(TypedActionInner { idx, origin: self })),
            },
            None => {
                let mut ports = NonNull::new(self.ports.as_ptr()).unwrap();
                let mut nbrs = NonNull::new(self.nbrs.as_ptr()).unwrap();
                let port_name: Rc<str> = Rc::from(port_name);
                unsafe {
                    nbrs.as_mut().insert(NeighborInfo {
                        p_port: port_name.clone(),
                        neighbor: port_name.clone(),
                        external: true,
                    });
                    let (idx, _) = ports.as_mut().insert_full(PortInfo {
                        name: port_name.to_string(),
                        mode: ActionType::FORWARD,
                        p_ports: vec![port_name.clone()],
                        neighbors: vec![port_name],
                    });
                    Some(TypedAction::Typed(TypedActionInner { idx, origin: self }))
                }
            }
        }
    }
}

#[derive(Default)]
pub struct DefaultInstLoader {}

impl<'a> InstanceLoader<'a, PortInfoBase> for DefaultInstLoader {
    fn _load<'x, E: ParseError<&'x str>>(&self, content: &'x str) -> IResult<(), PortInfoBase, E> {
        let nbrs = UnsafeCell::new(HashSet::with_hasher(FxBuildHasher::default()));
        let ports = UnsafeCell::new(vec![
            PortInfo {
                name: "no_overwrite_place_holder".to_owned(),
                mode: ActionType::DROP,
                p_ports: vec![],
                neighbors: vec![],
            },
            PortInfo {
                name: "default_drop".to_owned(),
                mode: ActionType::DROP,
                p_ports: vec![],
                neighbors: vec![],
            },
        ]);

        let capture_nbr_info = |(port_name, nbr): (&str, NeighborInfo)| {
            let nbrs_mut = unsafe { &mut *nbrs.get() };
            let ports_mut = unsafe { &mut *ports.get() };
            nbrs_mut.insert(nbr);
            let nbr = nbrs_mut.get(port_name).unwrap();
            ports_mut.push(PortInfo {
                name: port_name.to_owned(),
                mode: ActionType::FORWARD,
                p_ports: vec![nbr.p_port.clone()],
                neighbors: vec![],
            });
        };
        let capture_port_info = |port: PortInfo| {
            let nbrs_mut = unsafe { &mut *nbrs.get() };
            let ports_mut = unsafe { &mut *ports.get() };
            // use reference of p_port in nbrs
            let p_ports_in_map = port
                .p_ports
                .iter()
                .map(|s| nbrs_mut.get(s.as_ref()).unwrap().p_port.clone())
                .collect();
            ports_mut.push(PortInfo {
                name: port.name,
                mode: port.mode,
                p_ports: p_ports_in_map,
                neighbors: vec![],
            })
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

        let nbrs_mut = unsafe { &mut *nbrs.get() };
        let ports_mut = unsafe { &mut *ports.get() };
        // fill in neighbors of PortInfo in ports
        for port_info in ports_mut.iter_mut() {
            for p_port_name in &port_info.p_ports {
                if let Some(p_port) = nbrs_mut.get(p_port_name.as_ref()) {
                    port_info.neighbors.push(p_port.neighbor.clone());
                }
            }
        }
        let ports = IndexSet::<PortInfo, FxBuildHasher>::from_iter(ports.into_inner());
        Ok((
            (),
            PortInfoBase {
                dev: dev.to_string(),
                nbrs: RefCell::new(nbrs.into_inner()),
                ports: RefCell::new(ports),
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
    Ok((
        rest,
        PortInfo {
            name: port.to_owned(),
            mode,
            p_ports: ports.into_iter().map(Rc::from).collect(),
            neighbors: vec![],
        },
    ))
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
                p_port: Rc::from(port),
                neighbor: Rc::from(nbr),
                external: false,
            },
        ),
    ))
}

// implement for PortInfoBase::A (Coded Action)
impl<'a> FibLoader<'a, usize> for PortInfoBase {
    fn _load<'x, 'p, PE, Err>(
        &'a self,
        engine: &'p PE,
        content: &'x str,
    ) -> IResult<(), (String, Vec<Rule<PE::P, usize>>), Err>
    where
        PE: PredicateEngine<'p>,
        Err: ParseError<&'x str>,
        'a: 'p,
        'p: 'a,
    {
        let (rest, dev) = delimited(multispace0, parse_dev, multispace1)(content)?;
        let (rest, rules) = separated_list0(multispace1, parse_ipv4_rule(engine, self))(rest)?;
        let (_, _) = all_consuming(multispace0)(rest)?;
        Ok(((), (dev.to_owned(), rules)))
    }
}

// implement for PortInfoBase::A (Uncoded Action)
impl<'a> FibLoader<'a, TypedAction<'a>> for PortInfoBase {
    fn _load<'x, 'p, PE, Err>(
        &'a self,
        engine: &'p PE,
        content: &'x str,
    ) -> IResult<(), (String, Vec<Rule<PE::P, TypedAction<'a>>>), Err>
    where
        PE: PredicateEngine<'p>,
        Err: ParseError<&'x str>,
        'a: 'p,
        'p: 'a,
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
fn parse_ipv4_rule<'x, 'a, 'p, PE, AE, E>(
    engine: &'p PE,
    action_encoder: &'a AE,
) -> impl Fn(&'x str) -> IResult<&'x str, Rule<PE::P, AE::A>, E> + 'p + 'a
where
    PE: PredicateEngine<'p>,
    AE: ActionEncoder<'a>,
    E: ParseError<&'x str>,
    'a: 'p,
    'p: 'a,
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
        let action = action_encoder.encode(action_encoder.lookup(port_name).unwrap());
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
        let action = action_encoder.lookup(port_name).unwrap();
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
        assert_eq!(base.nbrs.borrow().len(), 2);
        assert_eq!(base.ports.borrow().len(), 6);

        let nbrs = &base.nbrs.borrow();
        let n1 = nbrs.get("ge0").unwrap();
        assert_eq!(n1.neighbor.as_ref(), "dev1");
        assert!(!n1.external);
        let n2 = nbrs.get("ge1").unwrap();
        assert_eq!(n2.neighbor.as_ref(), "dev2");
        assert!(!n2.external);

        let ports = &base.ports.borrow();

        // index 0 is for no overwrite action
        let p0 = ports.get_index(1).unwrap();
        assert_eq!(p0.name, "default_drop");
        assert_eq!(p0.mode, ActionType::DROP);
        assert_eq!(p0.p_ports.len(), 0);
        let p1 = ports.get_index(2).unwrap();
        assert_eq!(p1.name, "ge0");
        assert_eq!(p1.mode, ActionType::FORWARD);
        assert_eq!(p1.p_ports.len(), 1);
        assert_eq!(p1.p_ports[0].as_ref(), "ge0");
        let p2 = ports.get_index(3).unwrap();
        assert_eq!(p2.name, "ge1");
        assert_eq!(p2.mode, ActionType::FORWARD);
        assert_eq!(p2.p_ports.len(), 1);
        assert_eq!(p2.p_ports[0].as_ref(), "ge1");
        let p3 = ports.get_index(4).unwrap();
        assert_eq!(p3.name, "gi0");
        assert_eq!(p3.mode, ActionType::ECMP);
        assert_eq!(p3.p_ports.len(), 2);
        assert_eq!(p3.p_ports[0].as_ref(), "ge0");
        assert_eq!(p3.p_ports[1].as_ref(), "ge1");
        let p4 = ports.get_index(5).unwrap();
        assert_eq!(p4.name, "gi1");
        assert_eq!(p4.mode, ActionType::FLOOD);
        assert_eq!(p4.p_ports.len(), 2);
        assert_eq!(p4.p_ports[0].as_ref(), "ge0");
        assert_eq!(p4.p_ports[1].as_ref(), "ge1");

        let fib = r#"
        name dev0
        fw 192.168.1.0 24 24 gi0
        fw 0.0.0.0 0 0 ge0
        "#;
        let engine = RuddyPredicateEngine::init(1000, 100, Inet4Family);
        let (dev, rules) = FibLoader::<usize>::load(&base, &engine, fib).unwrap();
        let rules: Vec<_> = rules.into_iter().collect();
        assert_eq!(dev, "dev0");
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].predicate.to_string(), "dip: 192.168.1.0/24");
        assert_eq!(rules[0].priority, 24);
        assert_eq!(rules[0].action, 4);
        assert_eq!(rules[1].predicate.to_string(), "dip: 0.0.0.0/0");
        assert_eq!(rules[1].priority, 0);
        assert_eq!(rules[1].action, 2);
        let (dev, rules) = FibLoader::<TypedAction>::load(&base, &engine, fib).unwrap();
        let rules: Vec<_> = rules.into_iter().collect();
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
        let a0 = base.encode(TypedAction::NonOverwrite);
        let a1 = base.encode(TypedAction::Drop);
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
        let a5 = base.encode(TypedAction::Typed(TypedActionInner {
            idx: 5,
            origin: &base,
        }));
        assert_eq!(a0, 0);
        assert_eq!(a1, 1);
        assert_eq!(a2, 2);
        assert_eq!(a3, 3);
        assert_eq!(a4, 4);
        assert_eq!(a5, 5);
        assert_eq!(base.decode(a0).get_type(), ActionType::DROP);
        assert_eq!(base.decode(a1).get_type(), ActionType::DROP);
        assert_eq!(base.decode(a2).get_type(), ActionType::FORWARD);
        assert_eq!(base.decode(a3).get_type(), ActionType::FORWARD);
        assert_eq!(base.decode(a4).get_type(), ActionType::ECMP);
        assert_eq!(base.decode(a5).get_type(), ActionType::FLOOD);
        assert_eq!(
            base.decode(a4)
                .get_next_hops()
                .unwrap()
                .into_iter()
                .collect::<Vec<_>>()
                .len(),
            2
        );
    }
}
