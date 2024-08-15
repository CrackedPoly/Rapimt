use std::{
    cell::RefCell,
    cmp::Ordering,
    fmt::{Debug, Display, Formatter},
    hash::Hash,
};

use ruddy::{Bdd, BddIO, BddManager, BddOp, PrintSet, Ruddy};

use crate::r#match::{
    family::{FamilyDecl, MatchFamily},
    {MatchEncoder, Predicate, PredicateEngine, PredicateInner},
};

/// The RuddyPredicateEngine is a predicate engine based on the
/// [Ruddy](https://github.com/CrackedPoly/RuDDy) BDD library.
pub struct RuddyPredicateEngine {
    manager: RefCell<Ruddy>,
    var_pair: Vec<(Bdd, Bdd)>,
    family: MatchFamily,
}

impl RuddyPredicateEngine {
    /// Initialize the RuddyPredicateEngine with the given node_num, cache_size
    /// and family. As to the concrete number of these parameters, node_num
    /// does not need to be very large, it will grow inside automatically when
    /// needed. Cache_size grows along with node_num, but be aware that the
    /// ratio ```cache_size / node_num``` is fixed while growing. So choose a
    /// good ratio is more important.
    /// # Recommendation
    /// For recommendation, call ```init(1000, 100, family)``` to start with.
    pub fn init(node_num: usize, cache_size: usize, family: MatchFamily) -> Self {
        let mut engine = Self {
            manager: RefCell::new(Ruddy::init(node_num as u32, cache_size as u32, family.get_max_pos() as u32)),
            var_pair: Vec::new(),
            family: MatchFamily::Inet4Family,
        };
        let mut pairs = vec![(
            engine.manager.borrow().get_true(),
            engine.manager.borrow().get_false(),
        )];
        (0..family.get_max_pos()).rev().for_each(|i| {
            pairs.push((
                engine.manager.borrow().get_var(i as u16),
                engine.manager.borrow().get_nvar(i as u16),
            ));
        });
        engine.var_pair = pairs;
        engine.family = family;
        engine
    }
}

impl<'a> MatchEncoder<'a> for RuddyPredicateEngine {
    type P = RuddyPredicate<'a>;

    fn gc(&self) -> Option<usize> {
        self.manager.borrow_mut().gc()
    }

    fn one(&'a self) -> Predicate<Self::P> {
        Predicate::new(RuddyPredicate {
            bdd: self.var_pair[0].0,
            engine: self,
        })
    }

    fn zero(&'a self) -> Predicate<Self::P> {
        Predicate::new(RuddyPredicate {
            bdd: self.var_pair[0].1,
            engine: self,
        })
    }

    fn family(&self) -> &MatchFamily {
        &self.family
    }

    fn _encode(&'a self, value: u128, mask: u128, from: u32, to: u32) -> Predicate<Self::P> {
        let bdd = (from..=to)
            .map(|i| {
                let offset = i - from;
                let imasked = ((mask >> offset) & 1) == 1;
                let ivalue = ((value >> offset) & 1) == 1;
                if imasked {
                    if ivalue {
                        self.var_pair[i as usize + 1].0
                    } else {
                        self.var_pair[i as usize + 1].1
                    }
                } else {
                    self.var_pair[0].0
                }
            })
            .fold(self.var_pair[0].0, |acc, y| {
                self.manager.borrow_mut().and(&acc, &y)
            });
        Predicate::new(RuddyPredicate { bdd, engine: self })
    }
}

impl<'a> PredicateEngine<'a, RuddyPredicate<'a>> for RuddyPredicateEngine {
    fn read_buffer(&'a self, buffer: &Vec<u8>) -> Option<Predicate<Self::P>> {
        let bdd = self.manager.borrow_mut().read_buffer(buffer);
        if let Some(bdd) = bdd {
            self.manager.borrow_mut().ref_bdd(&bdd);
            Some(Predicate::new(RuddyPredicate { bdd, engine: self }))
        } else {
            None
        }
    }

    fn write_buffer(&'a self, pred: &Predicate<Self::P>, buffer: &mut Vec<u8>) -> Option<usize> {
        self.manager.borrow_mut().write_buffer(&pred.0.bdd, buffer)
    }
}

#[derive(Copy, Clone)]
pub struct RuddyPredicate<'a> {
    bdd: Bdd,
    pub engine: &'a RuddyPredicateEngine,
}

impl PartialEq<Self> for RuddyPredicate<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.bdd == other.bdd
    }
}

impl Eq for RuddyPredicate<'_> {}

impl Ord for RuddyPredicate<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.bdd.cmp(&other.bdd)
    }
}

impl PartialOrd<Self> for RuddyPredicate<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Hash for RuddyPredicate<'_> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.bdd.hash(state);
    }
}

impl PredicateInner for RuddyPredicate<'_> {
    fn not(&self) -> Self {
        let bdd = self.engine.manager.borrow_mut().not(&self.bdd);
        RuddyPredicate {
            bdd,
            engine: self.engine,
        }
    }

    fn and(&self, rhs: &Self) -> Self {
        let bdd = self.engine.manager.borrow_mut().and(&self.bdd, &rhs.bdd);
        RuddyPredicate {
            bdd,
            engine: self.engine,
        }
    }

    fn or(&self, rhs: &Self) -> Self {
        let bdd = self.engine.manager.borrow_mut().or(&self.bdd, &rhs.bdd);
        RuddyPredicate {
            bdd,
            engine: self.engine,
        }
    }

    fn comp(&self, rhs: &Self) -> Self {
        let bdd = self.engine.manager.borrow_mut().comp(&self.bdd, &rhs.bdd);
        RuddyPredicate {
            bdd,
            engine: self.engine,
        }
    }

    fn is_empty(&self) -> bool {
        self.bdd == self.engine.manager.borrow().get_false()
    }

    fn _ref(self) -> Self {
        self.engine.manager.borrow_mut().ref_bdd(&self.bdd);
        self
    }

    fn _deref(&self) {
        self.engine.manager.borrow_mut().deref_bdd(&self.bdd);
    }
}

impl Display for RuddyPredicate<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        fn to_prefix(str: String, offset: usize) -> String {
            if str == "TRUE\n" {
                return "0.0.0.0/0".to_string();
            } else if str == "FALSE\n" {
                return "None".to_string();
            }
            // remove tailing '\n'
            let str = str.trim_end();
            return if str.contains('\n') {
                let ss: Vec<String> = str.split('\n').map(|s| s.to_string()).collect();
                let ps: Vec<String> = ss
                    .iter()
                    .map(|s| to_prefix(s.to_string(), offset))
                    .collect();
                ps.join(" OR ")
            } else {
                let prefix_str: &str = &str[offset..offset + 32];
                let last_one = prefix_str.rfind('1').unwrap_or(0);
                let last_zero = prefix_str.rfind('0').unwrap_or(0);
                let prefix_len = last_one.max(last_zero) + 1;
                if let Some(t) = prefix_str[0..prefix_len].find('-') {
                    let mut zero = String::from(prefix_str);
                    let mut one = String::from(prefix_str);
                    zero.replace_range(t..t + 1, "0");
                    one.replace_range(t..t + 1, "1");
                    to_prefix(zero, offset).to_owned() + " OR " + to_prefix(one, offset).as_str()
                } else {
                    let real_prefix_str = prefix_str.replace('-', "0");
                    let first = u8::from_str_radix(&real_prefix_str[0..8], 2).unwrap();
                    let second = u8::from_str_radix(&real_prefix_str[8..16], 2).unwrap();
                    let third = u8::from_str_radix(&real_prefix_str[16..24], 2).unwrap();
                    let fourth = u8::from_str_radix(&real_prefix_str[24..32], 2).unwrap();
                    format!(
                        "{:}.{:}.{:}.{:}/{:}",
                        first, second, third, fourth, prefix_len
                    )
                }
            };
        }

        let mut s = String::new();
        self.engine.manager.borrow().print(&mut s, &self.bdd)?;
        match self.engine.family {
            MatchFamily::Inet4Family => f.write_fmt(format_args!("dip: {}", to_prefix(s, 0)))?,
            MatchFamily::TcpT4Family => {
                f.write_fmt(format_args!("dip only: {}", to_prefix(s, 0)))?
            }
        }
        Ok(())
    }
}

impl Debug for RuddyPredicate<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}", self))
    }
}

#[cfg(test)]
mod tests {
    use crate::r#match::{macros::ipv4_to_match, FieldMatch, Match};
    use crate::{fm_ipv4_from, fm_range_from};

    use super::*;

    #[test]
    #[allow(unused_variables)]
    fn test_ruddy_encode() {
        // 1. choose the family and initialize the engine
        let family = MatchFamily::Inet4Family;
        let engine = RuddyPredicateEngine::init(100, 10, family);

        // 2. encode the field value to get a predicate
        let fv = fm_ipv4_from!("dip", "3232235776/24");
        let (pred, _) = engine.encode_match(fv);
        assert_eq!(pred.to_string(), "dip: 192.168.1.0/24");

        let fv = fm_ipv4_from!("dip", "192.168.1.0/24");
        let (pred, _) = engine.encode_match(fv);
        assert_eq!(pred.to_string(), "dip: 192.168.1.0/24");
    }

    #[test]
    fn test_ruddy_not() {
        let family = MatchFamily::Inet4Family;
        let engine = RuddyPredicateEngine::init(100, 10, family);
        let (p, _) = engine.encode_match(fm_ipv4_from!("dip", "192.168.0.0/24"));
        let not = !p;
        let times_or = not.to_string().matches("OR").count();
        assert_eq!(times_or, 23);
    }

    #[test]
    fn test_ruddy_or() {
        let family = MatchFamily::Inet4Family;
        let engine = RuddyPredicateEngine::init(100, 10, family);
        let (mut p0, _) = engine.encode_match(fm_ipv4_from!("dip", "192.168.0.0/24"));
        let (p1, _) = engine.encode_match(fm_ipv4_from!("dip", "192.168.1.0/24"));
        p0 |= p1;
        assert_eq!(p0.to_string(), "dip: 192.168.0.0/23");
    }

    #[test]
    fn test_ruddy_and() {
        let family = MatchFamily::Inet4Family;
        let engine = RuddyPredicateEngine::init(100, 10, family);
        let (mut p0, _) = engine.encode_match(fm_ipv4_from!("dip", "192.168.1.0/24"));
        let (p1, _) = engine.encode_match(fm_ipv4_from!("dip", "192.168.1.0/28"));
        p0 &= p1;
        assert_eq!(p0.to_string(), "dip: 192.168.1.0/28");
    }

    #[test]
    fn test_ruddy_comp() {
        let family = MatchFamily::Inet4Family;
        let engine = RuddyPredicateEngine::init(100, 10, family);
        let (mut p0, _) = engine.encode_match(fm_ipv4_from!("dip", "192.168.0.0/23"));
        let (p1, _) = engine.encode_match(fm_ipv4_from!("dip", "192.168.0.0/24"));
        p0 -= p1;
        assert_eq!(p0.to_string(), "dip: 192.168.1.0/24");
    }

    #[test]
    fn test_ruddy_gc() {
        let family = MatchFamily::Inet4Family;
        let engine = RuddyPredicateEngine::init(100, 10, family);
        let (mut p0, _) = engine.encode_match(fm_ipv4_from!("dip", "64.0.0.0/2"));
        let (p1, _) = engine.encode_match(fm_ipv4_from!("dip", "192.0.0.0/2"));

        engine.gc();
        p0 |= p1;
        let freed = engine.gc().unwrap();
        // p1 is mutated to -1------..., aka the 2nd positive variable, so both
        // "64.0.0.0/2" and "192.0.0.0/2" are freed
        assert_eq!(freed, 2);
    }

    #[test]
    fn test_range_encode() {
        let family = MatchFamily::TcpT4Family;
        let engine = RuddyPredicateEngine::init(100, 10, family);
        let fm0 = fm_range_from!("sport", 123, 147);
        let (_, mvs) = engine.encode_match(fm0);
        assert_eq!(mvs.len(), 4);

        let fm0 = fm_range_from!("sport", 123, 147);
        let fm1 = fm_range_from!("dport", 123, 147);
        let (_, mvs) = engine.encode_matches(vec![fm0, fm1]);
        assert_eq!(mvs.len(), 16);
    }
}
