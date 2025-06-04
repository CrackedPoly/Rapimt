use std::{
    cmp::Ordering,
    fmt::{Debug, Display, Result as FmtResult},
    hash::Hash,
    io::Result as IoResult,
};

use funty::Unsigned;
use oxidd::{
    bdd::{BDDFunction, BDDManagerRef},
    BooleanFunction, BooleanFunctionQuant, Manager, ManagerRef,
};

use crate::r#match::{
    engine::{MatchEncoder, PredicateEngine},
    family::constant,
    predicate::{Predicate, PredicateInner},
    raw_match::{FieldMatch, Match},
};

/// A predicate engine based on the [oxidd](https://github.com/OxiDD/oxidd) library.
pub struct OxiddPredicateEngine {
    pub manager_ref: BDDManagerRef,
    var_pair: Vec<(BDDFunction, BDDFunction)>,

    #[cfg(feature = "dip")]
    pub dip_varset_pair: (BDDFunction, BDDFunction),

    #[cfg(feature = "sip")]
    pub sip_varset_pair: (BDDFunction, BDDFunction),

    #[cfg(feature = "dport")]
    pub dport_varset_pair: (BDDFunction, BDDFunction),

    #[cfg(feature = "sport")]
    pub sport_varset_pair: (BDDFunction, BDDFunction),

    #[cfg(feature = "tag")]
    pub tag_varset_pair: (BDDFunction, BDDFunction),

    #[cfg(feature = "lid")]
    pub lid_varset_pair: (BDDFunction, BDDFunction),
}

impl OxiddPredicateEngine {
    /// Initialize the OxiddPredicateEngine with the given node_num, cache_size
    /// and family. As to the concrete number of these parameters, node_num
    /// does not need to be very large, it will grow inside automatically when
    /// needed. Cache_size grows along with node_num, but be aware that the
    /// ratio ```cache_size / node_num``` is fixed while growing. So choose a
    /// good ratio is more important.
    /// # Recommendation
    /// For recommendation, call ```init(1000, 100, family)``` to start with.
    pub fn init(node_num: usize, cache_size: usize) -> Self {
        // though we enable multi-threading, we set num_thread to 1
        let manager_ref = oxidd::bdd::new_manager(node_num, cache_size, 1);
        let mut var_pair = vec![];

        manager_ref.with_manager_exclusive(|manager| {
            var_pair.push((BDDFunction::t(manager), BDDFunction::f(manager)))
        });
        for _ in 0..constant::MAX_POS {
            let v = manager_ref
                .with_manager_exclusive(|manager| BDDFunction::new_var(manager).unwrap());
            let nv = v.not().unwrap();
            var_pair.push((v, nv));
        }

        #[cfg(feature = "dip")]
        let (dip_varset, not_dip_varset) = {
            let (from, to) = constant::FIELD_MAP.get("dip").unwrap();
            let mut dip_varset = var_pair[0].0.clone();
            let mut not_dip_varset = var_pair[0].0.clone();
            for i in 0..constant::MAX_POS {
                if i >= *from && i < *to {
                    dip_varset = dip_varset.and(&var_pair[i + 1].0).unwrap();
                } else {
                    not_dip_varset = not_dip_varset.and(&var_pair[i + 1].0).unwrap();
                }
            }
            (dip_varset, not_dip_varset)
        };

        #[cfg(feature = "sip")]
        let (sip_varset, not_sip_varset) = {
            let (from, to) = constant::FIELD_MAP.get("sip").unwrap();
            let mut sip_varset = var_pair[0].0.clone();
            let mut not_sip_varset = var_pair[0].0.clone();
            for i in 0..constant::MAX_POS {
                if i >= *from && i < *to {
                    sip_varset = sip_varset.and(&var_pair[i + 1].0).unwrap();
                } else {
                    not_sip_varset = not_sip_varset.and(&var_pair[i + 1].0).unwrap();
                }
            }
            (sip_varset, not_sip_varset)
        };

        #[cfg(feature = "dport")]
        let (dport_varset, not_dport_varset) = {
            let (from, to) = constant::FIELD_MAP.get("dport").unwrap();
            let mut dport_varset = var_pair[0].0.clone();
            let mut not_dport_varset = var_pair[0].0.clone();
            for i in 0..constant::MAX_POS {
                if i >= *from && i < *to {
                    dport_varset = dport_varset.and(&var_pair[i + 1].0).unwrap();
                } else {
                    not_dport_varset = not_dport_varset.and(&var_pair[i + 1].0).unwrap();
                }
            }
            (dport_varset, not_dport_varset)
        };

        #[cfg(feature = "sport")]
        let (sport_varset, not_sport_varset) = {
            let (from, to) = constant::FIELD_MAP.get("sport").unwrap();
            let mut sport_varset = var_pair[0].0.clone();
            let mut not_sport_varset = var_pair[0].0.clone();
            for i in 0..constant::MAX_POS {
                if i >= *from && i < *to {
                    sport_varset = sport_varset.and(&var_pair[i + 1].0).unwrap();
                } else {
                    not_sport_varset = not_sport_varset.and(&var_pair[i + 1].0).unwrap();
                }
            }
            (sport_varset, not_sport_varset)
        };

        #[cfg(feature = "tag")]
        let (tag_varset, not_tag_varset) = {
            let (from, to) = constant::FIELD_MAP.get("tag").unwrap();
            let mut tag_varset = var_pair[0].0.clone();
            let mut not_tag_varset = var_pair[0].0.clone();
            for i in 0..constant::MAX_POS {
                if i >= *from && i < *to {
                    tag_varset = tag_varset.and(&var_pair[i + 1].0).unwrap();
                } else {
                    not_tag_varset = not_tag_varset.and(&var_pair[i + 1].0).unwrap();
                }
            }
            (tag_varset, not_tag_varset)
        };

        #[cfg(feature = "lid")]
        let (lid_varset, not_lid_varset) = {
            let (from, to) = constant::FIELD_MAP.get("lid").unwrap();
            let mut lid_varset = var_pair[0].0.clone();
            let mut not_lid_varset = var_pair[0].0.clone();
            for i in 0..constant::MAX_POS {
                if i >= *from && i < *to {
                    lid_varset = lid_varset.and(&var_pair[i + 1].0).unwrap();
                } else {
                    not_lid_varset = not_lid_varset.and(&var_pair[i + 1].0).unwrap();
                }
            }
            (lid_varset, not_lid_varset)
        };

        Self {
            manager_ref,
            var_pair,

            #[cfg(feature = "dip")]
            dip_varset_pair: (dip_varset, not_dip_varset),
            #[cfg(feature = "sip")]
            sip_varset_pair: (sip_varset, not_sip_varset),
            #[cfg(feature = "dport")]
            dport_varset_pair: (dport_varset, not_dport_varset),
            #[cfg(feature = "sport")]
            sport_varset_pair: (sport_varset, not_sport_varset),
            #[cfg(feature = "tag")]
            tag_varset_pair: (tag_varset, not_tag_varset),
            #[cfg(feature = "lid")]
            lid_varset_pair: (lid_varset, not_lid_varset),
        }
    }
}

impl<'a> Default for OxiddPredicateEngine {
    fn default() -> Self {
        Self::init(1000, 100)
    }
}

impl<'a> MatchEncoder<'a> for OxiddPredicateEngine {
    type P = OxiddPredicate<'a>;

    #[inline]
    fn gc(&self) -> usize {
        self.manager_ref
            .with_manager_exclusive(|manager| manager.gc())
    }

    #[inline]
    fn one(&'a self) -> Predicate<Self::P> {
        Predicate::from(OxiddPredicate {
            bdd: self.var_pair[0].0.clone(),
            engine: self,
        })
    }

    #[inline]
    fn zero(&'a self) -> Predicate<Self::P> {
        Predicate::from(OxiddPredicate {
            bdd: self.var_pair[0].1.clone(),
            engine: self,
        })
    }

    fn _encode<U: Unsigned>(
        &'a self,
        value: U,
        mask: U,
        from: usize,
        to: usize,
    ) -> Predicate<Self::P> {
        let mut bdd = self.var_pair[0].0.clone();
        let (mut tmp, mut offset, mut imasked, mut ivalue): (&BDDFunction, usize, bool, bool);
        for i in from..to {
            offset = i - from;
            imasked = ((mask >> offset) & U::ONE) == U::ONE;
            ivalue = ((value >> offset) & U::ONE) == U::ONE;
            tmp = if imasked {
                if ivalue {
                    &self.var_pair[i + 1].0
                } else {
                    &self.var_pair[i + 1].1
                }
            } else {
                &self.var_pair[0].0
            };

            bdd = bdd.and(tmp).unwrap();
        }

        Predicate::from(OxiddPredicate { bdd, engine: self })
    }
}

impl<'a> PredicateEngine<'a> for OxiddPredicateEngine {
    fn read_buffer(&'a self, mut _buffer: &[u8]) -> IoResult<Predicate<Self::P>> {
        unimplemented!()
    }

    fn write_buffer(&'a self, _pred: &Predicate<Self::P>, _buffer: &mut Vec<u8>) -> IoResult<()> {
        unimplemented!()
    }

    #[cfg(feature = "dip")]
    fn rewrite_dip(&'a self, before: &Predicate<Self::P>, m: Match<u32>) -> Predicate<Self::P> {
        self.encode_match_wo_mv(FieldMatch {
            field: "dip",
            cond: m,
        }) & self.erase_dip(before)
    }

    #[cfg(feature = "dip")]
    fn erase_dip(&'a self, before: &Predicate<Self::P>) -> Predicate<Self::P> {
        let bdd = BDDFunction::exist(&before.0.bdd, &self.dip_varset_pair.0).unwrap();
        Predicate::from(OxiddPredicate { bdd, engine: self })
    }

    #[cfg(feature = "dip")]
    fn erase_except_dip(&'a self, before: &Predicate<Self::P>) -> Predicate<Self::P> {
        let bdd = BDDFunction::exist(&before.0.bdd, &self.dip_varset_pair.1).unwrap();
        Predicate::from(OxiddPredicate { bdd, engine: self })
    }

    #[cfg(feature = "sip")]
    fn rewrite_sip(&'a self, before: &Predicate<Self::P>, m: Match<u32>) -> Predicate<Self::P> {
        self.encode_match_wo_mv(FieldMatch {
            field: "sip",
            cond: m,
        }) & self.erase_sip(before)
    }

    #[cfg(feature = "sip")]
    fn erase_sip(&'a self, before: &Predicate<Self::P>) -> Predicate<Self::P> {
        let bdd = BDDFunction::exist(&before.0.bdd, &self.sip_varset_pair.0).unwrap();
        Predicate::from(OxiddPredicate { bdd, engine: self })
    }

    #[cfg(feature = "sip")]
    fn erase_except_sip(&'a self, before: &Predicate<Self::P>) -> Predicate<Self::P> {
        let bdd = BDDFunction::exist(&before.0.bdd, &self.sip_varset_pair.1).unwrap();
        Predicate::from(OxiddPredicate { bdd, engine: self })
    }

    #[cfg(feature = "dport")]
    fn rewrite_dport(&'a self, before: &Predicate<Self::P>, m: Match<u16>) -> Predicate<Self::P> {
        self.encode_match_wo_mv(FieldMatch {
            field: "dport",
            cond: m,
        }) & self.erase_dport(before)
    }

    #[cfg(feature = "dport")]
    fn erase_dport(&'a self, before: &Predicate<Self::P>) -> Predicate<Self::P> {
        let bdd = BDDFunction::exist(&before.0.bdd, &self.dport_varset_pair.0).unwrap();
        Predicate::from(OxiddPredicate { bdd, engine: self })
    }

    #[cfg(feature = "dport")]
    fn erase_except_dport(&'a self, before: &Predicate<Self::P>) -> Predicate<Self::P> {
        let bdd = BDDFunction::exist(&before.0.bdd, &self.dport_varset_pair.1).unwrap();
        Predicate::from(OxiddPredicate { bdd, engine: self })
    }

    #[cfg(feature = "sport")]
    fn rewrite_sport(&'a self, before: &Predicate<Self::P>, m: Match<u16>) -> Predicate<Self::P> {
        self.encode_match_wo_mv(FieldMatch {
            field: "sport",
            cond: m,
        }) & self.erase_sport(before)
    }

    #[cfg(feature = "sport")]
    fn erase_sport(&'a self, before: &Predicate<Self::P>) -> Predicate<Self::P> {
        let bdd = BDDFunction::exist(&before.0.bdd, &self.sport_varset_pair.0).unwrap();
        Predicate::from(OxiddPredicate { bdd, engine: self })
    }

    #[cfg(feature = "sport")]
    fn erase_except_sport(&'a self, before: &Predicate<Self::P>) -> Predicate<Self::P> {
        let bdd = BDDFunction::exist(&before.0.bdd, &self.sport_varset_pair.1).unwrap();
        Predicate::from(OxiddPredicate { bdd, engine: self })
    }

    #[cfg(feature = "tag")]
    fn rewrite_tag(&'a self, before: &Predicate<Self::P>, m: Match<u16>) -> Predicate<Self::P> {
        self.encode_match_wo_mv(FieldMatch {
            field: "tag",
            cond: m,
        }) & self.erase_tag(before)
    }

    #[cfg(feature = "tag")]
    fn erase_tag(&'a self, before: &Predicate<Self::P>) -> Predicate<Self::P> {
        let bdd = BDDFunction::exist(&before.0.bdd, &self.tag_varset_pair.0).unwrap();
        Predicate::from(OxiddPredicate { bdd, engine: self })
    }

    #[cfg(feature = "tag")]
    fn erase_except_tag(&'a self, before: &Predicate<Self::P>) -> Predicate<Self::P> {
        let bdd = BDDFunction::exist(&before.0.bdd, &self.tag_varset_pair.1).unwrap();
        Predicate::from(OxiddPredicate { bdd, engine: self })
    }
}

/// Companion struct of [OxiddPredicateEngine].
#[derive(Clone)]
pub struct OxiddPredicate<'a> {
    pub bdd: BDDFunction,
    pub engine: &'a OxiddPredicateEngine,
}

impl PartialEq<Self> for OxiddPredicate<'_> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.bdd == other.bdd
    }
}

impl Eq for OxiddPredicate<'_> {}

impl Ord for OxiddPredicate<'_> {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.bdd.cmp(&other.bdd)
    }
}

impl PartialOrd<Self> for OxiddPredicate<'_> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Hash for OxiddPredicate<'_> {
    #[inline]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.bdd.hash(state);
    }
}

impl PredicateInner for OxiddPredicate<'_> {
    #[inline]
    fn not(&self) -> Self {
        OxiddPredicate {
            bdd: self.bdd.not().unwrap(),
            engine: self.engine,
        }
    }

    #[inline]
    fn and(&self, rhs: &Self) -> Self {
        OxiddPredicate {
            bdd: self.bdd.and(&rhs.bdd).unwrap(),
            engine: self.engine,
        }
    }

    #[inline]
    fn or(&self, rhs: &Self) -> Self {
        OxiddPredicate {
            bdd: self.bdd.or(&rhs.bdd).unwrap(),
            engine: self.engine,
        }
    }

    #[inline]
    fn comp(&self, rhs: &Self) -> Self {
        // note:
        // imp: lhs → rhs = ¬lhs ∨ rhs
        // strict imp: lhs < rhs = ¬lhs ∧ rhs
        OxiddPredicate {
            bdd: rhs.bdd.imp_strict(&self.bdd).unwrap(),
            engine: self.engine,
        }
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.bdd == self.engine.var_pair[0].1
    }

    #[inline]
    fn _ref(self) -> Self {
        self
    }

    #[inline]
    fn _deref(&self) {}
}

impl Display for OxiddPredicate<'_> {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> FmtResult {
        unimplemented!()
    }
}

impl Debug for OxiddPredicate<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> FmtResult {
        writeln!(f)?;
        writeln!(f, "Oxidd Predicate print in set:")?;
        #[cfg(feature = "dip")]
        write!(f, "{:-^31}|", "dst_ip")?;
        #[cfg(feature = "sip")]
        write!(f, "{:-^31}|", "src_ip")?;
        #[cfg(feature = "dport")]
        write!(f, "{:-^15}|", "dst_port")?;
        #[cfg(feature = "sport")]
        write!(f, "{:-^15}|", "src_port")?;
        #[cfg(feature = "tag")]
        write!(f, "{:-^15}|", "tag")?;
        writeln!(f)?;
        writeln!(f, "{}", self)
    }
}

#[cfg(test)]
mod tests {
    use crate::r#match::raw_match::{macros::ipv4_to_match, FieldMatch, Match};
    use crate::{fm_ipv4_from, fm_range_from};

    use oxidd::util::AllocResult;

    use super::*;

    #[test]
    fn test_oxidd() -> AllocResult<()> {
        let manager_ref = oxidd::bdd::new_manager(1024, 1024, 1);
        let (x1, x2, x3) = manager_ref.with_manager_exclusive(|manager| {
            (
                BDDFunction::new_var(manager).unwrap(),
                BDDFunction::new_var(manager).unwrap(),
                BDDFunction::new_var(manager).unwrap(),
            )
        });

        let res = x1.and(&x2)?.or(&x3)?;
        println!("{}", res.satisfiable());
        Ok(())
    }

    #[test]
    #[cfg(feature = "dip")]
    fn test_oxidd_not() {
        let engine = OxiddPredicateEngine::init(1000, 100);
        let (p, _) = engine.encode_match(fm_ipv4_from!("dip", "128.0.0.0/1"));
        let (not_p, _) = engine.encode_match(fm_ipv4_from!("dip", "0.0.0.0/1"));
        assert_eq!(!p, not_p);
    }

    #[test]
    #[cfg(feature = "dip")]
    fn test_oxidd_or() {
        let engine = OxiddPredicateEngine::init(1000, 100);

        let (mut p0, _) = engine.encode_match(fm_ipv4_from!("dip", "192.168.0.0/24"));
        let (p1, _) = engine.encode_match(fm_ipv4_from!("dip", "192.168.1.0/24"));
        p0 |= p1;

        // "192.168.0.0/23"
        let (p2, _) = engine.encode_match(fm_ipv4_from!("dip", "192.168.0.0/23"));
        assert_eq!(p0, p2);
    }

    #[test]
    #[cfg(feature = "dip")]
    fn test_oxidd_and() {
        let engine = OxiddPredicateEngine::init(1000, 100);

        let (mut p0, _) = engine.encode_match(fm_ipv4_from!("dip", "192.168.1.0/24"));
        let (p1, _) = engine.encode_match(fm_ipv4_from!("dip", "192.168.1.0/28"));
        p0 &= &p1;

        // "192.168.1.0/28"
        assert_eq!(p0, p1);
    }

    #[test]
    #[cfg(feature = "dip")]
    fn test_oxidd_comp() {
        let engine = OxiddPredicateEngine::init(1000, 100);

        let (mut p0, _) = engine.encode_match(fm_ipv4_from!("dip", "192.168.0.0/23"));
        let (p1, _) = engine.encode_match(fm_ipv4_from!("dip", "192.168.0.0/24"));
        p0 -= p1;

        // "192.168.1.0/24"
        let (p2, _) = engine.encode_match(fm_ipv4_from!("dip", "192.168.1.0/24"));
        assert_eq!(p0, p2);
    }

    #[test]
    #[cfg(all(feature = "dip", feature = "tag"))]
    fn test_oxidd_dip_modifier() {}

    #[test]
    #[cfg(all(feature = "dport", feature = "sport"))]
    fn test_range_encode() {
        let engine = OxiddPredicateEngine::init(1000, 100);
        let fm0 = fm_range_from!("sport", 123u16, 147u16);
        let (_, mvs) = engine.encode_match(fm0);
        // 0b00000000_01111011/16 -> 123
        // 0b00000000_011111xx/14 -> 124-127
        // 0b00000000_1000xxxx/12 -> 128-143
        // 0b00000000_100100xx/14 -> 144-147
        // range from 123 to 147 is encoded to 4 prefixes, kind of performance pitfall compared to
        // ip ternary match
        assert_eq!(mvs.len(), 4);

        let fm0 = fm_range_from!("sport", 123u16, 147u16);
        let fm1 = fm_range_from!("dport", 123u16, 147u16);
        let (_, mvs) = engine.encode_matches(&vec![fm0, fm1]);
        assert_eq!(mvs.len(), 16);
    }
}
