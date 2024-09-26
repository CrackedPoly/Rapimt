use std::{
    cell::RefCell,
    cmp::Ordering,
    fmt::{Debug, Display, Result as FmtResult},
    hash::Hash,
    io::Result as IoResult,
    str::from_utf8,
};

use funty::Unsigned;
use ruddy::{Bdd, BddIO, BddManager, BddOp, PrintSet, Ruddy};

use crate::r#match::{
    family::constant, FieldMatch, Match, MatchEncoder, Predicate, PredicateEngine, PredicateInner,
};

/// The RuddyPredicateEngine is a predicate engine based on the
/// [Ruddy](https://github.com/CrackedPoly/RuDDy) BDD library.
pub struct RuddyPredicateEngine {
    pub manager: RefCell<Ruddy>,
    var_pair: [(Bdd, Bdd); constant::MAX_POS + 1],

    #[cfg(feature = "dip")]
    pub dip_varset_pair: (Bdd, Bdd),

    #[cfg(feature = "sip")]
    pub sip_varset_pair: (Bdd, Bdd),

    #[cfg(feature = "dport")]
    pub dport_varset_pair: (Bdd, Bdd),

    #[cfg(feature = "sport")]
    pub sport_varset_pair: (Bdd, Bdd),

    #[cfg(feature = "tag")]
    pub tag_varset_pair: (Bdd, Bdd),
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
    pub fn init(node_num: usize, cache_size: usize) -> Self {
        let mut manager = Ruddy::init(node_num as u32, cache_size as u32, constant::MAX_POS as u32);
        let mut var_pair = [(Bdd::default(), Bdd::default()); constant::MAX_POS + 1];

        var_pair[0] = (manager.get_true(), manager.get_false());
        for (i, pair) in var_pair[1..]
            .iter_mut()
            .rev()
            .enumerate()
            .take(constant::MAX_POS)
        {
            *pair = (manager.get_var(i as u16), manager.get_nvar(i as u16));
        }

        #[cfg(feature = "dip")]
        let (dip_varset, not_dip_varset) = {
            let (from, to) = constant::FIELD_MAP.get("dip").unwrap();
            let mut dip_varset = var_pair[0].0;
            let mut not_dip_varset = var_pair[0].0;
            let mut tmp: Bdd;
            for i in 0..constant::MAX_POS {
                if i >= *from && i < *to {
                    tmp = manager.and(dip_varset, var_pair[i + 1].0);
                    manager.deref_bdd(dip_varset);
                    dip_varset = manager.ref_bdd(tmp);
                } else {
                    tmp = manager.and(not_dip_varset, var_pair[i + 1].0);
                    manager.deref_bdd(not_dip_varset);
                    not_dip_varset = manager.ref_bdd(tmp);
                }
            }
            (dip_varset, not_dip_varset)
        };

        #[cfg(feature = "sip")]
        let (sip_varset, not_sip_varset) = {
            let (from, to) = constant::FIELD_MAP.get("sip").unwrap();
            let mut sip_varset = var_pair[0].0;
            let mut not_sip_varset = var_pair[0].0;
            let mut tmp: Bdd;
            for i in 0..constant::MAX_POS {
                if i >= *from && i < *to {
                    tmp = manager.and(sip_varset, var_pair[i + 1].0);
                    manager.deref_bdd(sip_varset);
                    sip_varset = manager.ref_bdd(tmp);
                } else {
                    tmp = manager.and(not_sip_varset, var_pair[i + 1].0);
                    manager.deref_bdd(not_sip_varset);
                    not_sip_varset = manager.ref_bdd(tmp);
                }
            }
            (sip_varset, not_sip_varset)
        };

        #[cfg(feature = "dport")]
        let (dport_varset, not_dport_varset) = {
            let (from, to) = constant::FIELD_MAP.get("dport").unwrap();
            let mut dport_varset = var_pair[0].0;
            let mut not_dport_varset = var_pair[0].0;
            let mut tmp: Bdd;
            for i in 0..constant::MAX_POS {
                if i >= *from && i < *to {
                    tmp = manager.and(dport_varset, var_pair[i + 1].0);
                    manager.deref_bdd(dport_varset);
                    dport_varset = manager.ref_bdd(tmp);
                } else {
                    tmp = manager.and(not_dport_varset, var_pair[i + 1].0);
                    manager.deref_bdd(not_dport_varset);
                    not_dport_varset = manager.ref_bdd(tmp);
                }
            }
            (dport_varset, not_dport_varset)
        };

        #[cfg(feature = "sport")]
        let (sport_varset, not_sport_varset) = {
            let (from, to) = constant::FIELD_MAP.get("sport").unwrap();
            let mut sport_varset = var_pair[0].0;
            let mut not_sport_varset = var_pair[0].0;
            let mut tmp: Bdd;
            for i in 0..constant::MAX_POS {
                if i >= *from && i < *to {
                    tmp = manager.and(sport_varset, var_pair[i + 1].0);
                    manager.deref_bdd(sport_varset);
                    sport_varset = manager.ref_bdd(tmp);
                } else {
                    tmp = manager.and(not_sport_varset, var_pair[i + 1].0);
                    manager.deref_bdd(not_sport_varset);
                    not_sport_varset = manager.ref_bdd(tmp);
                }
            }
            (sport_varset, not_sport_varset)
        };

        #[cfg(feature = "tag")]
        let (tag_varset, not_tag_varset) = {
            let (from, to) = constant::FIELD_MAP.get("tag").unwrap();
            let mut tag_varset = var_pair[0].0;
            let mut not_tag_varset = var_pair[0].0;
            let mut tmp: Bdd;
            for i in 0..constant::MAX_POS {
                if i >= *from && i < *to {
                    tmp = manager.and(tag_varset, var_pair[i + 1].0);
                    manager.deref_bdd(tag_varset);
                    tag_varset = manager.ref_bdd(tmp);
                } else {
                    tmp = manager.and(not_tag_varset, var_pair[i + 1].0);
                    manager.deref_bdd(not_tag_varset);
                    not_tag_varset = manager.ref_bdd(tmp);
                }
            }
            (tag_varset, not_tag_varset)
        };

        Self {
            manager: RefCell::new(manager),
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
        }
    }
}

impl<'a> MatchEncoder<'a> for RuddyPredicateEngine {
    type P = RuddyPredicate<'a>;

    #[inline]
    fn gc(&self) -> usize {
        self.manager.borrow_mut().gc()
    }

    #[inline]
    fn one(&'a self) -> Predicate<Self::P> {
        Predicate::from(RuddyPredicate {
            bdd: self.var_pair[0].0,
            engine: self,
        })
    }

    #[inline]
    fn zero(&'a self) -> Predicate<Self::P> {
        Predicate::from(RuddyPredicate {
            bdd: self.var_pair[0].1,
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
        let mut bdd = self.var_pair[0].0;
        let (mut tmp, mut offset, mut imasked, mut ivalue): (Bdd, usize, bool, bool);
        for i in from..to {
            offset = i - from;
            imasked = ((mask >> offset) & U::ONE) == U::ONE;
            ivalue = ((value >> offset) & U::ONE) == U::ONE;
            tmp = if imasked {
                if ivalue {
                    self.var_pair[i + 1].0
                } else {
                    self.var_pair[i + 1].1
                }
            } else {
                self.var_pair[0].0
            };

            tmp = self.manager.borrow_mut().and(bdd, tmp);
            self.manager.borrow_mut().deref_bdd(bdd);
            bdd = self.manager.borrow_mut().ref_bdd(tmp);
        }

        Predicate::from(RuddyPredicate { bdd, engine: self })
    }
}

impl<'a> PredicateEngine<'a> for RuddyPredicateEngine {
    fn read_buffer(&'a self, mut buffer: &[u8]) -> IoResult<Predicate<Self::P>> {
        let bdd =
            BddIO::<Vec<u8>, &[u8]>::deserialize(&mut *self.manager.borrow_mut(), &mut buffer)?;
        Ok(Predicate::from(RuddyPredicate { bdd, engine: self }))
    }

    fn write_buffer(&'a self, pred: &Predicate<Self::P>, buffer: &mut Vec<u8>) -> IoResult<()> {
        BddIO::<Vec<u8>, &[u8]>::serialize(&*self.manager.borrow_mut(), pred.0.bdd, buffer)?;
        Ok(())
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
        let bdd = self
            .manager
            .borrow_mut()
            .exist(before.0.bdd, self.dip_varset_pair.0);
        Predicate::from(RuddyPredicate { bdd, engine: self })
    }

    #[cfg(feature = "dip")]
    fn erase_except_dip(&'a self, before: &Predicate<Self::P>) -> Predicate<Self::P> {
        let bdd = self
            .manager
            .borrow_mut()
            .exist(before.0.bdd, self.dip_varset_pair.1);
        Predicate::from(RuddyPredicate { bdd, engine: self })
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
        let bdd = self
            .manager
            .borrow_mut()
            .exist(before.0.bdd, self.sip_varset_pair.0);
        Predicate::from(RuddyPredicate { bdd, engine: self })
    }

    #[cfg(feature = "sip")]
    fn erase_except_sip(&'a self, before: &Predicate<Self::P>) -> Predicate<Self::P> {
        let bdd = self
            .manager
            .borrow_mut()
            .exist(before.0.bdd, self.sip_varset_pair.1);
        Predicate::from(RuddyPredicate { bdd, engine: self })
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
        let bdd = self
            .manager
            .borrow_mut()
            .exist(before.0.bdd, self.dport_varset_pair.0);
        Predicate::from(RuddyPredicate { bdd, engine: self })
    }

    #[cfg(feature = "dport")]
    fn erase_except_dport(&'a self, before: &Predicate<Self::P>) -> Predicate<Self::P> {
        let bdd = self
            .manager
            .borrow_mut()
            .exist(before.0.bdd, self.dport_varset_pair.1);
        Predicate::from(RuddyPredicate { bdd, engine: self })
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
        let bdd = self
            .manager
            .borrow_mut()
            .exist(before.0.bdd, self.sport_varset_pair.0);
        Predicate::from(RuddyPredicate { bdd, engine: self })
    }

    #[cfg(feature = "sport")]
    fn erase_except_sport(&'a self, before: &Predicate<Self::P>) -> Predicate<Self::P> {
        let bdd = self
            .manager
            .borrow_mut()
            .exist(before.0.bdd, self.sport_varset_pair.1);
        Predicate::from(RuddyPredicate { bdd, engine: self })
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
        let bdd = self
            .manager
            .borrow_mut()
            .exist(before.0.bdd, self.tag_varset_pair.0);
        Predicate::from(RuddyPredicate { bdd, engine: self })
    }

    #[cfg(feature = "tag")]
    fn erase_except_tag(&'a self, before: &Predicate<Self::P>) -> Predicate<Self::P> {
        let bdd = self
            .manager
            .borrow_mut()
            .exist(before.0.bdd, self.tag_varset_pair.1);
        Predicate::from(RuddyPredicate { bdd, engine: self })
    }
}

#[derive(Copy, Clone)]
pub struct RuddyPredicate<'a> {
    pub bdd: Bdd,
    pub engine: &'a RuddyPredicateEngine,
}

impl PartialEq<Self> for RuddyPredicate<'_> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.bdd == other.bdd
    }
}

impl Eq for RuddyPredicate<'_> {}

impl Ord for RuddyPredicate<'_> {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.bdd.cmp(&other.bdd)
    }
}

impl PartialOrd<Self> for RuddyPredicate<'_> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Hash for RuddyPredicate<'_> {
    #[inline]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.bdd.hash(state);
    }
}

impl PredicateInner for RuddyPredicate<'_> {
    #[inline]
    fn not(&self) -> Self {
        let bdd = self.engine.manager.borrow_mut().not(self.bdd);
        RuddyPredicate {
            bdd,
            engine: self.engine,
        }
    }

    #[inline]
    fn and(&self, rhs: &Self) -> Self {
        let bdd = self.engine.manager.borrow_mut().and(self.bdd, rhs.bdd);
        RuddyPredicate {
            bdd,
            engine: self.engine,
        }
    }

    #[inline]
    fn or(&self, rhs: &Self) -> Self {
        let bdd = self.engine.manager.borrow_mut().or(self.bdd, rhs.bdd);
        RuddyPredicate {
            bdd,
            engine: self.engine,
        }
    }

    #[inline]
    fn comp(&self, rhs: &Self) -> Self {
        let bdd = self.engine.manager.borrow_mut().comp(self.bdd, rhs.bdd);
        RuddyPredicate {
            bdd,
            engine: self.engine,
        }
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.bdd == self.engine.manager.borrow().get_false()
    }

    #[inline]
    fn _ref(self) -> Self {
        self.engine.manager.borrow_mut().ref_bdd(self.bdd);
        self
    }

    #[inline]
    fn _deref(&self) {
        self.engine.manager.borrow_mut().deref_bdd(self.bdd);
    }
}

impl Display for RuddyPredicate<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> FmtResult {
        let mut buffer = vec![];
        if self
            .engine
            .manager
            .borrow()
            .print(self.bdd, &mut buffer)
            .is_ok()
        {
            if let Ok(str) = from_utf8(&buffer) {
                write!(f, "{}", str)
            } else {
                Err(std::fmt::Error)
            }
        } else {
            Err(std::fmt::Error)
        }
    }
}

impl Debug for RuddyPredicate<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> FmtResult {
        writeln!(f)?;
        writeln!(f, "Ruddy Predicate print in set:")?;
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
    use crate::prelude::MaskedValue;
    use crate::r#match::{macros::ipv4_to_match, FieldMatch, Match};
    use crate::{fm_exact_from, fm_ipv4_from, fm_range_from};
    use std::fmt::Write;

    use super::*;

    fn assert_on_field(field: &str, mv: &MaskedValue, pred: &Predicate<RuddyPredicate<'_>>) {
        let mut actual = String::new();
        let mut expected = String::new();

        let (from, to) = constant::FIELD_MAP.get(field).unwrap();
        let max_pos = constant::MAX_POS;

        write!(&mut actual, "{}", pred).unwrap();
        write!(&mut expected, "{}", mv).unwrap();

        for split in actual.split('\n') {
            if split.is_empty() {
                continue;
            }
            assert_eq!(
                split[max_pos - to..max_pos - from],
                expected[max_pos - to..max_pos - from]
            );
        }
    }

    #[test]
    #[cfg(feature = "dip")]
    fn test_ruddy_not() {
        let engine = RuddyPredicateEngine::init(1000, 100);
        let (p, _) = engine.encode_match(fm_ipv4_from!("dip", "192.168.0.0/24"));
        let not = !p;

        let newline_cnt = not.to_string().matches("\n").count();
        assert_eq!(newline_cnt, 23 + 1);
    }

    #[test]
    #[cfg(feature = "dip")]
    fn test_ruddy_or() {
        let engine = RuddyPredicateEngine::init(1000, 100);

        let (dip_from, dip_to) = constant::FIELD_MAP.get("dip").unwrap();

        let (mut p0, _) = engine.encode_match(fm_ipv4_from!("dip", "192.168.0.0/24"));
        let (p1, _) = engine.encode_match(fm_ipv4_from!("dip", "192.168.1.0/24"));
        p0 |= p1;

        // "192.168.0.0/23"
        let expected_mv =
            MaskedValue::store((192u32 << 24) | (168 << 16), 0xfffffe00, *dip_from, *dip_to);

        assert_on_field("dip", &expected_mv, &p0);
    }

    #[test]
    #[cfg(feature = "dip")]
    fn test_ruddy_and() {
        let engine = RuddyPredicateEngine::init(1000, 100);

        let (mut p0, _) = engine.encode_match(fm_ipv4_from!("dip", "192.168.1.0/24"));
        let (p1, mvs) = engine.encode_match(fm_ipv4_from!("dip", "192.168.1.0/28"));
        p0 &= p1;

        // "192.168.1.0/28"
        assert_on_field("dip", &mvs[0], &p0);
    }

    #[test]
    #[cfg(feature = "dip")]
    fn test_ruddy_comp() {
        let engine = RuddyPredicateEngine::init(1000, 100);

        let (dip_from, dip_to) = constant::FIELD_MAP.get("dip").unwrap();

        let (mut p0, _) = engine.encode_match(fm_ipv4_from!("dip", "192.168.0.0/23"));
        let (p1, _) = engine.encode_match(fm_ipv4_from!("dip", "192.168.0.0/24"));
        p0 -= p1;

        // "192.168.1.0/24"
        let expected_mv = MaskedValue::store(
            (192u32 << 24) | (168 << 16) | (1 << 8),
            0xffffff00,
            *dip_from,
            *dip_to,
        );
        assert_on_field("dip", &expected_mv, &p0)
    }

    #[test]
    #[cfg(all(feature = "dip", feature = "tag"))]
    fn test_ruddy_dip_modifier() {
        let engine = RuddyPredicateEngine::init(1000, 100);

        let (dip_from, dip_to) = constant::FIELD_MAP.get("dip").unwrap();
        let (tag_from, tag_to) = constant::FIELD_MAP.get("tag").unwrap();

        // basic check: encoding is correct
        let (p0, mvs) = engine.encode_matches([
            fm_ipv4_from!("dip", "192.168.0.0/24"),
            fm_exact_from!("tag", 2),
        ]);
        assert_on_field("dip", &mvs[0], &p0);
        assert_on_field("tag", &mvs[0], &p0);

        // erase the dip to 0/0
        let p1 = engine.erase_dip(&p0);
        let expected_mv = MaskedValue::store(0u32, 0, *dip_from, *dip_to);
        assert_on_field("dip", &expected_mv, &p1);

        // rewrite the dip to 10.0.0.0/24
        let p1 = engine.rewrite_dip(&p1, ipv4_to_match("10.0.0.0/24"));
        let expected_mv = MaskedValue::store(10u32 << 24, 0xffffff00, *dip_from, *dip_to);
        assert_on_field("dip", &expected_mv, &p1);

        // erase all other fields to 0/0
        let p1 = engine.erase_except_dip(&p1);
        let expected_mv = MaskedValue::store(0u32, 0, *tag_from, *tag_to);
        assert_on_field("tag", &expected_mv, &p1);

        // while 10.0.0.0/24 is still there, rewrite dip to 255.255.255.0/32
        let p1 = engine.rewrite_dip(&p1, ipv4_to_match("255.255.255.0/32"));
        let expected_mv = MaskedValue::store(0xffffff00u32, 0xffffffff, *dip_from, *dip_to);
        assert_on_field("dip", &expected_mv, &p1);
    }

    #[test]
    #[cfg(all(feature = "dport", feature = "sport"))]
    fn test_range_encode() {
        let engine = RuddyPredicateEngine::init(1000, 100);
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
        let (_, mvs) = engine.encode_matches(vec![fm0, fm1]);
        assert_eq!(mvs.len(), 16);
    }
}
