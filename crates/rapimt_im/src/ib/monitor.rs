use crate::ib::rule::Rule;
use crate::im::{IbVecMonoid, MapMonoid};
use crate::{InverseModel, RuleMonitorLike};
use fxhash::{FxBuildHasher, FxHashMap};
use rapimt_core::prelude::{Action, Dimension, MatchEncoder, Predicate, Single};
use std::collections::{BTreeSet, HashMap};

pub struct IbRuleMonitor<'p, A, ME>
where
    A: Action<Single>,
    ME: MatchEncoder<'p>,
{
    #[allow(unused)]
    engine: &'p ME,

    i_rules: Vec<Rule<ME::P, A>>,
    d_rules: Vec<Rule<ME::P, A>>,
    default_rule: Rule<ME::P, A>,

    /// store of rules
    store: BTreeSet<Rule<ME::P, A>>,
    tmp_ow: FxHashMap<A, Predicate<ME::P>>,
}

impl<'p, A, OA, T, ME, S>
    RuleMonitorLike<A, OA, T, MapMonoid<OA, Predicate<ME::P>, S>, ME::P, Rule<ME::P, A>>
    for IbRuleMonitor<'p, A, ME>
where
    A: Action<Single>,
    OA: Action<T, S = A>,
    T: Dimension,
    ME: MatchEncoder<'p>,
    S: std::hash::BuildHasher + std::clone::Clone + std::default::Default,
{
    fn clear(&mut self) {
        self.i_rules.clear();
        self.d_rules.clear();
        self.store.clear();
        self.store.insert(self.default_rule.clone());
    }

    /// Invariant: predicate of any two rules in insertion and deletion respectively should not
    /// overlap.
    fn update(
        &mut self,
        insertion: impl IntoIterator<Item = Rule<ME::P, A>>,
        deletion: impl IntoIterator<Item = Rule<ME::P, A>>,
    ) -> InverseModel<OA, ME::P, T, MapMonoid<OA, Predicate<ME::P>, S>> {
        self.tmp_ow.clear();
        let mut p0 = self.engine.one();
        for r in deletion {
            if self.store.remove(&r) {
                self.d_rules.push(r);
            }
        }
        for r in insertion {
            if self.store.insert(r.clone()) {
                self.i_rules.push(r);
            }
        }
        for r in &self.d_rules {
            self.tmp_ow
                .entry(r.action.clone())
                .and_modify(|mut p| p |= &self.default_rule.predicate)
                .or_insert(r.predicate.clone());
            p0 -= &r.predicate;
        }
        for r in &self.i_rules {
            self.tmp_ow
                .entry(r.action.clone())
                .and_modify(|mut p| p |= &r.predicate)
                .or_insert(r.predicate.clone());
            p0 -= &r.predicate;
        }
        self.tmp_ow.insert(A::no_overwrite(), p0);
        InverseModel::from(self.tmp_ow.drain().map(|(a, p)| (OA::from_single(a), p)))
    }
}

impl<'p, A, OA, T, ME>
    RuleMonitorLike<A, OA, T, IbVecMonoid<(OA, Predicate<ME::P>)>, ME::P, Rule<ME::P, A>>
    for IbRuleMonitor<'p, A, ME>
where
    A: Action<Single>,
    OA: Action<T, S = A>,
    T: Dimension,
    ME: MatchEncoder<'p>,
{
    fn clear(&mut self) {
        self.i_rules.clear();
        self.d_rules.clear();
        self.store.clear();
        self.store.insert(self.default_rule.clone());
    }

    /// Invariant: predicate of any two rules in insertion and deletion respectively should not
    /// overlap.
    fn update(
        &mut self,
        insertion: impl IntoIterator<Item = Rule<ME::P, A>>,
        deletion: impl IntoIterator<Item = Rule<ME::P, A>>,
    ) -> InverseModel<OA, ME::P, T, IbVecMonoid<(OA, Predicate<ME::P>)>> {
        for r in deletion {
            self.store.remove(&r);
        }
        for r in insertion {
            self.store.insert(r.clone());
        }
        let entries = self.store.iter().cloned().map(|r| (r.action, r.predicate));
        InverseModel::from(entries.map(|(a, p)| (OA::from_single(a), p)))
    }
}

impl<'p, A, ME> IbRuleMonitor<'p, A, ME>
where
    A: Action<Single>,
    ME: MatchEncoder<'p>,
{
    pub fn new(engine: &'p ME) -> Self {
        // this is the default rule of every forwarding device
        let default_rule = Rule {
            action: A::default_action(),
            predicate: engine.one(),
            lid: Default::default(),
        };
        IbRuleMonitor {
            engine,
            i_rules: vec![],
            d_rules: vec![],
            default_rule,
            store: BTreeSet::new(),
            tmp_ow: HashMap::with_hasher(FxBuildHasher::default()),
        }
    }
}
