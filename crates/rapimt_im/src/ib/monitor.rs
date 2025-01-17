use crate::ib::rule::Rule;
use crate::{im::InverseModelMonoid, InverseModel, RuleMonitorLike};
use fxhash::{FxBuildHasher, FxHashMap, FxHashSet};
use rapimt_core::prelude::{Action, Dimension, MatchEncoder, Predicate, Single};
use std::collections::{HashMap, HashSet};

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
    store: FxHashSet<Rule<ME::P, A>>,
    tmp_ow: FxHashMap<A, Predicate<ME::P>>,
}

impl<'p, A, ME> RuleMonitorLike<A, ME::P, Rule<ME::P, A>> for IbRuleMonitor<'p, A, ME>
where
    A: Action<Single>,
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
    fn update<OA: Action<T, S = A>, T: Dimension, M: InverseModelMonoid<OA, ME::P, T>>(
        &mut self,
        insertion: impl IntoIterator<Item = Rule<ME::P, A>>,
        deletion: impl IntoIterator<Item = Rule<ME::P, A>>,
    ) -> InverseModel<OA, ME::P, T, M> {
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
        let im = InverseModel::<OA, ME::P, T, M>::from(
            self.tmp_ow.drain().map(|(a, p)| (OA::from_single(a), p)),
        );
        im
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
        };
        IbRuleMonitor {
            engine,
            i_rules: vec![],
            d_rules: vec![],
            default_rule,
            store: HashSet::with_hasher(FxBuildHasher::default()),
            tmp_ow: HashMap::with_hasher(FxBuildHasher::default()),
        }
    }
}
