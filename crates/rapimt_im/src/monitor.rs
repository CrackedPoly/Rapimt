use std::{cmp::Reverse, collections::HashMap, collections::HashSet, rc::Rc};

use fxhash::FxBuildHasher;
use rapimt_core::{
    action::{Action, ModelType, Single},
    r#match::{MaskedValue, MatchEncoder, Predicate, Rule},
    MAX_POS,
};
use rapimt_tpt::{Segmentizer, TernaryPatriciaTree};

use crate::{im::InverseModel, FibMonitor};

/// Default FIB Monitor
///
/// Default FIB Monitor functions as FIB storage of a forwarding device. A monitor has methods to
/// insert and delete FIB rules, and output an inverse model of the current forwarding state.
///
/// Generic parameters:
/// - `A`: Action<Single> type, which is used to represent the action of a FIB rule.
/// - `ME`: MatchEncoder type, which is used provide default "match any packet" predicate for
/// the default rule..
pub struct DefaultFibMonitor<'p, A, ME>
where
    A: Action<Single> + Clone,
    ME: MatchEncoder<'p>,
{
    engine: &'p ME,
    local_ap: HashMap<A, Predicate<ME::P>, FxBuildHasher>,
    tpt: TernaryPatriciaTree<Rc<Rule<ME::P, A>>>,
    i_rules: Vec<Rc<Rule<ME::P, A>>>,
    d_rules: Vec<Rc<Rule<ME::P, A>>>,
}

impl<'p, A, ME> FibMonitor<A, ME::P> for DefaultFibMonitor<'p, A, ME>
where
    A: Action<Single> + Default + Clone,
    ME: MatchEncoder<'p>,
{
    fn clear(&mut self) {
        self.tpt.clear();
        self.i_rules.clear();
        self.d_rules.clear();
    }

    fn update<OA, T>(
        &mut self,
        insertion: Vec<Rule<ME::P, A>>,
        deletion: Vec<Rule<ME::P, A>>,
    ) -> InverseModel<OA, ME::P, T>
    where
        OA: Action<T, S = A> + From<A>,
        T: ModelType,
    {
        insertion.into_iter().for_each(|r| {
            let r = Rc::new(r);
            self.insert_tpt(r.clone());
            self.i_rules.push(r.clone());
        });
        deletion.into_iter().for_each(|r| {
            let r = Rc::new(r);
            self.delete_tpt(r.clone());
            self.d_rules.push(r.clone());
        });
        self.refresh();
        self.current()
    }
}

impl<'p, A, ME> DefaultFibMonitor<'p, A, ME>
where
    A: Action<Single> + Default + Clone,
    ME: MatchEncoder<'p>,
{
    fn insert_tpt(&mut self, rule: Rc<Rule<ME::P, A>>) {
        rule.as_ref().origin.iter().for_each(|mv| {
            self.tpt.insert(rule.clone(), Segmentizer::from(*mv));
        });
    }

    fn delete_tpt(&mut self, rule: Rc<Rule<ME::P, A>>) {
        rule.as_ref().origin.iter().for_each(|mv| {
            self.tpt.delete(rule.clone(), Segmentizer::from(*mv));
        });
    }

    fn search_tpt(&self, rule: Rc<Rule<ME::P, A>>) -> HashSet<Rc<Rule<ME::P, A>>> {
        rule.as_ref()
            .origin
            .iter()
            .fold(HashSet::new(), |mut set, mv| {
                set.extend(self.tpt.search(rule.clone(), Segmentizer::from(*mv)));
                set
            })
    }

    pub fn new(engine: &'p ME) -> Self {
        // this is the default rule of every forwarding device
        let drop_rule = Rc::new(Rule {
            priority: -1,
            action: A::default(),
            predicate: engine.one(),
            origin: vec![MaskedValue::from((0u128, 0u128))],
        });
        let mut tpt = TernaryPatriciaTree::new(MAX_POS);
        drop_rule.as_ref().origin.iter().for_each(|mv| {
            tpt.insert(drop_rule.clone(), Segmentizer::from(*mv));
        });
        let i_rules = Vec::new();
        let d_rules = Vec::new();
        let local_ap = HashMap::with_hasher(FxBuildHasher::default());
        DefaultFibMonitor {
            engine,
            local_ap,
            tpt,
            i_rules,
            d_rules,
        }
    }

    fn refresh(&mut self) {
        self.i_rules.sort_by_key(|r| Reverse(r.priority));
        self.d_rules.sort_by_key(|r| Reverse(r.priority));
        self.local_ap.clear();
        let mut no_overwrite = self.engine.one();
        self.i_rules.clone().iter().for_each(|r| {
            let higher = self
                .search_tpt(r.clone())
                .into_iter()
                .filter(|y| y.priority > r.priority);
            let mut eff = r.predicate.clone();
            for y in higher {
                eff -= &y.predicate;
                if eff.is_empty() {
                    break;
                }
            }
            if !eff.is_empty() {
                self.local_ap
                    .entry(r.action.clone())
                    .and_modify(|mut p| p |= &eff)
                    .or_insert(eff.clone());
                no_overwrite -= &eff;
            }
        });
        self.d_rules.clone().iter().for_each(|r| {
            let (higher, lower_eq): (Vec<_>, Vec<_>) = self
                .search_tpt(r.clone())
                .into_iter()
                .partition(|y| y.priority > r.priority);
            let mut to_divide = r.predicate.clone();
            for y in &higher {
                to_divide -= &y.predicate;
                if to_divide.is_empty() {
                    break;
                }
            }
            while !to_divide.is_empty() {
                for y in &lower_eq {
                    let eff = &y.predicate & &to_divide;
                    if !eff.is_empty() {
                        self.local_ap
                            .entry(y.action.clone())
                            .and_modify(|mut p| p |= &eff)
                            .or_insert(eff.clone());
                        no_overwrite -= &eff;
                        to_divide -= &eff;
                        if to_divide.is_empty() {
                            break;
                        }
                    }
                }
            }
        });
        if !no_overwrite.is_empty() {
            self.local_ap.insert(A::default(), no_overwrite);
        }
        self.i_rules.clear();
        self.d_rules.clear();
    }

    fn current<OA, T>(&self) -> InverseModel<OA, ME::P, T>
    where
        OA: Action<T, S = A> + From<A> + From<A>,
        T: ModelType,
    {
        InverseModel::from(
            self.local_ap
                .iter()
                .map(|(a, p)| (OA::from(a.clone()), p.clone())),
        )
    }
}

#[cfg(test)]
mod tests {
    use rapimt_core::{
        action::{seq_action::SeqActions, Multiple, Single},
        r#match::{engine::RuddyPredicateEngine, family::MatchFamily},
    };
    use rapimt_io::{DefaultInstLoader, FibLoader, InstanceLoader, TypedAction};

    use crate::FibMonitor;
    use crate::{monitor::DefaultFibMonitor, InverseModel};

    #[test]
    fn test_default_fib_monitor() {
        let spec = r#"
        name dev0
        neighbor ge0 dev1
        neighbor ge1 dev2
        port gi0 ecmp ge0 ge1
        port gi1 flood ge0 ge1
        "#;
        let fib = r#"
        name dev0
        fw 192.168.1.0 24 24 gi0
        fw 0.0.0.0 1 1 ge0
        "#;
        // load port information
        let loader = DefaultInstLoader::default();
        let codex = InstanceLoader::load(&loader, spec).unwrap();

        // load fibs
        let family = MatchFamily::Inet4Family;
        let engine = RuddyPredicateEngine::init(100, 10, family);

        // load fib rules and encode action to usize with codex
        let (_, fibs) = FibLoader::<usize>::load(&codex, &engine, fib).unwrap();

        // setup fib monitor
        let mut fib_monitor = DefaultFibMonitor::new(&engine);

        // two rules as an incremental update
        // im should have three entries: one default "drop", one 0.0.0.0/1 and one "192.168.1.0/24"
        let im = fib_monitor.insert::<SeqActions<usize, 1>, Multiple>(fibs.clone());
        assert_eq!(im.len(), 3);

        fib_monitor.clear();
        let im = fib_monitor.insert::<usize, Single>(fibs);
        assert_eq!(im.len(), 3);

        let im = InverseModel::<SeqActions<usize, 1>, _, Multiple>::from(im);
        assert_eq!(im.len(), 3);

        // load fib rules and encode action to TypedAction with codex, run the same as above
        let (_, fibs) = FibLoader::<TypedAction>::load(&codex, &engine, fib).unwrap();
        let mut fib_monitor = DefaultFibMonitor::new(&engine);
        let im = fib_monitor.insert::<TypedAction, Single>(fibs);
        assert_eq!(im.len(), 3);
    }
}
