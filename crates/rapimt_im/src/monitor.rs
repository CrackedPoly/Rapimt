use std::{
    collections::{BTreeSet, BinaryHeap, HashMap},
    ops::Bound,
    rc::Rc,
};

use fxhash::{FxBuildHasher, FxHashMap};
use rapimt_core::{
    action::{Action, Dimension, Single},
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
///   the default rule..
pub struct DefaultFibMonitor<'p, A, ME>
where
    A: Action<Single>,
    ME: MatchEncoder<'p>,
{
    engine: &'p ME,
    local_ap: FxHashMap<A, Predicate<ME::P>>,
    #[allow(clippy::type_complexity)]
    tpt: TernaryPatriciaTree<Rc<Rule<ME::P, A>>, BTreeSet<Rc<Rule<ME::P, A>>>>,
    i_rules: BinaryHeap<Rc<Rule<ME::P, A>>>,
    d_rules: BinaryHeap<Rc<Rule<ME::P, A>>>,
    default_rule: Rc<Rule<ME::P, A>>,
}

impl<'p, A, ME> FibMonitor<A, ME::P> for DefaultFibMonitor<'p, A, ME>
where
    A: Action<Single>,
    ME: MatchEncoder<'p>,
{
    fn clear(&mut self) {
        self.tpt.clear();
        self.i_rules.clear();
        self.d_rules.clear();
        self.i_rules.push(self.default_rule.clone());
    }

    fn update<OA, T>(
        &mut self,
        insertion: Vec<Rule<ME::P, A>>,
        deletion: Vec<Rule<ME::P, A>>,
    ) -> InverseModel<OA, ME::P, T>
    where
        OA: Action<T, S = A> + From<A>,
        T: Dimension,
    {
        insertion.into_iter().for_each(|r| {
            let r = Rc::new(r);
            self.insert_tpt(r.clone());
            self.i_rules.push(r.clone());
        });
        deletion.into_iter().for_each(|r| {
            let r = Rc::new(r);
            self.delete_tpt(&r);
            self.d_rules.push(r.clone());
        });
        self.refresh()
    }
}

impl<'p, A, ME> DefaultFibMonitor<'p, A, ME>
where
    A: Action<Single>,
    ME: MatchEncoder<'p>,
{
    fn insert_tpt(&mut self, rule: Rc<Rule<ME::P, A>>) {
        for mv in rule.origin.iter() {
            self.tpt.insert(rule.clone(), Segmentizer::from(*mv));
        }
    }

    fn delete_tpt(&mut self, rule: &Rc<Rule<ME::P, A>>) {
        for mv in rule.origin.iter() {
            self.tpt.delete(rule, Segmentizer::from(*mv));
        }
    }

    fn search_tpt(&self, rule: &Rc<Rule<ME::P, A>>) -> BTreeSet<Rc<Rule<ME::P, A>>> {
        let mut set = BTreeSet::<Rc<Rule<ME::P, A>>>::default();
        for mv in rule.origin.iter() {
            set.extend(self.tpt.search(rule, Segmentizer::from(*mv)))
        }
        set
    }

    pub fn new(engine: &'p ME) -> Self {
        // this is the default rule of every forwarding device
        let drop_rule = Rc::new(Rule {
            priority: -1,
            action: A::drop_action(),
            predicate: engine.one(),
            origin: vec![MaskedValue::from((0u128, 0u128))],
        });
        let tpt = TernaryPatriciaTree::new(MAX_POS);
        let i_rules = BinaryHeap::from([drop_rule.clone()]);
        let d_rules = BinaryHeap::new();
        let local_ap = HashMap::with_hasher(FxBuildHasher::default());
        DefaultFibMonitor {
            engine,
            local_ap,
            tpt,
            i_rules,
            d_rules,
            default_rule: drop_rule,
        }
    }

    fn refresh<OA, T>(&mut self) -> InverseModel<OA, ME::P, T>
    where
        OA: Action<T, S = A> + From<A> + From<A>,
        T: Dimension,
    {
        self.local_ap.clear();
        let mut no_overwrite = self.engine.one();
        while let Some(r) = self.i_rules.pop() {
            let mut eff = r.predicate.clone();
            let related = self.search_tpt(&r);
            // effective predicate minus all higher priority predicates
            for y in related.range((Bound::Excluded(r.clone()), Bound::Unbounded)) {
                eff -= &y.predicate;
                if eff.is_empty() {
                    break;
                }
            }
            // if eff is not empty, then the action is valid
            if !eff.is_empty() {
                self.local_ap
                    .entry(r.action.clone())
                    .and_modify(|mut p| p |= &eff)
                    .or_insert(eff.clone());
                no_overwrite -= &eff;
            }
        }

        while let Some(r) = self.d_rules.pop() {
            let related = self.search_tpt(&r);
            let mut to_divide = r.predicate.clone();
            // to_divide minus all higher priority predicates
            for y in related.range((Bound::Excluded(r.clone()), Bound::Unbounded)) {
                to_divide -= &y.predicate;
                if to_divide.is_empty() {
                    break;
                }
            }
            // if to_divide is still not empty, then it means if the rule is removed, the hiden
            // rules (variable y below) that are lower priority than it will be revealed
            while !to_divide.is_empty() {
                for y in related
                    .range((Bound::Unbounded, Bound::Included(r.clone())))
                    .rev()
                {
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
        }
        if !no_overwrite.is_empty() {
            self.local_ap.insert(A::no_overwrite(), no_overwrite);
        }

        InverseModel::from(
            self.local_ap
                .drain()
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

    // #[test]
    // fn test_bbrb_stanford() {
    //     let spec = std::fs::read_to_string("examples/stanford/spec/bbrb_rtr.spec").unwrap();
    //     let fib = std::fs::read_to_string("examples/stanford/fib/bbrb_rtr.fib").unwrap();
    //
    //     let loader = DefaultInstLoader::default();
    //     let codex = InstanceLoader::load(&loader, &spec).unwrap();
    //
    //     // load fibs
    //     let family = MatchFamily::Inet4Family;
    //     let engine = RuddyPredicateEngine::init(100, 10, family);
    //
    //     // load fib rules and encode action to usize with codex
    //     let (_, fibs) = FibLoader::<usize>::load(&codex, &engine, &fib).unwrap();
    //
    //     // setup fib monitor
    //     let mut fib_monitor = DefaultFibMonitor::new(&engine);
    //     let bbrb_rtr_im = fib_monitor.insert::<SeqActions<usize, 1>, Multiple>(fibs);
    //
    //     for (a, p) in bbrb_rtr_im.iter() {
    //         let coded_action = a[0];
    //         let action = codex.decode(coded_action);
    //         println!("{:?}", action);
    //         if let TypedAction::NonOverwrite = action {
    //             println!("{:?}", p);
    //         }
    //     }
    //     println!("bbrb inverse model size: {:?}", bbrb_rtr_im.len());
    // }
}
