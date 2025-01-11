use nom::{
    error::{Error, ParseError},
    {Finish, IResult},
};
use rapimt_core::prelude::{Action, ActionEncoder, PredicateEngine, Rule, Single};

pub mod parser;
pub mod loader;

/// InstanceLoader is a parser that can parse the topology file load an instance (ActionEncoder)
/// according to some format.
///
/// ***The trait and the format are manufacture-specific.***
pub trait InstanceLoader<'a, AE: ActionEncoder<'a>> {
    // Required method
    fn _load<'x, Err: ParseError<&'x str>>(&self, content: &'x str) -> IResult<(), AE, Err>;

    // Provided method
    fn load<'x>(&self, content: &'x str) -> Result<AE, Error<&'x str>> {
        let res = self._load(content).finish();
        match res {
            Ok((_, ae)) => Ok(ae),
            Err(e) => Err(e),
        }
    }
}

/// [FibLoader] should be implemented by an [ActionEncoder], it enable action encoder to parse fib
/// rules in string format and encode them into into [Rule]s in the system.
///
/// ***The trait and the format are manufacture-specific.***
#[allow(clippy::type_complexity)]
pub trait FibLoader<'a, A>: ActionEncoder<'a>
where
    A: Action<Single>,
{
    // Required method
    fn _load<'x, 'p, PE, Err>(
        &'a self,
        engine: &'p PE,
        content: &'x str,
    ) -> IResult<(), (String, Vec<Rule<PE::P, A>>), Err>
    where
        PE: PredicateEngine<'p>,
        Err: ParseError<&'x str>,
        'a: 'p,
        'p: 'a;

    // Provided method

    /// load fib rules from string content. Since Rule is a combination of action as A and predicate as Predicate<PE::P>,
    /// the lifetime of A ('a) should equals to the lifetime of P ('p)
    fn load<'x, 'p, PE>(
        &'a self,
        engine: &'p PE,
        content: &'x str,
    ) -> Result<(String, Vec<Rule<PE::P, A>>), Error<&'x str>>
    where
        PE: PredicateEngine<'p>,
        'a: 'p,
        'p: 'a,
    {
        let res = self._load(engine, content).finish();
        match res {
            Ok((_, rules)) => Ok(rules),
            Err(e) => Err(e),
        }
    }
}

