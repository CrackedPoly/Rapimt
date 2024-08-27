//! This module provides basic parsing from the default format. (.fib for FIB rules and .spec for
//! topology instances)
//! TODO::This module needs to be documented.
mod default;

use nom::{
    error::{Error, ParseError},
    {Finish, IResult},
};

use rapimt_core::{
    action::{Action, ActionEncoder, Single},
    r#match::{PredicateEngine, Rule},
};

pub use default::{DefaultInstLoader, PortInfoBase, TypedAction};

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

/// Basics for io
pub mod basic {
    /// Basic helper functions for parsing
    pub mod parser {
        use nom::branch::alt;
        use nom::bytes::complete::{tag, take_while1};
        use nom::character::complete::{char, digit1};
        use nom::character::{is_alphanumeric, is_digit};
        use nom::combinator::{map, recognize};
        use nom::error::{Error as NomError, ErrorKind, ParseError};
        use nom::sequence::{pair, tuple};
        use nom::Err::Error;
        use nom::IResult;

        pub enum IoErrorKind {
            DevName,
            PortName,
            PortMode,
        }

        #[allow(dead_code)]
        pub struct IOError<I> {
            kind: IoErrorKind,
            nom_error: NomError<I>,
        }

        fn is_ident(chr: char) -> bool {
            is_alphanumeric(chr as u8) || chr == '_' || chr == '-' || chr == '.' || chr == '/'
        }

        /// r"[a-zA-Z0-9_-\.\/]+"
        pub fn parse_ident<'a, E: ParseError<&'a str>>(
            input: &'a str,
        ) -> IResult<&'a str, &'a str, E> {
            take_while1(is_ident)(input)
        }

        /// r"[0-9]+"
        pub fn parse_digits<'a, E: ParseError<&'a str>>(
            input: &'a str,
        ) -> IResult<&'a str, &'a str, E> {
            digit1(input)
        }

        /// r"(true)(false)"
        pub fn parse_bool<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, bool, E> {
            alt((map(tag("true"), |_| true), map(tag("false"), |_| false)))(input)
        }

        /// r"self|gi|xe|ge|te|et|so|fa|ds"
        pub fn parse_port_prefix<'a, E: ParseError<&'a str>>(
            input: &'a str,
        ) -> IResult<&'a str, &'a str, E> {
            alt((
                tag("self"),
                tag("gi"),
                tag("xe"),
                tag("ge"),
                tag("te"),
                tag("et"),
                tag("so"),
                tag("fa"),
                tag("ds"),
            ))(input)
        }

        /// "<port_prefix>[0-9/\\.-]\+"
        ///
        /// **Your format may not be like this. If the case, use [parse_ident]
        /// or else instead.**
        pub fn parse_port<'a, E: ParseError<&'a str>>(
            input: &'a str,
        ) -> IResult<&'a str, &'a str, E> {
            fn is_port_ident(chr: char) -> bool {
                is_digit(chr as u8)
                    || chr == '/'
                    || chr == '.'
                    || chr == '-'
                    || chr == '_'
                    || chr == '\\'
            }
            recognize(pair(parse_port_prefix, take_while1(is_port_ident)))(input)
        }

        /// r"[<=255].[<=255].[<=255].[<=255]"
        pub fn parse_ipv4_dotted<'a, E: ParseError<&'a str>>(
            input: &'a str,
        ) -> IResult<&'a str, u32, E> {
            fn parse_u8<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, u8, E> {
                let (rest, num) = digit1(input)?;
                if let Ok(num) = num.parse::<u8>() {
                    Ok((rest, num))
                } else {
                    Err(Error(E::from_error_kind(input, ErrorKind::Digit)))
                }
            }

            let (rest, (o1, _, o2, _, o3, _, o4)) = tuple((
                parse_u8,
                char('.'),
                parse_u8,
                char('.'),
                parse_u8,
                char('.'),
                parse_u8,
            ))(input)?;
            Ok((
                rest,
                (o1 as u32) << 24 | (o2 as u32) << 16 | (o3 as u32) << 8 | o4 as u32,
            ))
        }

        /// r"[<=u32::MAX]"
        pub fn parse_ipv4_num<'a, E: ParseError<&'a str>>(
            input: &'a str,
        ) -> IResult<&'a str, u32, E> {
            let (rest, num) = digit1(input)?;
            if let Ok(num) = num.parse::<u32>() {
                Ok((rest, num))
            } else {
                Err(Error(E::from_error_kind(input, ErrorKind::Digit)))
            }
        }
    }
}

#[allow(missing_docs)]
pub mod prelude {
    #[doc(hidden)]
    pub use crate::{DefaultInstLoader, FibLoader, InstanceLoader, PortInfoBase, TypedAction};
}
