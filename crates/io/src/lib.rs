mod default;

use nom::{
    error::{Error, ParseError},
    {Finish, IResult},
};

use rapimt_core::{
    action::{ActionEncoder, CodedAction, UncodedAction},
    r#match::Rule,
    r#match::{PredicateEngine, PredicateInner},
};

pub use default::{DefaultInstLoader, TypedAction, PortInfoBase};

/// InstanceLoader is a parser that can parse the topology file load an instance (ActionEncoder)
/// according to some format.
///
/// ***The trait and the format are manufacture-specific.***
pub trait InstanceLoader<'a, AE, UA, A = u32>
where
    AE: ActionEncoder<'a, A>,
    UA: UncodedAction,
    A: CodedAction,
{
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
pub trait FibLoader<'a, 'p, P, A = u32>
where
    Self: ActionEncoder<'a, A>,
    P: PredicateInner + 'p,
    A: CodedAction,
{
    // Required method
    fn _load<'x, 's: 'p, ME, Err>(
        &'s self,
        engine: &'p ME,
        content: &'x str,
    ) -> IResult<(), (String, Vec<Rule<P, A>>), Err>
    where
        ME: PredicateEngine<'p, P>,
        Err: ParseError<&'x str>;

    // Provided method
    fn load<'x, 's: 'p, ME>(
        &'s self,
        engine: &'p ME,
        content: &'x str,
    ) -> Result<(String, Vec<Rule<P, A>>), Error<&'x str>>
    where
        ME: PredicateEngine<'p, P>,
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
        use nom::combinator::recognize;
        use nom::error::{Error as NomError, ErrorKind, ParseError};
        use nom::sequence::{pair, tuple};
        use nom::Err::Error;
        use nom::IResult;

        #[allow(dead_code)]
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

        /// r"[a-zA-Z0-9_-]+"
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
