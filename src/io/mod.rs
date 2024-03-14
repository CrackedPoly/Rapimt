pub mod default;

use crate::core::action::CodedAction;
use crate::core::im::Rule;
use crate::core::{MatchEncoder, Predicate};
use crate::io::basic::action::ActionType;
use nom::error::{Error, ParseError};
use nom::{Finish, IResult};

/// UncodedAction is an action on a specific device, it should have rich
/// information, and may not be fix-sized. It can be encoded by its
/// ActionEncoder.
///
/// ***This trait is manufacture-specific.***
pub trait UncodedAction {
    fn get_type(&self) -> ActionType;
    fn get_next_hops(&self) -> Vec<&str>;
}

/// ActionEncoder is essentially an instance that has ports' all information
/// (name, mode, neighbors) in a device, it can encode/decode action
/// into/from CodedAction (which is more compact), and lookup the action by
/// port name.
///
/// ***This trait is manufacture-specific. CodedAction can have different
/// implementations.***
pub trait ActionEncoder<'a, A: CodedAction = u32>
where
    Self: 'a,
{
    type UA: UncodedAction + 'a;
    fn encode(&'a self, action: Self::UA) -> A;
    fn decode(&'a self, coded_action: A) -> Self::UA;
    fn lookup(&'a self, port_name: &str) -> Self::UA;
}

/// InstanceLoader is a parser that can load a specific instance
/// (ActionEncoder) from a specific format.
///
/// ***The trait and the format are manufacture-specific.***
pub trait InstanceLoader<'a, AE, UA, A = u32>
where
    AE: ActionEncoder<'a, A>,
    UA: UncodedAction,
    A: CodedAction,
{
    fn _load<'x, Err: ParseError<&'x str>>(&self, content: &'x str) -> IResult<(), AE, Err>;

    fn load<'x>(&self, content: &'x str) -> Result<AE, Error<&'x str>> {
        let res = self._load(content).finish();
        return match res {
            Ok((_, ae)) => Ok(ae),
            Err(e) => Err(e),
        };
    }
}

/// FibLoader enables ActionEncoder instances to parse and encode fib rules
/// from a specific format.
///
/// ***The trait and the format are manufacture-specific.***
pub trait FibLoader<'a, 'p, P, A = u32>
where
    Self: ActionEncoder<'a, A> + 'p,
    P: Predicate + 'p,
    A: CodedAction,
{
    fn _load<'x, 's: 'p, ME, Err>(
        &'s self,
        engine: &'p ME,
        content: &'x str,
    ) -> IResult<(), (String, Vec<Rule<P, A>>), Err>
    where
        ME: MatchEncoder<'p, P = P>,
        Err: ParseError<&'x str>;

    fn load<'x, 's: 'p, ME>(
        &'s self,
        engine: &'p ME,
        content: &'x str,
    ) -> Result<(String, Vec<Rule<P, A>>), Error<&'x str>>
    where
        ME: MatchEncoder<'p, P = P>,
    {
        let res = self._load(engine, content).finish();
        return match res {
            Ok((_, rules)) => Ok(rules),
            Err(e) => Err(e),
        };
    }
}

/// Basic helper functions for parsing and basic action types.
pub mod basic {
    pub mod parser {
        use nom::branch::alt;
        use nom::bytes::complete::{tag, take_while1};
        use nom::character::complete::{char, digit1};
        use nom::character::{is_alphanumeric, is_digit};
        use nom::combinator::recognize;
        use nom::error::{ErrorKind, ParseError};
        use nom::sequence::{pair, tuple};
        use nom::Err::Error;
        use nom::IResult;

        fn is_ident(chr: char) -> bool {
            is_alphanumeric(chr as u8) || chr == '_' || chr == '-' || chr == '.' || chr == '/'
        }

        /// r"[a-zA-Z0-9_-]+"
        pub fn parse_ident<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, &'a str, E> {
            take_while1(is_ident)(input)
        }

        /// r"[0-9]+"
        pub fn parse_digits<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, &'a str, E> {
            digit1(input)
        }

        /// r"self|gi|xe|ge|te|et|so|fa|ds"
        pub fn parse_port_prefix<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, &'a str, E> {
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
        pub fn parse_port<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, &'a str, E> {
            fn is_port_ident(chr: char) -> bool {
                is_digit(chr as u8) || chr == '/' || chr == '.' || chr == '-' || chr == '_' || chr == '\\'
            }
            recognize(pair(parse_port_prefix, take_while1(is_port_ident)))(input)
        }

        /// r"[<=255].[<=255].[<=255].[<=255]"
        pub fn parse_ipv4_dotted<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, u32, E> {
            fn parse_u8<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, u8, E> {
                let (rest, num) = digit1(input)?;
                return if let Ok(num) = num.parse::<u8>() {
                    Ok((rest, num))
                } else {
                    Err(Error(E::from_error_kind(input, ErrorKind::Digit)))
                };
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
            return Ok((
                rest,
                (o1 as u32) << 24 | (o2 as u32) << 16 | (o3 as u32) << 8 | o4 as u32,
            ));
        }

        /// r"[<=u32::MAX]"
        pub fn parse_ipv4_num<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, u32, E> {
            let (rest, num) = digit1(input)?;
            return if let Ok(num) = num.parse::<u32>() {
                Ok((rest, num))
            } else {
                Err(Error(E::from_error_kind(input, ErrorKind::Digit)))
            };
        }
    }

    pub mod action {
        #[derive(Debug, Clone, Copy, PartialEq)]
        pub enum ActionType {
            DROP = 0,
            FORWARD = 1,
            FLOOD = 2,
            ECMP = 3,
            FAILOVER = 4,
        }
    }
}
