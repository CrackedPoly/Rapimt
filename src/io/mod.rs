/// Default format of the topo and fib.
mod default;

use crate::core::action::CodedAction;
use crate::core::im::Rule;
use crate::core::Predicate;
use crate::io::basic::action::ActionType;
use nom::error::{Error, ParseError};
use nom::{Finish, IResult};

/// Action = action type + neighbors
///
/// Action should have rich information, and may not have fixed size. Action
/// is device-specific, and should be encoded into fixed-size EncodedAction
/// before computation.
pub trait UncodedAction {
    fn get_type(&self) -> ActionType;
    fn get_next_hops(&self) -> Vec<&str>;
}

/// EncodedAction is a fixed-size representation of Action.
pub trait ActionEncoder<'a, A: CodedAction = u32>
where
    Self: 'a,
{
    type UA: UncodedAction + 'a;
    fn encode(&'a self, action: Self::UA) -> A;
    fn decode(&'a self, code: A) -> Self::UA;
}

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

pub trait FibLoader<'a, P: Predicate, A: CodedAction = u32>
where
    Self: ActionEncoder<'a, A>,
{
    fn _load<'x, Err: ParseError<&'x str>>(&self, content: &'x str) -> IResult<(), Vec<Rule<P, A>>, Err>;

    fn load<'x>(&self, content: &'x str) -> Result<Vec<Rule<P, A>>, Error<&'x str>> {
        let res = self._load(content).finish();
        return match res {
            Ok((_, rules)) => Ok(rules),
            Err(e) => Err(e),
        };
    }
}

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

        /// r""[0-9]+"
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
        pub fn parse_port<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, &'a str, E> {
            fn is_port_ident(chr: char) -> bool {
                is_digit(chr as u8) || chr == '/' || chr == '.' || chr == '-' || chr == '_' || chr == '\\'
            }
            recognize(pair(parse_port_prefix, take_while1(is_port_ident)))(input)
        }

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
