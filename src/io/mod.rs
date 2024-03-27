use std::fmt::{Debug, Display};
use std::hash::Hash;

use nom::error::{Error, ParseError};
use nom::{Finish, IResult};

use crate::core::r#match::Rule;
use crate::core::r#match::{PredicateEngine, PredicateInner};
use crate::io::basic::action::ActionType;

pub mod default;

/// UncodedAction is an action on a specific device, it should have rich information such as device
/// name, forwrading mode, next hops, and may not be fix-sized. It can be encoded by an action
/// encoder that represents the device.
///
/// ***This trait is manufacture-specific.***
pub trait UncodedAction {
  fn get_type(&self) -> ActionType;
  fn get_next_hops(&self) -> Vec<&str>;
}

/// CodedAction should have fixed size and can live in stack to achieve better performance.
/// [Default] trait implementation default() should return a value that represents no action
/// overwrite, refer to Fast-IMT theory for more information.
///
/// ***It seems an integer is sufficient, but we leave this trait for flexibility***
pub trait CodedAction:
  Eq + PartialEq + Ord + PartialOrd + Display + Debug + Default + Hash + Sized + Copy
{
}

impl CodedAction for u32 {}

/// ActionEncoder is essentially an instance that has all information about this device's topology
/// (name, ports, port mode, neighbors), it can encode/decode raw action into/from CodedAction
/// (which is more compact), and lookup the action by port name.
///
/// ***This trait is manufacture-specific.***
pub trait ActionEncoder<'a, A: CodedAction = u32>
where
  Self: 'a,
{
  type UA: UncodedAction + 'a;
  fn encode(&'a self, action: Self::UA) -> A;
  fn decode(&'a self, coded_action: A) -> Self::UA;
  fn lookup(&'a self, port_name: &str) -> Self::UA;
}

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

/// basics for io
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
    pub struct FimtIOError<I> {
      kind: IoErrorKind,
      nom_error: NomError<I>,
    }

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
    pub fn parse_ipv4_num<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, u32, E> {
      let (rest, num) = digit1(input)?;
      if let Ok(num) = num.parse::<u32>() {
        Ok((rest, num))
      } else {
        Err(Error(E::from_error_kind(input, ErrorKind::Digit)))
      }
    }
  }

  /// Basic action types.
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
