use crate::core::action::CodedAction;
use crate::core::r#match::engine::MaskedValue;
use crate::core::Predicate;

pub struct Rule<P: Predicate, A: CodedAction = u32> {
    priority: u32,
    action: A,
    predicate: P,
    origin: Vec<MaskedValue>,
}
