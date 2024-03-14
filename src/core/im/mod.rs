use crate::core::action::CodedAction;
use crate::core::r#match::engine::MaskedValue;
use crate::core::Predicate;

pub struct Rule<P: Predicate, A: CodedAction = u32> {
    pub priority: u32,
    pub action: A,
    pub predicate: P,
    pub origin: Vec<MaskedValue>,
}
