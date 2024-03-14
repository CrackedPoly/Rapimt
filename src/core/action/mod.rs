mod seq_action;

/// EncodedAction should have fixed size and be cast [Into] to u32. We assume
/// that the number of actions on single device will not exceed 2^32.
///
/// EncodedAction.into() == 0 means no overwrite
pub trait CodedAction: Default + Sized + Copy + Into<u32> {}

impl CodedAction for u32 {}

pub trait Actions<A: CodedAction> {
    fn from(a: A) -> Self;
    fn from_all(data: Vec<A>) -> Self;
    fn get(&self, idx: usize) -> A;
    fn get_all(&self) -> &[A];
    fn resize(&self, to: usize, offset: usize) -> Self;
    fn update(&mut self, idx: usize, value: A);
    fn diff(&self, rhs: &Self) -> usize;
    fn overwrite(&self, rhs: &Self) -> Self;
}
