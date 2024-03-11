mod seq_action;

trait Action {}

trait ActionEncoder {
    fn encode(&self, action: dyn Action) -> u64;
    fn decode(&self, code: u64) -> dyn Action;
}

trait Actions {
    type Impl;
    fn get_impl(&self) -> &Self::Impl;
    fn get(&self, idx: usize) -> u64;
    fn resize(&self, to: usize, offset: usize) -> Self;
    fn update(self, pos: usize, value: u64) -> Self;
    fn diff(&self, rhs: &Self) -> u64;
    fn overwrite(&self, rhs: &Self) -> Self;
}
