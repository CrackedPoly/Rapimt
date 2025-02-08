use snafu::Snafu;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("Data plane is broken: {}", source))]
    DataPlaneIntegrity { source: rapimt_io::error::Error },
    #[snafu(display("This forwarding pattern should be ignored"))]
    ForwardingGraphIgnored,
}

impl From<rapimt_io::error::Error> for Error {
    fn from(source: rapimt_io::error::Error) -> Self {
        Error::DataPlaneIntegrity { source }
    }
}
