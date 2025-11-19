use std::path::PathBuf;

use snafu::Snafu;

use crate::prelude::ib::loader::{GroupIdx, Guid, PortIdx};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("File name not comply with the format: {}", filename.display()))]
    FileName { filename: PathBuf },
    #[snafu(display("Failed to read file: {}", source))]
    FileIo { source: std::io::Error },
    #[snafu(display("Failed to parse csv file: {}", source))]
    ParseCsv { source: csv::Error },
    #[snafu(display("Failed to parse integer: {}", source))]
    ParseInt { source: std::num::ParseIntError },

    #[snafu(display("IB node type {} not found", number))]
    IbNodeTypeNotFound { number: u8 },
    #[snafu(display("IB port type {} not found", number))]
    IbPortTypeNotFound { number: u8 },
    #[snafu(display("Ib node {} not found", node))]
    IbNodeNotFound { node: Guid },
    #[snafu(display("Ib port {} not found in node {}", port, node))]
    IbPortNotFound { node: Guid, port: PortIdx },
    #[snafu(display("Ib group {} not found in node {}", group, node))]
    IbGroupNotFound { node: Guid, group: GroupIdx },
}
