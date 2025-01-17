use crate::{
    ib::loader::{Guid, Lid},
    prelude::{LinkSpec, NodeCommon, PortSpec},
};
use funty::Unsigned;
use fxhash::{FxBuildHasher, FxHashMap};
use serde::{Deserialize, Deserializer};

fn deserialize_maybe_nan<'de, D, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum MaybeNA<U> {
        Value(Option<U>),
        NAString(String),
    }

    // deserialize into local enum
    let value: MaybeNA<T> = Deserialize::deserialize(deserializer)?;
    match value {
        MaybeNA::Value(value) => Ok(value),
        MaybeNA::NAString(string) => {
            if string == "N/A" {
                Ok(None)
            } else {
                Err(serde::de::Error::custom("Unexpected string"))
            }
        }
    }
}

fn deserialize_maybe_nan_hex<'de, D, T: Deserialize<'de> + Unsigned>(
    deserializer: D,
) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
{
    // deserialize into local enum
    let value: &str = Deserialize::deserialize(deserializer)?;
    match value {
        "N/A" => Ok(None),
        _ => Ok(Some(T::from_str_radix(&value[2..], 16).unwrap())),
    }
}

/// NodeDesc,NumPorts,NodeType,ClassVersion,BaseVersion,SystemImageGUID,NodeGUID,PortGUID,DeviceID,PartitionCap,revision,VendorID,LocalPortNum
#[doc(hidden)]
#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
pub struct NodeRecord<'a> {
    pub NodeDesc: &'a str,
    pub NumPorts: u8,
    pub NodeType: u8,
    pub ClassVersion: u8,
    pub BaseVersion: u8,
    pub SystemImageGUID: Guid,
    pub NodeGUID: Guid,
    pub PortGUID: Guid,
    pub DeviceID: u16,
    pub PartitionCap: u16,
    pub revision: u16,
    pub VendorID: u16,
    pub LocalPortNum: u8,
}

/// NodeGuid1,PortNum1,NodeGuid2,PortNum2
#[doc(hidden)]
#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
pub struct LinkRecord {
    pub NodeGuid1: Guid,
    pub PortNum1: u8,
    pub NodeGuid2: Guid,
    pub PortNum2: u8,
}

/// NodeGuid,PortGuid,PortNum,MKey,GIDPrfx,MSMLID,LID,CapMsk,M_KeyLeasePeriod,DiagCode,LinkWidthActv,LinkWidthSup,LinkWidthEn,LocalPortNum,LinkSpeedEn,LinkSpeedActv,LMC,MKeyProtBits,LinkDownDefState,PortPhyState,PortState,LinkSpeedSup,VLArbHighCap,VLHighLimit,InitType,VLCap,MSMSL,NMTU,FilterRawOutb,FilterRawInb,PartEnfOutb,PartEnfInb,OpVLs,HoQLife,VLStallCnt,MTUCap,InitTypeReply,VLArbLowCap,PKeyViolations,MKeyViolations,SubnTmo,MulticastPKeyTrapSuppressionEnabled,ClientReregister,GUIDCap,QKeyViolations,MaxCreditHint,OverrunErrs,LocalPhyError,RespTimeValue,LinkRoundTripLatency,OOOSLMask,CapMsk2,FECActv,RetransActv
#[doc(hidden)]
#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
pub struct PortRecord {
    pub NodeGuid: Guid,
    pub PortGuid: Guid,
    pub PortNum: u8,
    pub MKey: u64,
    pub GIDPrfx: u64,
    pub MSMLID: u16,
    pub LID: Lid,
    pub CapMsk: u64,
    pub M_KeyLeasePeriod: u32,
    pub DiagCode: u8,
    pub LinkWidthActv: u8,
    pub LinkWidthSup: u8,
    pub LinkWidthEn: u8,
    pub LocalPortNum: u8,
    pub LinkSpeedEn: u64,
    pub LinkSpeedActv: u64,
    pub LMC: Lid,
    pub MKeyProtBits: u8,
    pub LinkDownDefState: u8,
    pub PortPhyState: u8,
    pub PortState: u8,
    pub LinkSpeedSup: u64,
    pub VLArbHighCap: u8,
    pub VLHighLimit: u8,
    pub InitType: u8,
    pub VLCap: u8,
    pub MSMSL: u8,
    pub NMTU: u16,
    pub FilterRawOutb: u8,
    pub FilterRawInb: u8,
    pub PartEnfOutb: u8,
    pub PartEnfInb: u8,
    pub OpVLs: u8,
    pub HoQLife: u8,
    pub VLStallCnt: u8,
    pub MTUCap: u16,
    pub InitTypeReply: u8,
    pub VLArbLowCap: u8,
    pub PKeyViolations: u8,
    pub MKeyViolations: u8,
    pub SubnTmo: u8,
    pub MulticastPKeyTrapSuppressionEnabled: u8,
    pub ClientReregister: u8,
    pub GUIDCap: u8,
    pub QKeyViolations: u8,
    pub MaxCreditHint: u8,
    pub OverrunErrs: u8,
    pub LocalPhyError: u8,
    pub RespTimeValue: u8,
    pub LinkRoundTripLatency: u64,
    #[serde(deserialize_with = "deserialize_maybe_nan_hex")]
    pub OOOSLMask: Option<u16>,
    #[serde(deserialize_with = "deserialize_maybe_nan")]
    pub CapMsk2: Option<u64>,
    #[serde(deserialize_with = "deserialize_maybe_nan")]
    pub FECActv: Option<u64>,
    #[serde(deserialize_with = "deserialize_maybe_nan")]
    pub RetransActv: Option<u64>,
}

pub fn load_nodes(
    file: impl AsRef<std::path::Path>,
) -> Result<Vec<NodeCommon>, Box<dyn std::error::Error>> {
    let file = std::fs::File::open(file)?;
    let mut nodes = vec![];
    let mut rdr = csv::Reader::from_reader(file);
    let mut raw_record = csv::ByteRecord::new();
    let headers = rdr.byte_headers()?.clone();
    while rdr.read_byte_record(&mut raw_record)? {
        let nr: NodeRecord = raw_record.deserialize(Some(&headers))?;
        nodes.push(NodeCommon {
            vendor_id: nr.VendorID,
            device_id: nr.DeviceID,
            sysimg_guid: nr.SystemImageGUID,
            node_guid: nr.NodeGUID,
            port_guid: nr.PortGUID,
            port_num: nr.NumPorts,
            node_type: nr.NodeType.try_into()?,
            description: nr.NodeDesc.to_string(),
            ..Default::default()
        });
    }
    Ok(nodes)
}

pub fn load_links(
    file: impl AsRef<std::path::Path>,
) -> Result<Vec<LinkSpec>, Box<dyn std::error::Error>> {
    let file = std::fs::File::open(file)?;
    let mut links = vec![];
    let mut rdr = csv::Reader::from_reader(file);
    let mut raw_record = csv::ByteRecord::new();
    let headers = rdr.byte_headers()?.clone();
    while rdr.read_byte_record(&mut raw_record)? {
        let lr: LinkRecord = raw_record.deserialize(Some(&headers))?;
        links.push(LinkSpec {
            src_node_guid: lr.NodeGuid1,
            src_port_idx: lr.PortNum1,
            dst_node_guid: lr.NodeGuid2,
            dst_port_idx: lr.PortNum2,
        });
    }
    Ok(links)
}

pub fn load_ports(
    file: impl AsRef<std::path::Path>,
) -> Result<FxHashMap<Guid, Vec<PortSpec>>, Box<dyn std::error::Error>> {
    let file = std::fs::File::open(file)?;
    let mut node_ports: FxHashMap<Guid, Vec<PortSpec>> =
        FxHashMap::with_hasher(FxBuildHasher::default());
    let mut rdr = csv::Reader::from_reader(file);
    let mut raw_record = csv::ByteRecord::new();
    let headers = rdr.byte_headers()?.clone();
    while rdr.read_byte_record(&mut raw_record)? {
        let pr: PortRecord = raw_record.deserialize(Some(&headers)).unwrap();
        let spec = PortSpec {
            port_guid: pr.PortGuid,
            port_num: pr.PortNum,
        };
        node_ports
            .entry(pr.NodeGuid)
            .and_modify(|v| v.push(spec))
            .or_insert(vec![spec]);
    }
    Ok(node_ports)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_nodes_from_csv() {
        match load_nodes("examples/ibdiagnet2/nodes.csv") {
            Ok(nodes) => {
                println!("{}", nodes.len());
            }
            Err(err) => {
                println!("{}", err);
                panic!("parse error");
            }
        }
    }

    #[test]
    fn test_read_links_from_csv() {
        match load_links("examples/ibdiagnet2/links.csv") {
            Ok(links) => {
                println!("{}", links.len());
            }
            Err(err) => {
                println!("{}", err);
                panic!("parse error");
            }
        }
    }

    #[test]
    fn test_read_ports_from_csv() {
        match load_ports("examples/ibdiagnet2/ports.csv") {
            Ok(ports) => {
                println!("{}", ports.len());
            }
            Err(err) => {
                println!("{}", err);
                panic!("parse error");
            }
        }
    }
}
