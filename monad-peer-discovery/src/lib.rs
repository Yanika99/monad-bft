// Copyright (C) 2025 Category Labs, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    net::{Ipv4Addr, SocketAddrV4},
    time::Duration,
};

use alloy_rlp::{Decodable, Encodable, RlpDecodable, RlpEncodable, encode_list};
use message::{PeerLookupRequest, PeerLookupResponse, Ping, Pong};
use monad_crypto::{
    certificate_signature::{
        CertificateSignature, CertificateSignaturePubKey, CertificateSignatureRecoverable,
    },
    signing_domain,
};
use monad_executor::ExecutorMetrics;
use monad_executor_glue::PeerEntry;
use monad_types::{Epoch, NodeId, Round};
use tracing::{debug, warn};

pub mod discovery;
pub mod driver;
pub mod ipv4_validation;
pub mod message;
pub mod mock;

pub use message::PeerDiscoveryMessage;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PortTag {
    TCP = 0,
    UDP = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct Port {
    pub tag: u8,
    pub port: u16,
}

impl Port {
    pub fn new(tag: PortTag, port: u16) -> Self {
        Self {
            tag: tag as u8,
            port,
        }
    }

    pub fn tag_enum(&self) -> Option<PortTag> {
        match self.tag {
            0 => Some(PortTag::TCP),
            1 => Some(PortTag::UDP),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WireNameRecord {
    pub ip: Ipv4Addr,
    pub ports: Vec<Port>,
    pub capabilities: u64,
    pub seq: u64,
}

impl Encodable for WireNameRecord {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        let ports_vec: Vec<Port> = self.ports.to_vec();
        let enc: [&dyn Encodable; 4] =
            [&self.ip.octets(), &ports_vec, &self.capabilities, &self.seq];
        encode_list::<_, dyn Encodable>(&enc, out);
    }
}

fn decode_vec_with_limit<T: Decodable>(buf: &mut &[u8], limit: usize) -> alloy_rlp::Result<Vec<T>> {
    let mut bytes = alloy_rlp::Header::decode_bytes(buf, true)?;
    let mut vec = Vec::new();
    let payload_view = &mut bytes;
    while !payload_view.is_empty() {
        if vec.len() >= limit {
            return Err(alloy_rlp::Error::Custom("Too many items in vector"));
        }
        vec.push(T::decode(payload_view)?);
    }
    Ok(vec)
}

impl Decodable for WireNameRecord {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let buf = &mut alloy_rlp::Header::decode_bytes(buf, true)?;

        let Ok(ip_bytes) = <[u8; 4]>::decode(buf) else {
            warn!("ip address decode failed: {:?}", buf);
            return Err(alloy_rlp::Error::Custom("Invalid IPv4 address"));
        };
        let ip = Ipv4Addr::from(ip_bytes);
        let ports = decode_vec_with_limit::<Port>(buf, 8)?;
        let capabilities = u64::decode(buf)?;
        let seq = u64::decode(buf)?;

        Ok(Self {
            ip,
            ports,
            capabilities,
            seq,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameRecord {
    wire: WireNameRecord,
    tcp_port: u16,
    udp_port: u16,
}

impl NameRecord {
    pub fn new(ip: Ipv4Addr, tcp_port: u16, udp_port: u16, capabilities: u64, seq: u64) -> Self {
        let ports = vec![
            Port::new(PortTag::TCP, tcp_port),
            Port::new(PortTag::UDP, udp_port),
        ];
        let wire = WireNameRecord {
            ip,
            ports,
            capabilities,
            seq,
        };
        Self {
            wire,
            tcp_port,
            udp_port,
        }
    }

    pub fn ip(&self) -> Ipv4Addr {
        self.wire.ip
    }

    pub fn tcp_port(&self) -> u16 {
        self.tcp_port
    }

    pub fn udp_port(&self) -> u16 {
        self.udp_port
    }

    pub fn capabilities(&self) -> u64 {
        self.wire.capabilities
    }

    pub fn seq(&self) -> u64 {
        self.wire.seq
    }

    pub fn tcp_socket(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.wire.ip, self.tcp_port)
    }

    pub fn udp_socket(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.wire.ip, self.udp_port)
    }

    pub fn check_capability(&self, capability: Capability) -> bool {
        (self.wire.capabilities & (1u64 << (capability as u8))) != 0
    }

    pub fn set_capability(&mut self, capability: Capability) {
        self.wire.capabilities |= 1u64 << (capability as u8);
    }
}

impl Encodable for NameRecord {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        self.wire.encode(out);
    }
}

impl Decodable for NameRecord {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let wire = WireNameRecord::decode(buf)?;

        let mut tcp_port = None;
        let mut udp_port = None;
        let mut seen_tags = HashSet::new();

        for port in &wire.ports {
            if !seen_tags.insert(port.tag) {
                return Err(alloy_rlp::Error::Custom("duplicate port tag"));
            }

            match port.tag_enum() {
                Some(PortTag::TCP) => tcp_port = Some(port.port),
                Some(PortTag::UDP) => udp_port = Some(port.port),
                None => {
                    debug!(
                        tag = port.tag,
                        port = port.port,
                        "unknown port tag in name record"
                    );
                }
            }
        }

        let tcp_port = tcp_port.ok_or(alloy_rlp::Error::Custom("Missing TCP port"))?;
        let udp_port = udp_port.ok_or(alloy_rlp::Error::Custom("Missing UDP port"))?;

        Ok(NameRecord {
            wire,
            tcp_port,
            udp_port,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {}

#[derive(Debug, Clone, PartialEq, RlpEncodable, RlpDecodable, Eq)]
pub struct MonadNameRecord<ST: CertificateSignatureRecoverable> {
    pub name_record: NameRecord,
    pub signature: ST,
}

impl<ST: CertificateSignatureRecoverable> MonadNameRecord<ST> {
    pub fn new(name_record: NameRecord, key: &ST::KeyPairType) -> Self {
        let mut encoded = Vec::new();
        name_record.encode(&mut encoded);
        let signature = ST::sign::<signing_domain::NameRecord>(&encoded, key);
        Self {
            name_record,
            signature,
        }
    }

    pub fn recover_pubkey(
        &self,
    ) -> Result<NodeId<CertificateSignaturePubKey<ST>>, <ST as CertificateSignature>::Error> {
        let mut encoded = Vec::new();
        self.name_record.encode(&mut encoded);
        let pubkey = self
            .signature
            .recover_pubkey::<signing_domain::NameRecord>(&encoded)?;
        Ok(NodeId::new(pubkey))
    }

    pub fn address(&self) -> SocketAddrV4 {
        self.name_record.tcp_socket()
    }

    pub fn seq(&self) -> u64 {
        self.name_record.seq()
    }
}

#[derive(Debug, Clone)]
pub enum PeerDiscoveryEvent<ST: CertificateSignatureRecoverable> {
    SendPing {
        to: NodeId<CertificateSignaturePubKey<ST>>,
        socket_address: SocketAddrV4,
        ping: Ping<ST>,
    },
    PingRequest {
        from: NodeId<CertificateSignaturePubKey<ST>>,
        ping: Ping<ST>,
    },
    PongResponse {
        from: NodeId<CertificateSignaturePubKey<ST>>,
        pong: Pong,
    },
    PingTimeout {
        to: NodeId<CertificateSignaturePubKey<ST>>,
        ping_id: u32,
    },
    SendPeerLookup {
        to: NodeId<CertificateSignaturePubKey<ST>>,
        target: NodeId<CertificateSignaturePubKey<ST>>,
        open_discovery: bool,
    },
    PeerLookupRequest {
        from: NodeId<CertificateSignaturePubKey<ST>>,
        request: PeerLookupRequest<ST>,
    },
    PeerLookupResponse {
        from: NodeId<CertificateSignaturePubKey<ST>>,
        response: PeerLookupResponse<ST>,
    },
    PeerLookupTimeout {
        to: NodeId<CertificateSignaturePubKey<ST>>,
        target: NodeId<CertificateSignaturePubKey<ST>>,
        lookup_id: u32,
    },
    SendFullNodeRaptorcastRequest {
        to: NodeId<CertificateSignaturePubKey<ST>>,
    },
    FullNodeRaptorcastRequest {
        from: NodeId<CertificateSignaturePubKey<ST>>,
    },
    FullNodeRaptorcastResponse {
        from: NodeId<CertificateSignaturePubKey<ST>>,
    },
    UpdateCurrentRound {
        round: Round,
        epoch: Epoch,
    },
    UpdateValidatorSet {
        epoch: Epoch,
        validators: BTreeSet<NodeId<CertificateSignaturePubKey<ST>>>,
    },
    UpdatePeers {
        peers: Vec<PeerEntry<ST>>,
    },
    UpdatePinnedNodes {
        dedicated_full_nodes: BTreeSet<NodeId<CertificateSignaturePubKey<ST>>>,
        prioritized_full_nodes: BTreeSet<NodeId<CertificateSignaturePubKey<ST>>>,
    },
    UpdateConfirmGroup {
        end_round: Round,
        peers: BTreeSet<NodeId<CertificateSignaturePubKey<ST>>>,
    },
    Refresh,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TimerKind {
    SendPing,
    PingTimeout,
    RetryPeerLookup { lookup_id: u32 },
    Refresh,
    FullNodeRaptorcastRequest,
}

#[derive(Debug, Clone)]
pub enum PeerDiscoveryTimerCommand<E, ST: CertificateSignatureRecoverable> {
    Schedule {
        node_id: NodeId<CertificateSignaturePubKey<ST>>,
        timer_kind: TimerKind,
        duration: Duration,
        on_timeout: E,
    },
    ScheduleReset {
        node_id: NodeId<CertificateSignaturePubKey<ST>>,
        timer_kind: TimerKind,
    },
}

#[derive(Debug, Clone)]
pub struct PeerDiscoveryMetricsCommand(ExecutorMetrics);

#[derive(Debug, Clone)]
pub enum PeerDiscoveryCommand<ST: CertificateSignatureRecoverable> {
    RouterCommand {
        target: NodeId<CertificateSignaturePubKey<ST>>,
        message: PeerDiscoveryMessage<ST>,
    },
    PingPongCommand {
        target: NodeId<CertificateSignaturePubKey<ST>>,
        socket_address: SocketAddrV4,
        message: PeerDiscoveryMessage<ST>,
    },
    TimerCommand(PeerDiscoveryTimerCommand<PeerDiscoveryEvent<ST>, ST>),
    MetricsCommand(PeerDiscoveryMetricsCommand),
}

pub trait PeerDiscoveryAlgo {
    type SignatureType: CertificateSignatureRecoverable;

    fn send_ping(
        &mut self,
        target: NodeId<CertificateSignaturePubKey<Self::SignatureType>>,
        socket_address: SocketAddrV4,
        ping: Ping<Self::SignatureType>,
    ) -> Vec<PeerDiscoveryCommand<Self::SignatureType>>;

    fn handle_ping(
        &mut self,
        from: NodeId<CertificateSignaturePubKey<Self::SignatureType>>,
        ping: Ping<Self::SignatureType>,
    ) -> Vec<PeerDiscoveryCommand<Self::SignatureType>>;

    fn handle_pong(
        &mut self,
        from: NodeId<CertificateSignaturePubKey<Self::SignatureType>>,
        pong: Pong,
    ) -> Vec<PeerDiscoveryCommand<Self::SignatureType>>;

    fn handle_ping_timeout(
        &mut self,
        to: NodeId<CertificateSignaturePubKey<Self::SignatureType>>,
        ping_id: u32,
    ) -> Vec<PeerDiscoveryCommand<Self::SignatureType>>;

    fn send_peer_lookup_request(
        &mut self,
        to: NodeId<CertificateSignaturePubKey<Self::SignatureType>>,
        target: NodeId<CertificateSignaturePubKey<Self::SignatureType>>,
        open_discovery: bool,
    ) -> Vec<PeerDiscoveryCommand<Self::SignatureType>>;

    fn handle_peer_lookup_request(
        &mut self,
        from: NodeId<CertificateSignaturePubKey<Self::SignatureType>>,
        request: PeerLookupRequest<Self::SignatureType>,
    ) -> Vec<PeerDiscoveryCommand<Self::SignatureType>>;

    fn handle_peer_lookup_response(
        &mut self,
        from: NodeId<CertificateSignaturePubKey<Self::SignatureType>>,
        response: PeerLookupResponse<Self::SignatureType>,
    ) -> Vec<PeerDiscoveryCommand<Self::SignatureType>>;

    fn handle_peer_lookup_timeout(
        &mut self,
        to: NodeId<CertificateSignaturePubKey<Self::SignatureType>>,
        target: NodeId<CertificateSignaturePubKey<Self::SignatureType>>,
        lookup_id: u32,
    ) -> Vec<PeerDiscoveryCommand<Self::SignatureType>>;

    fn send_full_node_raptorcast_request(
        &mut self,
        to: NodeId<CertificateSignaturePubKey<Self::SignatureType>>,
    ) -> Vec<PeerDiscoveryCommand<Self::SignatureType>>;

    fn handle_full_node_raptorcast_request(
        &mut self,
        from: NodeId<CertificateSignaturePubKey<Self::SignatureType>>,
    ) -> Vec<PeerDiscoveryCommand<Self::SignatureType>>;

    fn handle_full_node_raptorcast_response(
        &mut self,
        from: NodeId<CertificateSignaturePubKey<Self::SignatureType>>,
    ) -> Vec<PeerDiscoveryCommand<Self::SignatureType>>;

    fn refresh(&mut self) -> Vec<PeerDiscoveryCommand<Self::SignatureType>>;

    fn update_current_round(
        &mut self,
        round: Round,
        epoch: Epoch,
    ) -> Vec<PeerDiscoveryCommand<Self::SignatureType>>;

    fn update_validator_set(
        &mut self,
        epoch: Epoch,
        validators: BTreeSet<NodeId<CertificateSignaturePubKey<Self::SignatureType>>>,
    ) -> Vec<PeerDiscoveryCommand<Self::SignatureType>>;

    fn update_peers(
        &mut self,
        peers: Vec<PeerEntry<Self::SignatureType>>,
    ) -> Vec<PeerDiscoveryCommand<Self::SignatureType>>;

    fn update_pinned_nodes(
        &mut self,
        dedicated_full_nodes: BTreeSet<NodeId<CertificateSignaturePubKey<Self::SignatureType>>>,
        prioritized_full_nodes: BTreeSet<NodeId<CertificateSignaturePubKey<Self::SignatureType>>>,
    ) -> Vec<PeerDiscoveryCommand<Self::SignatureType>>;

    fn update_peer_participation(
        &mut self,
        round: Round,
        peers: BTreeSet<NodeId<CertificateSignaturePubKey<Self::SignatureType>>>,
    ) -> Vec<PeerDiscoveryCommand<Self::SignatureType>>;

    fn metrics(&self) -> &ExecutorMetrics;

    fn get_pending_addr_by_id(
        &self,
        id: &NodeId<CertificateSignaturePubKey<Self::SignatureType>>,
    ) -> Option<SocketAddrV4>;

    fn get_addr_by_id(
        &self,
        id: &NodeId<CertificateSignaturePubKey<Self::SignatureType>>,
    ) -> Option<SocketAddrV4>;

    fn get_known_addrs(
        &self,
    ) -> HashMap<NodeId<CertificateSignaturePubKey<Self::SignatureType>>, SocketAddrV4>;

    fn get_secondary_fullnodes(
        &self,
    ) -> Vec<NodeId<CertificateSignaturePubKey<Self::SignatureType>>>;

    fn get_name_records(
        &self,
    ) -> HashMap<
        NodeId<CertificateSignaturePubKey<Self::SignatureType>>,
        MonadNameRecord<Self::SignatureType>,
    >;
}

pub trait PeerDiscoveryAlgoBuilder {
    type PeerDiscoveryAlgoType: PeerDiscoveryAlgo;

    fn build(
        self,
    ) -> (
        Self::PeerDiscoveryAlgoType,
        Vec<
            PeerDiscoveryCommand<<Self::PeerDiscoveryAlgoType as PeerDiscoveryAlgo>::SignatureType>,
        >,
    );
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use monad_secp::{KeyPair, SecpSignature};

    use super::*;

    #[test]
    fn test_name_record_v4_rlp() {
        let name_record = NameRecord::new(Ipv4Addr::from_str("1.1.1.1").unwrap(), 8000, 8001, 0, 2);

        let mut encoded = Vec::new();
        name_record.encode(&mut encoded);

        let result = NameRecord::decode(&mut encoded.as_slice());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), name_record);
    }

    #[test]
    fn test_name_record_validation() {
        let name_record = NameRecord::new(Ipv4Addr::from_str("1.1.1.1").unwrap(), 8000, 8001, 0, 1);

        assert_eq!(
            name_record.tcp_socket(),
            SocketAddrV4::from_str("1.1.1.1:8000").unwrap()
        );
        assert_eq!(
            name_record.udp_socket(),
            SocketAddrV4::from_str("1.1.1.1:8001").unwrap()
        );
    }

    #[test]
    fn test_name_record_duplicate_port_validation() {
        let wire = WireNameRecord {
            ip: Ipv4Addr::from_str("1.1.1.1").unwrap(),
            ports: vec![
                Port::new(PortTag::TCP, 8000),
                Port::new(PortTag::UDP, 8001),
                Port::new(PortTag::TCP, 8002),
            ],
            capabilities: 0,
            seq: 1,
        };

        let mut encoded = Vec::new();
        wire.encode(&mut encoded);

        let decoded = NameRecord::decode(&mut encoded.as_slice());
        assert!(decoded.is_err());
    }

    #[test]
    fn test_name_record_missing_port_validation() {
        let wire = WireNameRecord {
            ip: Ipv4Addr::from_str("1.1.1.1").unwrap(),
            ports: vec![Port::new(PortTag::TCP, 8000)],
            capabilities: 0,
            seq: 1,
        };

        let mut encoded = Vec::new();
        wire.encode(&mut encoded);

        let decoded = NameRecord::decode(&mut encoded.as_slice());
        assert!(decoded.is_err());
    }

    #[test]
    fn test_name_record_encode_snapshot() {
        let name_record = NameRecord::new(
            Ipv4Addr::from_str("192.168.1.1").unwrap(),
            8080,
            8081,
            0,
            42,
        );

        let mut encoded = Vec::new();
        name_record.encode(&mut encoded);
        let hex_encoded = hex::encode(&encoded);
        insta::assert_snapshot!(hex_encoded);
    }

    #[test]
    fn test_name_record_roundtrip() {
        let original = NameRecord::new(
            Ipv4Addr::from_str("172.16.0.1").unwrap(),
            7000,
            7001,
            255,
            999,
        );

        let mut encoded = Vec::new();
        original.encode(&mut encoded);

        let decoded = NameRecord::decode(&mut encoded.as_slice()).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_wire_name_record_compatibility() {
        let name_record =
            NameRecord::new(Ipv4Addr::from_str("127.0.0.1").unwrap(), 8000, 8001, 0, 1);

        let mut encoded = Vec::new();
        name_record.encode(&mut encoded);

        let wire = WireNameRecord::decode(&mut encoded.as_slice()).unwrap();
        assert_eq!(wire.ports.len(), 2);
        assert_eq!(wire.ports[0].tag, PortTag::TCP as u8);
        assert_eq!(wire.ports[0].port, 8000);
        assert_eq!(wire.ports[1].tag, PortTag::UDP as u8);
        assert_eq!(wire.ports[1].port, 8001);
    }

    #[test]
    fn test_name_record_with_unknown_ports_and_capabilities() {
        let wire = WireNameRecord {
            ip: Ipv4Addr::from_str("10.0.0.1").unwrap(),
            ports: vec![
                Port::new(PortTag::TCP, 9000),
                Port::new(PortTag::UDP, 9001),
                Port { tag: 2, port: 9002 },
                Port { tag: 5, port: 9005 },
            ],
            capabilities: 7,
            seq: 100,
        };

        let mut wire_encoded = Vec::new();
        wire.encode(&mut wire_encoded);

        let decoded = NameRecord::decode(&mut wire_encoded.as_slice()).unwrap();

        assert_eq!(decoded.ip(), Ipv4Addr::from_str("10.0.0.1").unwrap());
        assert_eq!(decoded.tcp_port(), 9000);
        assert_eq!(decoded.udp_port(), 9001);
        assert_eq!(decoded.capabilities(), 7);
        assert_eq!(decoded.seq(), 100);

        let mut reencoded = Vec::new();
        decoded.encode(&mut reencoded);
        assert_eq!(wire_encoded, reencoded);

        let keypair = KeyPair::from_ikm(b"test keypair for signature veri").unwrap();
        let signature = SecpSignature::sign::<signing_domain::NameRecord>(&wire_encoded, &keypair);

        let signed_record = MonadNameRecord::<SecpSignature> {
            name_record: decoded,
            signature,
        };

        let recovered_node_id = signed_record.recover_pubkey().unwrap();
        let expected_node_id = NodeId::new(keypair.pubkey());

        assert_eq!(recovered_node_id, expected_node_id);
    }
}
