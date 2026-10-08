//! atproto as vlpds and vlRelay both speak it: the repo data model
//! ([`cbor`], [`cid`], [`tid`], [`car`], [`car_order`], [`mst`]), K-256
//! keys ([`crypto`]), firehose frames ([`events`]), PLC operations
//! ([`plc`]), identifier syntax ([`syntax`]), DID resolution
//! ([`did_resolver`]) over the shared outbound clients ([`http`]), and XRPC
//! errors ([`xrpc`]).

pub mod car;
pub mod car_order;
pub mod cbor;
pub mod cid;
pub mod crypto;
pub mod did_resolver;
pub mod events;
pub mod http;
pub mod mst;
pub mod plc;
pub mod syntax;
pub mod tid;
pub mod xrpc;
