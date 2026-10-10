//! Request/response over TCP between peers, moved here from vlRelay's quorum
//! log (`qlog::node::Rpc`) so heartbeats ([`crate::peers`]) and vlRelay share
//! one client. A message is a length-prefixed frame carrying a request id
//! its response echoes. One connection per peer, one request at a time.
//!
//! [`Faults`] partitions peers in-process for tests: a call to a blocked
//! peer waits out its timeout and fails (a blackhole, not a refusal).

use bytes::{Bytes, BytesMut};
use parking_lot::RwLock;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// A message type a peer protocol sends.
pub trait Wire: Sized + Send + Sync {
    /// Frames larger than this are refused.
    const MAX_FRAME: usize;
    /// Prefixes the frame-size error ("qlog: frame too large").
    const NAME: &'static str;
    /// The whole frame: a big-endian u32 length of the body, then the body.
    fn encode(&self, rid: u64) -> Bytes;
    /// A body (after the length prefix): its request id and message.
    fn decode(body: Bytes) -> Result<(u64, Self), &'static str>;
}

pub async fn read_frame<M: Wire, R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<(u64, M)> {
    let n = r.read_u32().await? as usize;
    if n > M::MAX_FRAME {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{}: frame too large", M::NAME)));
    }
    let mut buf = BytesMut::zeroed(n);
    r.read_exact(&mut buf).await?;
    M::decode(buf.freeze()).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

pub async fn write_frame<M: Wire, W: AsyncWrite + Unpin>(w: &mut W, rid: u64, m: &M) -> std::io::Result<()> {
    w.write_all(&m.encode(rid)).await?;
    w.flush().await
}

/// In-process partitions for tests: requests to and from a blocked peer
/// are dropped (a blackhole, not a refusal).
#[derive(Default)]
pub struct Faults {
    blocked: RwLock<HashSet<String>>,
}

impl Faults {
    pub fn block(&self, peers: &[&str]) {
        self.blocked.write().extend(peers.iter().map(|p| p.to_string()));
    }
    pub fn heal(&self) {
        self.blocked.write().clear();
    }
    pub fn blocked(&self, peer: &str) -> bool {
        self.blocked.read().contains(peer)
    }
}

#[derive(Debug)]
pub enum CallError {
    /// The port refused the connection: the process is gone.
    Refused,
    Timeout,
    Io(String),
    Blocked,
}

/// One connection to a peer, one request at a time.
pub struct Rpc<M> {
    peer: String,
    addr: String,
    conn: tokio::sync::Mutex<Option<TcpStream>>,
    rid: AtomicU64,
    faults: Arc<Faults>,
    _m: std::marker::PhantomData<fn(M) -> M>,
}

impl<M: Wire> Rpc<M> {
    pub fn new(peer: &str, addr: &str, faults: Arc<Faults>) -> Rpc<M> {
        Rpc {
            peer: peer.to_string(),
            addr: addr.to_string(),
            conn: tokio::sync::Mutex::new(None),
            rid: AtomicU64::new(1),
            faults,
            _m: std::marker::PhantomData,
        }
    }

    pub async fn call(&self, m: &M, timeout: Duration) -> Result<M, CallError> {
        if self.faults.blocked(&self.peer) {
            tokio::time::sleep(timeout).await;
            return Err(CallError::Blocked);
        }
        let mut g = self.conn.lock().await;
        let rid = self.rid.fetch_add(1, Ordering::Relaxed);
        let r = tokio::time::timeout(timeout, async {
            if g.is_none() {
                let s = TcpStream::connect(&self.addr).await.map_err(|e| {
                    if e.kind() == std::io::ErrorKind::ConnectionRefused {
                        CallError::Refused
                    } else {
                        CallError::Io(e.to_string())
                    }
                })?;
                let _ = s.set_nodelay(true);
                *g = Some(s);
            }
            let s = g.as_mut().expect("connected above");
            write_frame(s, rid, m).await.map_err(|e| CallError::Io(e.to_string()))?;
            loop {
                let (r, resp) = read_frame::<M, _>(s).await.map_err(|e| CallError::Io(e.to_string()))?;
                if r == rid {
                    return Ok(resp);
                }
            }
        })
        .await;
        match r {
            Ok(Ok(m)) => Ok(m),
            Ok(Err(e)) => {
                *g = None;
                Err(e)
            }
            Err(_) => {
                *g = None;
                Err(CallError::Timeout)
            }
        }
    }
}
