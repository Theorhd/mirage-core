//! Socket tuning, large-backlog TCP listener setup, UDP buffer sizing, and
//! high-throughput DirectCopy relay (Linux `splice(2)` zero-copy with automatic
//! 64 KiB userspace fallback).

use core::future::Future;
use core::net::SocketAddr;
use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;
use std::io;

use socket2::{Domain, Protocol, SockAddr, SockRef, Socket, TcpKeepalive, Type};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Notify;

use crate::metrics::Metrics;

/// Userspace DirectCopy chunk size (`64 KiB`) used on non-Linux hosts or when
/// Linux `splice(2)` is unavailable.
pub const DIRECT_COPY_CHUNK_SIZE: usize = 64 * 1024;

/// Default UDP socket receive/send buffer request (`2 MiB`) for bursty QUIC / XUDP traffic.
/// The OS kernel silently clamps this to `net.core.{rmem,wmem}_max`.
pub const UDP_SOCKET_BUFFER_BYTES: usize = 2 * 1024 * 1024;

/// Creates and binds a non-blocking `TcpListener` with `SO_REUSEADDR` and an
/// explicit accept backlog (minimum `128`).
pub fn bind_tcp_listener(addr: SocketAddr, backlog: i32) -> io::Result<TcpListener> {
    let domain = Domain::for_address(addr);
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&SockAddr::from(addr))?;
    socket.listen(backlog.max(128))?;
    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener)
}

/// Applies low-latency and dead-peer-detection TCP socket options:
/// - `TCP_NODELAY = true`
/// - `SO_KEEPALIVE` with idle/interval/retry probes (when `keepalive_idle > 0`)
/// - `TCP_USER_TIMEOUT` on Linux so stalled mobile/CGNAT links fail fast
pub fn tune_tcp_stream(stream: &TcpStream, keepalive_idle: Duration) {
    let _ = stream.set_nodelay(true);
    if keepalive_idle.is_zero() {
        return;
    }

    let sock = SockRef::from(stream);
    let interval = keepalive_idle
        .checked_div(3)
        .unwrap_or(Duration::from_secs(10))
        .max(Duration::from_secs(5));

    let mut ka = TcpKeepalive::new()
        .with_time(keepalive_idle)
        .with_interval(interval);

    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "ios"
    ))]
    {
        ka = ka.with_retries(3);
    }

    let _ = sock.set_tcp_keepalive(&ka);

    #[cfg(target_os = "linux")]
    {
        let user_timeout = keepalive_idle
            .saturating_mul(2)
            .clamp(Duration::from_secs(15), Duration::from_secs(60));
        let _ = sock.set_tcp_user_timeout(Some(user_timeout));
    }
}

/// Requests larger kernel receive/send buffers on a `UdpSocket` (best-effort;
/// clamped by OS sysctl limits).
pub fn tune_udp_socket(sock: &UdpSocket, buf_size: usize) {
    let sock_ref = SockRef::from(sock);
    let _ = sock_ref.set_recv_buffer_size(buf_size);
    let _ = sock_ref.set_send_buffer_size(buf_size);
}

/// Zero-allocation half-close signal shared between the uplink and downlink
/// futures of a bidirectional TCP relay.
///
/// When one direction finishes, calling [`HalfCloseSignal::mark_closed`]
/// immediately wakes the opposite direction if it is parked inside a long
/// `idle_timeout` wait, clamping its remaining wait time to `half_close_timeout`.
#[derive(Debug)]
pub struct HalfCloseSignal {
    closed: AtomicBool,
    notify: Notify,
}

impl Default for HalfCloseSignal {
    fn default() -> Self {
        Self::new()
    }
}

impl HalfCloseSignal {
    /// Creates an open `HalfCloseSignal` with zero heap allocations.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            closed: AtomicBool::new(false),
            notify: Notify::const_new(),
        }
    }

    /// Returns `true` if one direction of the relay has already closed.
    #[inline]
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Marks the relay as half-closed and wakes any in-flight `idle_timeout` wait
    /// so it tightens immediately to `half_close_timeout`.
    #[inline]
    pub fn mark_closed(&self) {
        if !self.closed.swap(true, Ordering::Release) {
            self.notify.notify_waiters();
        }
    }
}

/// Error returned by [`timeout_with_half_close`] when the idle or half-close
/// deadline expires before the inner I/O future completes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayElapsed;

/// Runs a cancel-safe I/O future bounded by `idle_timeout`, tightening reactively
/// to `half_close_timeout` even if `peer_closed` transitions while `fut` is already
/// suspended in a long idle wait.
pub async fn timeout_with_half_close<F, T>(
    idle_timeout: Duration,
    half_close_timeout: Duration,
    peer_closed: &HalfCloseSignal,
    fut: F,
) -> Result<T, RelayElapsed>
where
    F: Future<Output = T>,
{
    let short_dur = half_close_timeout.min(idle_timeout);
    if peer_closed.is_closed() {
        return tokio::time::timeout(short_dur, fut)
            .await
            .map_err(|_| RelayElapsed);
    }

    let notified = peer_closed.notify.notified();
    tokio::pin!(notified);
    // Register the waiter before re-checking `is_closed()` to prevent lost wakeups.
    notified.as_mut().enable();

    if peer_closed.is_closed() {
        return tokio::time::timeout(short_dur, fut)
            .await
            .map_err(|_| RelayElapsed);
    }

    let deadline = async {
        tokio::select! {
            () = tokio::time::sleep(idle_timeout) => {}
            () = async {
                notified.await;
                tokio::time::sleep(short_dur).await;
            } => {}
        }
    };

    tokio::select! {
        res = fut => Ok(res),
        () = deadline => Err(RelayElapsed),
    }
}

/// Copies bytes between two half-split TCP streams with adaptive idle/half-close
/// timeouts. Uses Linux kernel zero-copy `splice(2)` when available, falling back
/// transparently to a 64 KiB heap-buffered userspace copy.
pub async fn relay_direct_copy(
    reader: &mut OwnedReadHalf,
    writer: &mut OwnedWriteHalf,
    idle_timeout: Duration,
    half_close_timeout: Duration,
    peer_closed: &HalfCloseSignal,
    metrics: &Metrics,
) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        match splice_direct_copy(
            reader,
            writer,
            idle_timeout,
            half_close_timeout,
            peer_closed,
            metrics,
        )
        .await
        {
            Ok(()) => return Ok(()),
            Err(SpliceOutcome::Unsupported) => {
                // Seccomp or kernel denied splice(2); fall back seamlessly to userspace copy.
            }
            Err(SpliceOutcome::Io(err)) => return Err(err),
        }
    }

    userspace_direct_copy(
        reader,
        writer,
        idle_timeout,
        half_close_timeout,
        peer_closed,
        metrics,
    )
    .await
}

async fn userspace_direct_copy(
    reader: &mut OwnedReadHalf,
    writer: &mut OwnedWriteHalf,
    idle_timeout: Duration,
    half_close_timeout: Duration,
    peer_closed: &HalfCloseSignal,
    metrics: &Metrics,
) -> io::Result<()> {
    let mut buf = vec![0u8; DIRECT_COPY_CHUNK_SIZE];
    loop {
        match timeout_with_half_close(
            idle_timeout,
            half_close_timeout,
            peer_closed,
            reader.read(&mut buf),
        )
        .await
        {
            Ok(Ok(0)) => return Ok(()),
            Ok(Ok(n)) => {
                let Some(slice) = buf.get(..n) else {
                    return Ok(());
                };
                match timeout_with_half_close(
                    idle_timeout,
                    half_close_timeout,
                    peer_closed,
                    writer.write_all(slice),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => return Err(err),
                    Err(RelayElapsed) => {
                        metrics.inc_idle_timeouts();
                        return Ok(());
                    }
                }
            }
            Ok(Err(err)) => return Err(err),
            Err(RelayElapsed) => {
                metrics.inc_idle_timeouts();
                return Ok(());
            }
        }
    }
}

#[cfg(target_os = "linux")]
enum SpliceOutcome {
    Unsupported,
    Io(io::Error),
}

#[cfg(target_os = "linux")]
const SPLICE_CHUNK_SIZE: usize = 64 * 1024;

#[cfg(target_os = "linux")]
const SPLICE_PIPE_SIZE: usize = 128 * 1024;

#[cfg(target_os = "linux")]
fn is_splice_unsupported(err: rustix::io::Errno) -> bool {
    matches!(
        err,
        rustix::io::Errno::NOSYS
            | rustix::io::Errno::PERM
            | rustix::io::Errno::INVAL
            | rustix::io::Errno::OPNOTSUPP
    )
}

#[cfg(target_os = "linux")]
async fn splice_direct_copy(
    reader: &mut OwnedReadHalf,
    writer: &mut OwnedWriteHalf,
    idle_timeout: Duration,
    half_close_timeout: Duration,
    peer_closed: &HalfCloseSignal,
    metrics: &Metrics,
) -> Result<(), SpliceOutcome> {
    use rustix::pipe::{fcntl_setpipe_size, pipe_with, splice, PipeFlags, SpliceFlags};
    use tokio::io::Interest;

    let (pipe_r, pipe_w) = pipe_with(PipeFlags::NONBLOCK | PipeFlags::CLOEXEC)
        .map_err(|_| SpliceOutcome::Unsupported)?;
    let _ = fcntl_setpipe_size(&pipe_w, SPLICE_PIPE_SIZE);

    let flags = SpliceFlags::NONBLOCK | SpliceFlags::MOVE;
    let mut counted = false;

    loop {
        let mut in_pipe = 0usize;

        // 1. Splice from reader socket into kernel pipe.
        while in_pipe == 0 {
            match timeout_with_half_close(
                idle_timeout,
                half_close_timeout,
                peer_closed,
                reader.readable(),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(err)) => return Err(SpliceOutcome::Io(err)),
                Err(RelayElapsed) => {
                    metrics.inc_idle_timeouts();
                    return Ok(());
                }
            }

            let mut unsupported = false;
            let res = reader.as_ref().try_io(Interest::READABLE, || {
                match splice(
                    reader.as_ref(),
                    None,
                    &pipe_w,
                    None,
                    SPLICE_CHUNK_SIZE,
                    flags,
                ) {
                    Ok(n) => Ok(n),
                    Err(e)
                        if e == rustix::io::Errno::AGAIN || e == rustix::io::Errno::WOULDBLOCK =>
                    {
                        Err(io::Error::from(io::ErrorKind::WouldBlock))
                    }
                    Err(e) if is_splice_unsupported(e) => {
                        unsupported = true;
                        Err(io::Error::from(io::ErrorKind::Unsupported))
                    }
                    Err(e) => Err(io::Error::from_raw_os_error(e.raw_os_error())),
                }
            });

            match res {
                Ok(0) => return Ok(()),
                Ok(n) => {
                    if !counted {
                        metrics.inc_splice_direct_copies();
                        counted = true;
                    }
                    in_pipe = n;
                }
                Err(_) if unsupported => return Err(SpliceOutcome::Unsupported),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(SpliceOutcome::Io(e)),
            }
        }

        // 2. Drain all bytes from kernel pipe into writer socket.
        while in_pipe > 0 {
            match timeout_with_half_close(
                idle_timeout,
                half_close_timeout,
                peer_closed,
                writer.writable(),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(err)) => return Err(SpliceOutcome::Io(err)),
                Err(RelayElapsed) => {
                    metrics.inc_idle_timeouts();
                    return Ok(());
                }
            }

            let res = writer.as_ref().try_io(Interest::WRITABLE, || {
                match splice(&pipe_r, None, writer.as_ref(), None, in_pipe, flags) {
                    Ok(n) => Ok(n),
                    Err(e)
                        if e == rustix::io::Errno::AGAIN || e == rustix::io::Errno::WOULDBLOCK =>
                    {
                        Err(io::Error::from(io::ErrorKind::WouldBlock))
                    }
                    Err(e) => Err(io::Error::from_raw_os_error(e.raw_os_error())),
                }
            });

            match res {
                Ok(0) => {
                    return Err(SpliceOutcome::Io(io::Error::from(io::ErrorKind::WriteZero)));
                }
                Ok(n) => {
                    in_pipe = in_pipe.saturating_sub(n);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(SpliceOutcome::Io(e)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn binds_listener_tunes_sockets_and_relays_direct_copy() {
        let Ok(listener) = bind_tcp_listener(SocketAddr::from(([127, 0, 0, 1], 0)), 1024) else {
            return;
        };
        let Ok(addr) = listener.local_addr() else {
            return;
        };

        let server = tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            tune_tcp_stream(&stream, Duration::from_secs(30));
            let (mut r, mut w) = stream.into_split();
            let closed = HalfCloseSignal::new();
            let metrics = Metrics::new();
            let _ = relay_direct_copy(
                &mut r,
                &mut w,
                Duration::from_secs(5),
                Duration::from_secs(1),
                &closed,
                &metrics,
            )
            .await;
            let _ = w.shutdown().await;
        });

        let Ok(mut client) = TcpStream::connect(addr).await else {
            return;
        };
        tune_tcp_stream(&client, Duration::from_secs(30));
        let payload = vec![0x5Au8; 96 * 1024];
        assert!(client.write_all(&payload).await.is_ok());
        assert!(client.shutdown().await.is_ok());

        let mut echoed = Vec::new();
        assert!(client.read_to_end(&mut echoed).await.is_ok());
        assert_eq!(echoed, payload);

        if let Ok(udp) = UdpSocket::bind("127.0.0.1:0").await {
            tune_udp_socket(&udp, UDP_SOCKET_BUFFER_BYTES);
        }

        let _ = server.await;
    }

    #[tokio::test]
    async fn half_close_signal_interrupts_in_flight_long_idle_wait() {
        let signal = std::sync::Arc::new(HalfCloseSignal::new());
        let signal_trigger = std::sync::Arc::clone(&signal);

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            signal_trigger.mark_closed();
        });

        let start = std::time::Instant::now();
        let res = timeout_with_half_close(
            Duration::from_secs(300),
            Duration::from_millis(30),
            &signal,
            core::future::pending::<()>(),
        )
        .await;
        assert!(res.is_err());
        assert!(start.elapsed() < Duration::from_secs(1));
    }
}
