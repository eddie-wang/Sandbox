//! App traffic reverse proxy, after AgentENV's gateway (`host_route.go`, streaming `server.go`) and
//! node proxy (`src/api/proxy.rs`). The controller accepts `<port>-<sandbox-id>.<proxy_domain>` hosts
//! and the path form `/v1/sandboxes/<id>/proxy/<port>/<path>`, authenticates the management bearer
//! token and streams the exchange to the owning worker. The worker opens a fresh connection to the
//! guest's fixed address from inside the sandbox's routing namespace (never the host network), for
//! template-approved service ports only. Bodies stream both ways, statuses and headers are real, and a
//! 101 answer to an upgrade request (WebSocket) becomes a byte tunnel. The management Authorization
//! header never reaches the sandbox. Open exchanges are bounded and end after an idle period while
//! the receiving side keeps reading; there is no total deadline.
use std::{fs::File, future::Future, os::fd::{AsRawFd, FromRawFd, OwnedFd}, path::PathBuf, pin::Pin, sync::{Arc, Mutex, PoisonError}, task::{Context, Poll}, time::Duration};
use axum::{body::{Body, Bytes}, extract::Request, http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header}, response::{IntoResponse, Response}};
use hyper::body::{Body as HttpBody, Frame, SizeHint};
use hyper_util::rt::TokioIo;
use tokio::{io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt}, sync::{OwnedSemaphorePermit, watch}, time::Instant};
use crate::{http::ApiError, model::sandbox_owner};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
type Stop = Pin<Box<dyn Future<Output = ()> + Send>>;

// AgentENV's node proxy connect timeout to a guest service.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const PATH_PREFIX: &str = "/v1/sandboxes/";

// Decide whether a request path is the path form of the app proxy (`/v1/sandboxes/<id>/proxy/...`).
pub fn is_proxy_path(path: &str) -> bool {
    path.strip_prefix(PATH_PREFIX).and_then(|rest| rest.split('/').nth(1)) == Some("proxy")
}

// Read a decimal service port without sign or leading zeros (1-65535).
fn port_number(text: &str) -> Option<u16> {
    text.parse::<u16>().ok().filter(|port| *port != 0 && port.to_string() == text)
}

// Split a path-form proxy path into the sandbox ID, the guest port and the application path (at least
// "/"). Returns nothing if the ID or port is invalid.
pub fn parse(path: &str) -> Option<(String, u16, String)> {
    let (id, rest) = path.strip_prefix(PATH_PREFIX)?.split_once('/')?;
    let rest = rest.strip_prefix("proxy/")?;
    let (port, app) = rest.find('/').map_or((rest, "/"), |at| (&rest[..at], &rest[at..]));
    sandbox_owner(id)?;
    Some((id.to_owned(), port_number(port)?, app.to_owned()))
}

// Accept a lowercase DNS name (labels of letters, digits and inner hyphens) as the proxy domain.
pub fn valid_domain(domain: &str) -> bool {
    domain.len() <= 253 && domain.split('.').all(|label| {
        let bytes = label.as_bytes();
        !bytes.is_empty() && bytes.len() <= 63 && bytes.iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
            && bytes[0] != b'-' && bytes[bytes.len() - 1] != b'-'
    })
}

// Read an AgentENV-style host route `<port>-<sandbox-id>.<domain>` from the Host header (the port
// after a colon and a trailing dot are ignored; the domain matches case-insensitively). Returns
// nothing when the host is not below the domain, is the domain itself or has no hyphen, and an error
// when it is below it but the port or sandbox ID is malformed.
pub fn host_route(headers: &HeaderMap, domain: &str) -> Result<Option<(String, u16)>, ()> {
    let Some(host) = headers.get(header::HOST).and_then(|value| value.to_str().ok()) else { return Ok(None) };
    let host = host.trim();
    let host = host.rsplit_once(':').filter(|(_, port)| !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit())).map_or(host, |(name, _)| name);
    let host = host.strip_suffix('.').unwrap_or(host);
    let Some(split) = host.len().checked_sub(domain.len() + 1).filter(|at| *at > 0 && host.is_char_boundary(*at)) else { return Ok(None) };
    let (label, suffix) = host.split_at(split);
    if !suffix.strip_prefix('.').is_some_and(|suffix| suffix.eq_ignore_ascii_case(domain)) { return Ok(None); }
    // The port has no hyphen, so the first one ends it; a label without one is not a route (AgentENV
    // parseHostRoute).
    let Some((port, id)) = label.split_once('-') else { return Ok(None) };
    match (port_number(port), sandbox_owner(id)) {
        (Some(port), Some(_)) => Ok(Some((id.to_owned(), port))),
        _ => Err(()),
    }
}

// Decide whether the client asks to switch protocols (Connection names "upgrade" and an Upgrade
// header is present), as WebSocket does.
pub fn upgrade_requested(headers: &HeaderMap) -> bool {
    headers.contains_key(header::UPGRADE) && headers.get_all(header::CONNECTION).iter()
        .filter_map(|value| value.to_str().ok()).flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
}

// Remove hop-by-hop headers, every header the Connection header names and proxy credentials
// (AgentENV remove_hop_by_hop_headers). Keep `te: trailers` (as Go's reverse proxy does) and, for an
// upgrade, `connection: upgrade` with the Upgrade header so the next hop can switch protocols.
pub fn strip_hop_headers(headers: &mut HeaderMap, upgrade: bool) {
    let named: Vec<HeaderName> = headers.get_all(header::CONNECTION).iter().filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(',')).filter_map(|token| HeaderName::from_bytes(token.trim().as_bytes()).ok()).collect();
    let protocol = headers.get(header::UPGRADE).cloned();
    let trailers = headers.get_all(header::TE).iter().filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(',')).any(|token| token.trim().eq_ignore_ascii_case("trailers"));
    for name in [header::CONNECTION, header::UPGRADE, header::TE, header::TRAILER, header::TRANSFER_ENCODING, header::PROXY_AUTHENTICATE, header::PROXY_AUTHORIZATION] {
        headers.remove(name);
    }
    for name in named { headers.remove(name); }
    headers.remove("keep-alive");
    if trailers { headers.insert(header::TE, HeaderValue::from_static("trailers")); }
    if let Some(protocol) = protocol.filter(|_| upgrade) {
        headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
        headers.insert(header::UPGRADE, protocol);
    }
}

// Turn an optional "sandbox closed" signal into a future that finishes when the worker drops the
// sender (sandbox deletion), or never.
fn stop_future(stop: Option<watch::Receiver<()>>) -> Stop {
    Box::pin(async move {
        match stop {
            Some(mut stop) => while stop.changed().await.is_ok() {},
            None => std::future::pending().await,
        }
    })
}

// A streamed body that fails when no frame arrives within the idle timeout or when its sandbox is
// closed, reports upload progress to the response-head wait, and holds the exchange's connection
// permit until it ends. Both checks run only when the receiving side asks for the next frame: a
// receiver that stops reading is not timed out, and sees the close only at its next read. The mutex
// is never locked across a wait; it only makes the body shareable.
pub struct Tracked<B>(Mutex<TrackedState<B>>);
struct TrackedState<B> {
    inner: B, idle: Duration, timer: Pin<Box<tokio::time::Sleep>>, stop: Stop,
    activity: Option<watch::Sender<()>>, _permit: Arc<OwnedSemaphorePermit>,
}
impl<B> Tracked<B> {
    // Wrap a body with its idle timeout, optional close signal, optional progress channel and permit.
    pub fn new(inner: B, idle: Duration, stop: Option<watch::Receiver<()>>, activity: Option<watch::Sender<()>>, permit: Arc<OwnedSemaphorePermit>) -> Self {
        Self(Mutex::new(TrackedState { inner, idle, timer: Box::pin(tokio::time::sleep(idle)), stop: stop_future(stop), activity, _permit: permit }))
    }
}
impl<B> HttpBody for Tracked<B> where B: HttpBody<Data = Bytes> + Unpin, B::Error: Into<BoxError> {
    type Data = Bytes;
    type Error = BoxError;
    // Pass the next frame through, restarting the idle timer; fail on a closed sandbox or an idle
    // timeout. The end of the body closes the progress channel.
    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let state = self.get_mut().0.get_mut().unwrap_or_else(PoisonError::into_inner);
        if state.stop.as_mut().poll(cx).is_ready() { return Poll::Ready(Some(Err("sandbox_closed".into()))); }
        match Pin::new(&mut state.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                let deadline = Instant::now() + state.idle;
                state.timer.as_mut().reset(deadline);
                if frame.is_data() { if let Some(activity) = &state.activity { let _ = activity.send(()); } }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(error.into()))),
            Poll::Ready(None) => { state.activity = None; Poll::Ready(None) }
            Poll::Pending if state.timer.as_mut().poll(cx).is_ready() => Poll::Ready(Some(Err("idle_timeout".into()))),
            Poll::Pending => Poll::Pending,
        }
    }
    // Report the wrapped body's end, so empty bodies stay empty on the next hop.
    fn is_end_stream(&self) -> bool { self.0.lock().is_ok_and(|state| state.inner.is_end_stream()) }
    // Report the wrapped body's size, so a known Content-Length is kept on the next hop.
    fn size_hint(&self) -> SizeHint { self.0.lock().map_or_else(|_| SizeHint::default(), |state| state.inner.size_hint()) }
}

// How the wait for an upstream response head ended.
enum Head<T> { Ready(T), Idle, Closed }

// Wait for the upstream response head (AgentENV pattern): the idle timer restarts whenever the request
// body sends data; once the body is done, the head must arrive within one more idle period. The close
// signal is checked first, so a closed sandbox never gets a head through.
async fn head<F: Future>(response: F, mut activity: watch::Receiver<()>, idle: Duration, closed: &mut Stop) -> Head<F::Output> {
    let mut response = std::pin::pin!(response);
    let mut timer = std::pin::pin!(tokio::time::sleep(idle));
    let mut uploading = true;
    loop {
        tokio::select! {
            biased;
            _ = &mut *closed => return Head::Closed,
            result = &mut response => return Head::Ready(result),
            _ = &mut timer => return Head::Idle,
            changed = activity.changed(), if uploading => {
                uploading = changed.is_ok();
                timer.as_mut().reset(Instant::now() + idle);
            }
        }
    }
}

// Copy bytes both ways between an upgraded client connection and the upstream one until both sides
// close, nothing moves for one idle period (reads or a blocked write) or the sandbox is closed. The
// permit is held until then.
async fn tunnel<A, B>(client: A, upstream: B, idle: Duration, stop: Option<watch::Receiver<()>>, _permit: Arc<OwnedSemaphorePermit>)
where A: AsyncRead + AsyncWrite + Unpin, B: AsyncRead + AsyncWrite + Unpin {
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);
    let mut stop = stop_future(stop);
    let (mut up, mut down) = (vec![0u8; 16384], vec![0u8; 16384]);
    let (mut client_open, mut upstream_open) = (true, true);
    while client_open || upstream_open {
        tokio::select! {
            read = client_read.read(&mut up), if client_open => match read {
                Ok(n) if n > 0 => if !matches!(tokio::time::timeout(idle, upstream_write.write_all(&up[..n])).await, Ok(Ok(()))) { return; },
                _ => { client_open = false; let _ = upstream_write.shutdown().await; }
            },
            read = upstream_read.read(&mut down), if upstream_open => match read {
                Ok(n) if n > 0 => if !matches!(tokio::time::timeout(idle, client_write.write_all(&down[..n])).await, Ok(Ok(()))) { return; },
                _ => { upstream_open = false; let _ = client_write.shutdown().await; }
            },
            _ = tokio::time::sleep(idle) => return,
            _ = &mut stop => return,
        }
    }
}

// Answer a proxy-side failure with the safe error envelope (never an upstream error body).
fn failed(status: StatusCode, code: &'static str, message: &'static str) -> Response {
    ApiError(status, code, message).into_response()
}

// Threads that only create sockets inside routing namespaces for the app proxy (see
// namespace_socket), and how many requests may wait for them.
const CONNECTORS: usize = 4;
const CONNECTOR_QUEUE: usize = 1024;
// One socket request: the routing namespace pin and where to send the socket.
type SocketRequest = (PathBuf, tokio::sync::oneshot::Sender<Option<OwnedFd>>);

// Start bounded socket-making threads on first use. Each enters only the requested namespace,
// creates a socket and returns home, never retaining a released slot while idle. Failed entry
// returns no socket; failed return ends the thread. No shared runtime thread changes namespace.
fn connectors() -> Option<&'static std::sync::mpsc::SyncSender<SocketRequest>> {
    static MAILBOX: std::sync::OnceLock<Option<std::sync::mpsc::SyncSender<SocketRequest>>> = std::sync::OnceLock::new();
    MAILBOX.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::sync_channel::<SocketRequest>(CONNECTOR_QUEUE);
        let rx = Arc::new(Mutex::new(rx));
        for index in 0..CONNECTORS {
            let rx = rx.clone();
            let home = File::open("/proc/thread-self/ns/net").ok()?;
            std::thread::Builder::new().name(format!("sandbox-proxy-netns-{index}")).spawn(move || loop {
                let next = rx.lock().unwrap_or_else(PoisonError::into_inner).recv();
                let Ok((netns, reply)) = next else { return };
                let mut entered = false;
                let socket = File::open(&netns).ok().and_then(|namespace| {
                    if unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET) } != 0 { return None; }
                    entered = true;
                    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };
                    (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd) })
                });
                let _ = reply.send(socket);
                if entered && unsafe { libc::setns(home.as_raw_fd(), libc::CLONE_NEWNET) } != 0 { return; }
            }).ok()?;
        }
        Some(tx)
    }).as_ref()
}

// Create a TCP socket inside the routing namespace pinned at `netns` on one of the connector threads,
// so no thread that serves other work ever changes namespace; the socket stays in that namespace. A
// full connector queue yields no socket.
async fn namespace_socket(netns: PathBuf) -> Option<OwnedFd> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    connectors()?.try_send((netns, tx)).ok()?;
    rx.await.ok().flatten()
}

// Worker side: forward one request to guest `port` over a fresh connection opened inside the routing
// namespace `netns`, sending `app` (path and query) with Host set to the guest address and without
// the Authorization header. Stream both bodies; a 101 answer to an upgrade request becomes a byte
// tunnel. The idle timeout covers the response head, both bodies and the tunnel; `stop` (sandbox
// deletion or expiry) ends the exchange while it is connecting, waiting for the head or tunnelling,
// and a body at its next read, so a pooled slot never carries it to the slot's next sandbox; `permit`
// is held until it ends.
pub async fn to_sandbox(netns: PathBuf, port: u16, app: String, mut request: Request, idle: Duration, stop: watch::Receiver<()>, permit: OwnedSemaphorePermit) -> Response {
    let upgrade = upgrade_requested(request.headers());
    let client_upgrade = upgrade.then(|| hyper::upgrade::on(&mut request));
    let (parts, body) = request.into_parts();
    let mut headers = parts.headers;
    strip_hop_headers(&mut headers, upgrade);
    headers.remove(header::AUTHORIZATION);
    let guest = std::net::SocketAddr::from((crate::network::GUEST.parse::<std::net::Ipv4Addr>().expect("fixed guest address"), port));
    headers.insert(header::HOST, HeaderValue::from_str(&guest.to_string()).expect("socket address is a valid header"));
    let unavailable = || failed(StatusCode::BAD_GATEWAY, "upstream_unavailable", "The sandbox service did not accept or answer the connection");
    let mut closed = stop_future(Some(stop.clone()));
    let socket = tokio::select! {
        biased;
        _ = &mut closed => None,
        fd = namespace_socket(netns) => fd,
    };
    let Some(fd) = socket else { return unavailable() };
    let socket = tokio::net::TcpSocket::from_std_stream(std::net::TcpStream::from(fd));
    let stream = tokio::select! {
        biased;
        _ = &mut closed => return unavailable(),
        connected = tokio::time::timeout(CONNECT_TIMEOUT, socket.connect(guest)) => match connected {
            Ok(Ok(stream)) => stream,
            _ => return unavailable(),
        },
    };
    let _ = stream.set_nodelay(true);
    let permit = Arc::new(permit);
    let (activity_tx, activity_rx) = watch::channel(());
    let body = Tracked::new(body, idle, Some(stop.clone()), Some(activity_tx), permit.clone());
    let Ok((mut sender, connection)) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await else { return unavailable() };
    // One request per connection (AgentENV disables pooling: guest addresses are reused).
    tokio::spawn(connection.with_upgrades());
    let Ok(mut upstream) = hyper::Request::builder().method(parts.method).uri(app).body(body) else {
        return failed(StatusCode::BAD_REQUEST, "invalid_input", "Invalid application request target");
    };
    *upstream.headers_mut() = headers;
    let mut response = match head(sender.send_request(upstream), activity_rx, idle, &mut closed).await {
        Head::Idle => return failed(StatusCode::GATEWAY_TIMEOUT, "upstream_timeout", "The sandbox service sent nothing within the proxy idle timeout"),
        Head::Closed | Head::Ready(Err(_)) => return unavailable(),
        Head::Ready(Ok(response)) => response,
    };
    if response.status() == StatusCode::SWITCHING_PROTOCOLS {
        let Some(client_upgrade) = client_upgrade else { return unavailable() };
        let upstream_upgrade = hyper::upgrade::on(&mut response);
        tokio::spawn(async move {
            if let Ok((Ok(client), Ok(upstream))) = tokio::time::timeout(idle, async { tokio::join!(client_upgrade, upstream_upgrade) }).await {
                tunnel(TokioIo::new(client), TokioIo::new(upstream), idle, Some(stop), permit).await;
            }
        });
        let (mut parts, _) = response.into_parts();
        strip_hop_headers(&mut parts.headers, true);
        return Response::from_parts(parts, Body::empty());
    }
    let (mut parts, body) = response.into_parts();
    strip_hop_headers(&mut parts.headers, false);
    Response::from_parts(parts, Body::new(Tracked::new(body, idle, Some(stop), None, permit)))
}

// Controller side: forward one app or streaming exec exchange to the owner's `url` over the proxy
// client with the worker credential instead of the client's. Client-supplied forwarding headers are
// replaced by X-Forwarded-Host (the original host) and X-Forwarded-Proto. Stream the answer back; a
// 101 answer to an upgrade request becomes a byte tunnel. The idle timeout covers the response head,
// both bodies and the tunnel; `permit` is held until the exchange ends.
pub async fn to_owner(client: &reqwest::Client, url: reqwest::Url, token: &str, mut request: Request, idle: Duration, permit: OwnedSemaphorePermit) -> Response {
    if request.method() == Method::CONNECT { return failed(StatusCode::BAD_REQUEST, "invalid_input", "CONNECT is not proxied"); }
    let upgrade = upgrade_requested(request.headers());
    let client_upgrade = upgrade.then(|| hyper::upgrade::on(&mut request));
    let (parts, body) = request.into_parts();
    let mut headers = parts.headers;
    let original_host = headers.get(header::HOST).cloned();
    strip_hop_headers(&mut headers, upgrade);
    let forwarded: Vec<HeaderName> = headers.keys().filter(|name| name.as_str().starts_with("x-forwarded-") || name.as_str() == "forwarded").cloned().collect();
    for name in forwarded { headers.remove(name); }
    headers.remove(header::HOST);
    let Ok(credential) = HeaderValue::from_str(&format!("Bearer {token}")) else {
        return failed(StatusCode::INTERNAL_SERVER_ERROR, "credential_unusable", "Worker credential cannot be sent");
    };
    headers.insert(header::AUTHORIZATION, credential);
    if let Some(host) = original_host { headers.insert("x-forwarded-host", host); }
    headers.insert("x-forwarded-proto", HeaderValue::from_static("http"));
    let permit = Arc::new(permit);
    let (activity_tx, activity_rx) = watch::channel(());
    let body = reqwest::Body::wrap(Tracked::new(body, idle, None, Some(activity_tx), permit.clone()));
    let send = client.request(parts.method, url).headers(headers).body(body).send();
    let response = match head(send, activity_rx, idle, &mut stop_future(None)).await {
        Head::Idle => return failed(StatusCode::GATEWAY_TIMEOUT, "owner_response_timeout", "Owner sent nothing within the proxy idle timeout"),
        Head::Closed | Head::Ready(Err(_)) => return failed(StatusCode::SERVICE_UNAVAILABLE, "owner_response_unavailable", "Owner connection failed or was lost"),
        Head::Ready(Ok(response)) => response,
    };
    if response.status() == StatusCode::SWITCHING_PROTOCOLS {
        let Some(client_upgrade) = client_upgrade else {
            return failed(StatusCode::SERVICE_UNAVAILABLE, "owner_response_unavailable", "Owner switched protocols without an upgrade request");
        };
        let (status, mut headers) = (response.status(), response.headers().clone());
        strip_hop_headers(&mut headers, true);
        tokio::spawn(async move {
            if let Ok((Ok(client), Ok(upstream))) = tokio::time::timeout(idle, async { tokio::join!(client_upgrade, response.upgrade()) }).await {
                tunnel(TokioIo::new(client), upstream, idle, None, permit).await;
            }
        });
        let mut answer = Response::new(Body::empty());
        *answer.status_mut() = status;
        *answer.headers_mut() = headers;
        return answer;
    }
    let response: axum::http::Response<reqwest::Body> = response.into();
    let (mut parts, body) = response.into_parts();
    strip_hop_headers(&mut parts.headers, false);
    Response::from_parts(parts, Body::new(Tracked::new(body, idle, None, None, permit)))
}
