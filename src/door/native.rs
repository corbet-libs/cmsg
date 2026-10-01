//! Native HTTP projection. Host and Origin are checked independently, and every
//! response is no-store. The runtime chooses a loopback listener; no body logs.
use super::*;
use axum::{
    body::to_bytes,
    extract::{Path, Request, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use std::sync::{Arc, Mutex};

/// Injected trusted clock. Member-controlled request data never supplies time.
pub trait Clock: Send + Sync {
    fn now(&self) -> u64;
}

#[derive(Clone)]
struct HttpState {
    door: Arc<Mutex<Door>>,
    hosts: BTreeSet<String>,
    clock: Arc<dyn Clock>,
    requests: Arc<tokio::sync::Semaphore>,
}

pub fn router(door: Door, hosts: BTreeSet<String>, clock: Arc<dyn Clock>) -> Result<Router> {
    if hosts.is_empty()
        || hosts.len() > 8
        || hosts.iter().any(|host| {
            host.is_empty() || host.len() > 253 || host.contains('/') || host.contains('@')
        })
    {
        return Err(ErrorCode::InvalidRequest);
    }
    Ok(Router::new()
        .route("/invoke", post(invoke))
        .route("/v1/{action}", post(call))
        .with_state(HttpState {
            door: Arc::new(Mutex::new(door)),
            hosts,
            clock,
            requests: Arc::new(tokio::sync::Semaphore::new(MAX_CLIENTS)),
        })
        .fallback(|| async {
            response(Output::Error {
                error: ErrorCode::UnsupportedAction,
            })
        })
        .method_not_allowed_fallback(|| async {
            response(Output::Error {
                error: ErrorCode::InvalidRequest,
            })
        })
        .layer(middleware::map_response(no_store)))
}

// Never let different HTTP consumers choose different values for an authority
// header. Exact configured origins and hosts do not accept comma lists either.
fn unique_header(headers: &HeaderMap, name: HeaderName) -> Option<&str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    Some(value)
}

async fn call(
    State(state): State<HttpState>,
    Path(action): Path<String>,
    request: Request,
) -> Response {
    dispatch(state, Some(action), request).await
}

async fn invoke(State(state): State<HttpState>, request: Request) -> Response {
    dispatch(state, None, request).await
}

async fn dispatch(state: HttpState, action: Option<String>, request: Request) -> Response {
    let headers = request.headers();
    let host = unique_header(headers, header::HOST);
    let origin = unique_header(headers, header::ORIGIN);
    let token =
        unique_header(headers, header::AUTHORIZATION).and_then(|h| h.strip_prefix("Bearer "));
    let (Some(host), Some(origin), Some(token)) = (host, origin, token) else {
        return response(Output::Error {
            error: ErrorCode::Unauthorized,
        });
    };
    if !state.hosts.contains(host)
        || unique_header(headers, header::CONTENT_TYPE) != Some("application/json")
    {
        return response(Output::Error {
            error: ErrorCode::Unauthorized,
        });
    }
    let origin = origin.to_owned();
    let token = Zeroizing::new(token.to_owned());
    let authorized = match state.door.lock() {
        Ok(mut door) => door
            .authenticate(&origin, &token, state.clock.now())
            .map(|_| ()),
        Err(_) => Err(ErrorCode::Unavailable),
    };
    if let Err(error) = authorized {
        return response(Output::Error { error });
    }
    let Ok(_permit) = state.requests.try_acquire() else {
        return response(Output::Error {
            error: ErrorCode::Capacity,
        });
    };
    let bytes = match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        to_bytes(request.into_body(), MAX_BODY_BYTES),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_)) => {
            return response(Output::Error {
                error: ErrorCode::Capacity,
            })
        }
        Err(_) => {
            return response(Output::Error {
                error: ErrorCode::Unavailable,
            })
        }
    };
    // Preserve the exact body bytes for the typed Serde decoder, including its
    // duplicate-field rejection. No Value round trip before authorization.
    let envelope = if let Some(action) = action {
        let Ok(body) = std::str::from_utf8(&bytes) else {
            return response(Output::Error {
                error: ErrorCode::InvalidRequest,
            });
        };
        let name = serde_json::to_string(&action).expect("a string always encodes as JSON");
        format!("{{\"action\":{name},\"version\":1,\"body\":{body}}}").into_bytes()
    } else {
        bytes.to_vec()
    };
    let output = match state.door.lock() {
        Ok(mut door) => door.dispatch(&origin, &token, &envelope, state.clock.now()),
        Err(_) => Output::Error {
            error: ErrorCode::Unavailable,
        },
    };
    response(output)
}

fn response(output: Output) -> Response {
    let code = match output {
        Output::Ok { .. } => StatusCode::OK,
        Output::Error {
            error: ErrorCode::Unauthorized,
        } => StatusCode::FORBIDDEN,
        Output::Error {
            error: ErrorCode::Capacity,
        } => StatusCode::PAYLOAD_TOO_LARGE,
        Output::Error {
            error: ErrorCode::Unavailable | ErrorCode::Reconcile,
        } => StatusCode::SERVICE_UNAVAILABLE,
        Output::Error { .. } => StatusCode::BAD_REQUEST,
    };
    (code, Json(output)).into_response()
}

// Includes routing and extraction refusals as well as domain responses.
async fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

/// Native paired-client transport for CLI/MCP/TUI. No Clone/Debug or credential
/// accessor exists. Pairing is performed by the trusted host, never by this client.
pub struct Client {
    http: reqwest::Client,
    endpoint: url::Url,
    origin: String,
    capability: ClientToken,
}

impl Client {
    /// Consume an already paired local capability. Only literal loopback HTTP
    /// origins are allowed; neither DNS, redirects nor environment proxies can
    /// forward this capability to a different service. No cookie jar is used.
    pub fn new(base: &str, origin: &str, capability: ClientToken) -> Result<Self> {
        validate_origin(origin)?;
        let mut endpoint = url::Url::parse(base).map_err(|_| ErrorCode::InvalidRequest)?;
        let loopback = match endpoint.host() {
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            _ => false,
        };
        if !loopback
            || endpoint.scheme() != "http"
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.path() != "/"
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(ErrorCode::InvalidRequest);
        }
        endpoint.set_path("/invoke");
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|_| ErrorCode::Unavailable)?;
        Ok(Self {
            http,
            endpoint,
            origin: origin.into(),
            capability,
        })
    }

    /// Forward the original invocation bytes. There is no Value parse/reencode
    /// that could erase duplicate fields before the Door's typed decoder.
    /// Transport failures and door refusals remain distinct Result/Output layers.
    pub async fn invoke_bytes(&self, request: &[u8]) -> Result<Output> {
        if request.len() > MAX_BODY_BYTES {
            return Err(ErrorCode::Capacity);
        }
        let bearer = Zeroizing::new(format!("Bearer {}", self.capability.expose_for_transport()));
        // Capability encoding is fixed ASCII base64url from the owner constructor.
        let mut authorization =
            HeaderValue::from_str(&bearer).expect("paired capability is fixed ASCII base64url");
        authorization.set_sensitive(true);
        let mut response = self
            .http
            .post(self.endpoint.clone())
            .header(header::ORIGIN, &self.origin)
            .header(header::AUTHORIZATION, authorization)
            .header(header::CONTENT_TYPE, "application/json")
            .body(request.to_vec())
            .send()
            .await
            .map_err(|_| ErrorCode::Unavailable)?;
        let status = response.status();
        if unique_header(response.headers(), header::CONTENT_TYPE) != Some("application/json")
            || unique_header(response.headers(), header::CACHE_CONTROL) != Some("no-store")
        {
            return Err(ErrorCode::Unavailable);
        }
        let mut bytes = Zeroizing::new(Vec::new());
        while let Some(chunk) = response.chunk().await.map_err(|_| ErrorCode::Unavailable)? {
            if chunk.len() > MAX_RESULT_BYTES - bytes.len() {
                return Err(ErrorCode::Capacity);
            }
            bytes.extend_from_slice(&chunk);
        }
        let output: Output = serde_json::from_slice(&bytes).map_err(|_| ErrorCode::Unavailable)?;
        if status.is_success() != matches!(output, Output::Ok { .. }) {
            return Err(ErrorCode::Unavailable);
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, Bytes};
    use futures_util::{stream, FutureExt};
    use http_body_util::BodyExt;

    const ORIGIN: &str = "https://member.example";
    struct FixedClock;
    impl Clock for FixedClock {
        fn now(&self) -> u64 {
            11
        }
    }
    fn paired() -> (HttpState, ClientToken) {
        let config = Configuration::new(
            "a".into(),
            BTreeMap::from([(Role::Member, BTreeSet::from([ORIGIN.into()]))]),
        )
        .unwrap();
        let mut door = Door::new(config);
        let token = door
            .pair_client(
                ORIGIN,
                Role::Member,
                BTreeSet::from(["runtime.status".into()]),
                10,
                100,
            )
            .unwrap();
        (
            HttpState {
                door: Arc::new(Mutex::new(door)),
                hosts: BTreeSet::from(["localhost:3000".into()]),
                clock: Arc::new(FixedClock),
                requests: Arc::new(tokio::sync::Semaphore::new(MAX_CLIENTS)),
            },
            token,
        )
    }
    fn request(token: &ClientToken, body: Body) -> Request {
        Request::post("/invoke")
            .header("host", "localhost:3000")
            .header("origin", ORIGIN)
            .header(
                "authorization",
                format!("Bearer {}", token.expose_for_transport()),
            )
            .header("content-type", "application/json")
            .body(body)
            .unwrap()
    }
    fn pending() -> Body {
        Body::from_stream(stream::pending::<std::result::Result<Bytes, std::io::Error>>())
    }
    async fn assert_error(response: Response, expected: ErrorCode) {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert!(
            matches!(serde_json::from_slice::<Output>(&bytes).unwrap(), Output::Error{error} if error == expected)
        );
    }
    #[tokio::test(start_paused = true)]
    async fn bounds_waiting_bodies_and_releases_capacity_after_timeout_or_cancel() {
        let (state, token) = paired();
        let mut calls = Vec::new();
        for _ in 0..MAX_CLIENTS {
            let mut call = Box::pin(dispatch(state.clone(), None, request(&token, pending())));
            assert!(call.as_mut().now_or_never().is_none());
            calls.push(call);
        }
        assert_eq!(state.requests.available_permits(), 0);
        assert_error(
            dispatch(state.clone(), None, request(&token, pending())).await,
            ErrorCode::Capacity,
        )
        .await;
        drop(calls.pop());
        assert_eq!(state.requests.available_permits(), 1);
        let response = dispatch(state.clone(), None, request(&token, pending())).await;
        assert_error(response, ErrorCode::Unavailable).await;
        drop(calls);
        assert_eq!(state.requests.available_permits(), MAX_CLIENTS);
        state.door.lock().unwrap().revoke(&token);
        // A revoked capability is refused before any pending body is polled.
        let before = tokio::time::Instant::now();
        assert_error(
            dispatch(state.clone(), None, request(&token, pending())).await,
            ErrorCode::Unauthorized,
        )
        .await;
        assert_eq!(before, tokio::time::Instant::now());
    }
    #[tokio::test]
    async fn rejects_invalid_header_bytes_and_poisoned_embedding_state() {
        let (state, token) = paired();
        let mut req = request(&token, Body::empty());
        req.headers_mut()
            .insert(header::ORIGIN, HeaderValue::from_bytes(&[255]).unwrap());
        assert_error(
            dispatch(state.clone(), None, req).await,
            ErrorCode::Unauthorized,
        )
        .await;
        let locked = state.door.clone();
        let _ = std::thread::spawn(move || {
            let _guard = locked.lock().unwrap();
            panic!("trusted embedding failure");
        })
        .join();
        assert_error(
            dispatch(state, None, request(&token, Body::empty())).await,
            ErrorCode::Unavailable,
        )
        .await;
        assert_eq!(
            response(Output::Error {
                error: ErrorCode::Reconcile
            })
            .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
    #[tokio::test]
    async fn rechecks_authority_after_body_completion() {
        let (state, token) = paired();
        let revoked = ClientToken::from_protected_transport(Zeroizing::new(
            token.expose_for_transport().as_bytes().to_vec(),
        ))
        .unwrap();
        let control = state.door.clone();
        let body = Body::from_stream(stream::once(async move {
            control.lock().unwrap().revoke(&revoked);
            Ok::<_, std::io::Error>(Bytes::from_static(
                br#"{"action":"runtime.status","version":1,"body":{}}"#,
            ))
        }));
        assert_error(
            dispatch(state.clone(), None, request(&token, body)).await,
            ErrorCode::Unauthorized,
        )
        .await;
        let (state, token) = paired();
        let control = state.door.clone();
        let body = Body::from_stream(stream::once(async move {
            let _ = std::thread::spawn(move || {
                let _guard = control.lock().unwrap();
                panic!("trusted embedding failure");
            })
            .join();
            Ok::<_, std::io::Error>(Bytes::from_static(b"{}"))
        }));
        assert_error(
            dispatch(state, None, request(&token, body)).await,
            ErrorCode::Unavailable,
        )
        .await;
    }
}
