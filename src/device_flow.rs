//! RFC 8628 OAuth 2.0 Device Authorization Grant client against a
//! kyc worker. Three HTTPS POSTs total — no localhost listener, no
//! loopback callback, no CORS/PNA contortions:
//!
//!   1. POST /device → device_code, user_code, verification_uri
//!   2. Print URL + code; user opens URL, types code on a /verify page
//!   3. Poll POST /token every `interval` seconds until the worker
//!      reports `license: "..."` (success) or a sticky error
//!
//! The flow returns the license PEM as a `String`; callers handle
//! writing it to disk (this crate's [`super::license_store`] is one
//! option; `kyc-license`'s `keygen::atomic_write` is another).
//!
//! Lifted from kyc-cli's original implementation (see
//! `crates/kyc-cli/src/cli/license.rs` pre-extraction) and generalised
//! to support both an interactive CLI shape (stderr + optional Enter
//! prompt + browser launch) and a stdio-protocol-bound shape (apt
//! method, which can't read stdin and shouldn't try to).

use std::io::{IsTerminal, Write};
#[cfg(feature = "cli-ui")]
use std::io::BufRead;
use std::thread::sleep;
use std::time::{Duration, Instant};

use serde::Deserialize;

/// Caller-supplied output shape for the device flow.
pub enum UserIo {
    /// Interactive CLI: print URL+code to stderr; if stdin is a TTY,
    /// prompt the user to press Enter to launch the browser (the
    /// `enable_browser` flag controls the launch — the prompt itself
    /// is harmless on non-TTY because we skip it). The Enter listener
    /// runs in a background thread so the poll loop never blocks on a
    /// human; if `/token` resolves before the user presses Enter, the
    /// listener is orphaned and dies with the process.
    Cli {
        /// Whether to attempt opening the verification URL in a browser
        /// when the user presses Enter. Only honoured when the `cli-ui`
        /// feature is enabled (otherwise it's a no-op even if `true`).
        enable_browser: bool,
    },
    /// Apt method or other protocol-bound caller. Prints URL+code to
    /// stderr (visible in apt's scrollback) and optionally calls
    /// `status_sink` with each progress line for echo through apt's
    /// `102 Status` channel. Never reads stdin, never launches a
    /// browser. The polling loop runs to completion or timeout.
    AptMethod {
        /// Optional callback invoked for each user-visible status line.
        /// Pass `None` to suppress and rely on stderr only.
        status_sink: Option<Box<dyn Fn(&str) + Send + Sync>>,
    },
}

/// Configuration for one device-flow run.
pub struct DeviceFlowConfig {
    /// Origin of the kyc worker, e.g. `"https://id.knowyourco.de"`.
    pub worker_origin: String,
    /// `ref` form parameter posted to `/device`. Filters which keygen
    /// Group the new user is auto-assigned to on first sign-in.
    pub referral_tag: String,
    /// Overall wall-clock budget. The worker's KV TTL on device codes
    /// is 15 minutes; pick something slightly under that.
    pub timeout: Duration,
    /// User-Agent string posted with each request.
    pub user_agent: String,
    /// How the caller wants user-visible output handled.
    pub user_io: UserIo,
}

impl DeviceFlowConfig {
    /// Sensible defaults: id.knowyourco.de, 14-minute budget, the
    /// `closed-beta` referral tag we use today. Caller still has to
    /// supply a `user_agent` and `user_io`.
    pub fn defaults(user_agent: String, user_io: UserIo) -> Self {
        Self {
            worker_origin: "https://id.knowyourco.de".to_string(),
            referral_tag: "closed-beta".to_string(),
            // Slightly under the worker's 15-min KV TTL so we surface
            // a clean "timed out" error before the worker's
            // `expired_token` reply would catch us.
            timeout: Duration::from_secs(14 * 60),
            user_agent,
            user_io,
        }
    }
}

#[derive(Debug)]
pub enum DeviceFlowError {
    /// HTTP transport / JSON parse / non-2xx response from the worker.
    Http(String),
    /// Caller's `timeout` elapsed before the user finished signing in.
    Timeout,
    /// Worker reported `expired_token` — the device code aged out
    /// before the user got back to the browser.
    Expired,
    /// Sticky worker-side error other than `authorization_pending` /
    /// `expired_token`. The string is the worker's `detail` or
    /// `error` field, ready to surface to the user.
    Worker(String),
}

impl std::fmt::Display for DeviceFlowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http(msg) => write!(f, "{msg}"),
            Self::Timeout => f.write_str("timed out waiting for sign-in"),
            Self::Expired => f.write_str(
                "sign-in code expired before you finished. Re-run sign-in.",
            ),
            Self::Worker(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for DeviceFlowError {}

/// Run the device flow. Returns the issued license PEM on success;
/// the caller is responsible for writing it to disk and verifying it.
pub fn run(config: DeviceFlowConfig) -> Result<String, DeviceFlowError> {
    let client = reqwest::blocking::Client::builder()
        .user_agent(config.user_agent.clone())
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|err| DeviceFlowError::Http(format!("http client: {err}")))?;

    let device = post_device(&client, &config.worker_origin, &config.referral_tag)?;

    announce_to_user(&device, &config.user_io);

    let deadline = Instant::now() + config.timeout;
    let interval = Duration::from_secs(device.interval.max(1));

    loop {
        if Instant::now() >= deadline {
            return Err(DeviceFlowError::Timeout);
        }
        sleep(interval);
        let resp = post_token(&client, &config.worker_origin, &device.device_code)?;

        if let Some(license) = resp.license {
            return Ok(license);
        }

        match resp.error.as_deref() {
            Some("authorization_pending") => continue,
            Some("expired_token") => return Err(DeviceFlowError::Expired),
            Some(code) => {
                let detail = resp.detail.unwrap_or_else(|| code.to_string());
                return Err(DeviceFlowError::Worker(detail));
            }
            None => {
                return Err(DeviceFlowError::Worker(
                    "/token returned neither a license nor an error".into(),
                ));
            }
        }
    }
}

fn announce_to_user(device: &DeviceResp, io: &UserIo) {
    // Both shapes print the same three things: a header line, the
    // URL, and the user code. Stderr is the safe channel — apt
    // captures stdout for its protocol; brew's spinner overwrites
    // stdout's last line. Stderr survives both.
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr);
    let _ = writeln!(stderr, "Sign in to install:");
    let _ = writeln!(stderr);
    let _ = writeln!(stderr, "    Open this URL in a browser:");
    let _ = writeln!(stderr, "        {}", device.verification_uri);
    let _ = writeln!(stderr);
    let _ = writeln!(stderr, "    Then enter this code on that page:");
    let _ = writeln!(stderr, "        {}", device.user_code);
    let _ = writeln!(stderr);
    drop(stderr);

    match io {
        UserIo::Cli { enable_browser } => {
            if std::io::stdin().is_terminal() {
                let mut stderr = std::io::stderr().lock();
                let _ = writeln!(
                    stderr,
                    "Press Enter to open the URL in your browser (or open it yourself)."
                );
                drop(stderr);
                if *enable_browser {
                    spawn_enter_to_open(device.verification_uri.clone());
                }
            }
        }
        UserIo::AptMethod { status_sink } => {
            if let Some(sink) = status_sink {
                // Apt's 102 Status channel — strictly informational;
                // the actual protocol bytes are still going out
                // through stdout from the bin's emitter.
                sink(&format!(
                    "Visit {} and enter code {}",
                    device.verification_uri, device.user_code
                ));
            }
        }
    }
}

#[cfg(feature = "cli-ui")]
fn spawn_enter_to_open(url: String) {
    std::thread::spawn(move || {
        let mut buf = String::new();
        // If stdin closes without an Enter (rare), the read errors
        // and we silently exit — no spurious browser launch. If the
        // user opens the URL themselves and /token resolves first,
        // this thread is orphaned and dies with the process.
        if std::io::stdin().lock().read_line(&mut buf).is_ok()
            && let Err(err) = webbrowser::open(&url)
        {
            eprintln!("warning: couldn't open browser ({err}) — open the URL above manually");
        }
    });
}

#[cfg(not(feature = "cli-ui"))]
fn spawn_enter_to_open(_url: String) {
    // No-op when built without `cli-ui` (the apt-transport-kyc
    // binary case). Device flow polls silently; user opens URL
    // themselves.
}

#[derive(Deserialize)]
struct DeviceResp {
    device_code: String,
    user_code: String,
    verification_uri: String,
    #[serde(default = "default_interval")]
    interval: u64,
}

fn default_interval() -> u64 {
    5
}

#[derive(Deserialize)]
struct TokenResp {
    #[serde(default)]
    license: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    detail: Option<String>,
}

fn post_device(
    client: &reqwest::blocking::Client,
    worker_origin: &str,
    referral_tag: &str,
) -> Result<DeviceResp, DeviceFlowError> {
    let url = format!("{}/device", worker_origin.trim_end_matches('/'));
    let resp = client
        .post(&url)
        .form(&[("ref", referral_tag)])
        .send()
        .map_err(|err| DeviceFlowError::Http(format!("POST {url}: {err}")))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        return Err(DeviceFlowError::Http(format!(
            "POST {url} returned HTTP {status}: {}",
            truncate(&body, 200)
        )));
    }
    resp.json::<DeviceResp>()
        .map_err(|err| DeviceFlowError::Http(format!("POST {url} returned non-JSON: {err}")))
}

fn post_token(
    client: &reqwest::blocking::Client,
    worker_origin: &str,
    device_code: &str,
) -> Result<TokenResp, DeviceFlowError> {
    let url = format!("{}/token", worker_origin.trim_end_matches('/'));
    let resp = client
        .post(&url)
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", device_code),
        ])
        .send()
        .map_err(|err| DeviceFlowError::Http(format!("POST {url}: {err}")))?;
    // /token returns 400 for authorization_pending and expired_token —
    // those are part of RFC 8628, not transport failures. Parse JSON
    // unconditionally and let the caller switch on the body shape.
    let status = resp.status();
    if !status.is_success() && !status.is_client_error() {
        let body = resp.text().unwrap_or_default();
        return Err(DeviceFlowError::Http(format!(
            "POST {url} returned HTTP {status}: {}",
            truncate(&body, 200)
        )));
    }
    resp.json::<TokenResp>()
        .map_err(|err| DeviceFlowError::Http(format!("POST {url} returned non-JSON: {err}")))
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max])
    }
}
