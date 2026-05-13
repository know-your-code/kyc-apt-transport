//! `/usr/lib/apt/methods/kyc` — APT external method binary that
//! handles the `kyc+https://` URL scheme.
//!
//! Apt invokes this binary once per `apt update` / `apt install` and
//! talks to it over stdin/stdout using the text protocol parsed by
//! [`apt_transport_kyc::protocol`]. For each `600 URI Acquire`:
//!
//! 1. URL-decode the URI, rewrite `kyc+https://` → `https://`.
//! 2. If the path is under `/dists/` or `/install/`, fetch
//!    unauthenticated. If under `/pool/`, attach
//!    `Authorization: Kyc-License <base64-of-license-file>` from
//!    `~/.kyc/license` (or `/etc/kyc/license`).
//! 3. On a missing license at first /pool/ request, run the device
//!    flow (RFC 8628) once, cache for the remainder of this method
//!    instance, write to disk per the SUDO_USER policy.
//! 4. Stream the response to apt's named `Filename`, hashing into
//!    sha256+sha512+md5+size as we write.
//! 5. Atomic rename and emit `201 URI Done` with all four checksums.
//!
//! Failures emit `400 URI Failure` and the method stays alive for
//! the next 600 — exiting would mark all subsequent URIs failed.

use std::io::{BufReader, Read, Write};
use std::process::ExitCode;
use std::sync::Mutex;

use apt_transport_kyc::device_flow::{self, DeviceFlowConfig, DeviceFlowError, UserIo};
use apt_transport_kyc::license_store;
use apt_transport_kyc::protocol::{
    AptRequest, AptResponse, UriAcquire, read_request, write_response,
};
use sha2::{Digest, Sha256, Sha512};

const URL_SCHEME: &str = "kyc+https://";
const AUTH_HEADER_PREFIX: &str = "Kyc-License ";

fn main() -> ExitCode {
    let stdin = std::io::stdin();
    let mut stdin = BufReader::new(stdin.lock());
    let stdout = std::io::stdout();
    let stdout_lock = Mutex::new(stdout.lock());

    // Announce capabilities first thing — apt won't send any requests
    // until it sees this.
    if let Err(err) = announce_capabilities(&stdout_lock) {
        eprintln!("apt-transport-kyc: failed to write capabilities: {err}");
        return ExitCode::from(1);
    }

    // Cached license bytes (lazily loaded; lazily bootstrapped). Once
    // we have it for this invocation we reuse it across every /pool/
    // URI without re-reading disk or re-running the device flow.
    let mut license_cache: Option<Vec<u8>> = None;

    loop {
        let req = match read_request(&mut stdin) {
            Ok(Some(r)) => r,
            Ok(None) => return ExitCode::SUCCESS, // EOF — apt's done with us
            Err(err) => {
                eprintln!("apt-transport-kyc: protocol error: {err}");
                // Stay alive only on recoverable errors; a corrupt
                // stream is fatal.
                return ExitCode::from(1);
            }
        };

        match req {
            AptRequest::Configuration { .. } => continue, // we don't read apt config
            AptRequest::UriAcquire(acq) => {
                if let Err(err) = handle_uri(&acq, &stdout_lock, &mut license_cache) {
                    let _ = write_response(
                        &mut *stdout_lock.lock().unwrap(),
                        &AptResponse::UriFailure {
                            uri: &acq.uri,
                            message: &err,
                        },
                    );
                }
            }
        }
    }
}

fn announce_capabilities(stdout: &Mutex<std::io::StdoutLock<'_>>) -> std::io::Result<()> {
    write_response(
        &mut *stdout.lock().unwrap(),
        &AptResponse::Capabilities {
            single_instance: true,
            pipeline: true,
            send_config: true,
        },
    )
}

fn handle_uri(
    acq: &UriAcquire,
    stdout: &Mutex<std::io::StdoutLock<'_>>,
    license_cache: &mut Option<Vec<u8>>,
) -> Result<(), String> {
    let https_url = acq
        .uri
        .strip_prefix(URL_SCHEME)
        .ok_or_else(|| format!("uri doesn't start with {URL_SCHEME}: {}", acq.uri))?;
    let https_url = format!("https://{https_url}");

    let needs_license = path_needs_license(&https_url);

    // Status line lets apt's UI show "Signing in..." or "Downloading"
    // alongside the standard progress UI. Worth emitting even when we
    // immediately succeed — apt updates its TTY display on each.
    emit_status(stdout, &acq.uri, "Downloading");

    let mut req = reqwest_client()
        .get(&https_url)
        .header("User-Agent", user_agent());

    if needs_license {
        let license_b64 = ensure_license_b64(stdout, &acq.uri, license_cache)?;
        req = req.header("Authorization", format!("{AUTH_HEADER_PREFIX}{license_b64}"));
    }
    if let Some(lm) = &acq.last_modified {
        req = req.header("If-Modified-Since", lm);
    }

    let mut resp = req
        .send()
        .map_err(|err| format!("HTTPS GET {https_url}: {err}"))?;

    let status = resp.status();
    if !status.is_success() {
        return Err(format!("HTTPS GET {https_url} returned HTTP {status}"));
    }

    let last_modified = resp
        .headers()
        .get("last-modified")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    // Write to <Filename>.partial first, hashing as we go, then
    // atomic rename. Apt expects the file fully written before we
    // emit 201 URI Done.
    let tmp_path = format!("{}.partial", acq.filename);
    let mut tmp = std::fs::File::create(&tmp_path)
        .map_err(|err| format!("create {tmp_path}: {err}"))?;

    let mut sha256 = Sha256::new();
    let mut sha512 = Sha512::new();
    let mut md5 = md5_init();
    let mut size: u64 = 0;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = resp
            .read(&mut buf)
            .map_err(|err| format!("read {https_url}: {err}"))?;
        if n == 0 {
            break;
        }
        tmp.write_all(&buf[..n])
            .map_err(|err| format!("write {tmp_path}: {err}"))?;
        sha256.update(&buf[..n]);
        sha512.update(&buf[..n]);
        md5_update(&mut md5, &buf[..n]);
        size += n as u64;
    }
    tmp.sync_all()
        .map_err(|err| format!("fsync {tmp_path}: {err}"))?;
    drop(tmp);

    std::fs::rename(&tmp_path, &acq.filename)
        .map_err(|err| format!("rename {tmp_path} -> {}: {err}", acq.filename))?;

    let sha256_hex = hex::encode(sha256.finalize());
    let sha512_hex = hex::encode(sha512.finalize());
    let md5_hex = md5_finalize(md5);

    write_response(
        &mut *stdout.lock().unwrap(),
        &AptResponse::UriDone {
            uri: &acq.uri,
            filename: &acq.filename,
            size,
            sha256: &sha256_hex,
            sha512: Some(&sha512_hex),
            md5: Some(&md5_hex),
            last_modified: last_modified.as_deref(),
        },
    )
    .map_err(|err| format!("write URI Done: {err}"))?;
    Ok(())
}

/// Returns the base64-encoded license bytes ready to drop straight
/// into the `Authorization` header. Caches across calls so the device
/// flow runs at most once per apt invocation.
fn ensure_license_b64(
    stdout: &Mutex<std::io::StdoutLock<'_>>,
    uri: &str,
    cache: &mut Option<Vec<u8>>,
) -> Result<String, String> {
    if cache.is_none() {
        let bytes = match license_store::read()
            .map_err(|err| format!("reading license: {err}"))?
        {
            Some(b) => b,
            None => {
                emit_status(stdout, uri, "License missing — starting sign-in...");
                let pem = run_device_flow(stdout, uri)?;
                let path = license_store::write(pem.as_bytes())
                    .map_err(|err| format!("writing license: {err}"))?;
                emit_status(
                    stdout,
                    uri,
                    &format!("Sign-in complete; license at {}", path.display()),
                );
                pem.into_bytes()
            }
        };
        *cache = Some(bytes);
    }
    Ok(base64_encode(cache.as_ref().unwrap()))
}

fn run_device_flow(
    _stdout: &Mutex<std::io::StdoutLock<'_>>,
    uri: &str,
) -> Result<String, String> {
    // The status sink runs on the poll thread of the device flow.
    // We can't share the caller's stdout lock with it (could
    // deadlock against the main loop), so the closure builds its
    // own lock per emission. stdout's underlying handle is global,
    // so this is fine.
    let uri_for_sink = uri.to_string();
    let status_sink: Box<dyn Fn(&str) + Send + Sync> = Box::new(move |msg: &str| {
        let stdout = std::io::stdout();
        let mut guard = stdout.lock();
        let _ = write_response(
            &mut guard,
            &AptResponse::Status {
                uri: &uri_for_sink,
                message: msg,
            },
        );
    });

    let config = DeviceFlowConfig::defaults(
        user_agent(),
        UserIo::AptMethod {
            status_sink: Some(status_sink),
        },
    );
    device_flow::run(config).map_err(|err: DeviceFlowError| err.to_string())
}

fn path_needs_license(https_url: &str) -> bool {
    // Parse out the path component manually; the URL crate isn't
    // worth a dep for this. Assumes our hosts only have one path
    // section (everything after the third `/`).
    let after_scheme = https_url.strip_prefix("https://").unwrap_or(https_url);
    let path = after_scheme
        .find('/')
        .map(|i| &after_scheme[i..])
        .unwrap_or("/");
    path.starts_with("/pool/")
}

fn emit_status(stdout: &Mutex<std::io::StdoutLock<'_>>, uri: &str, message: &str) {
    let mut g = stdout.lock().unwrap();
    let _ = write_response(
        &mut *g,
        &AptResponse::Status { uri, message },
    );
}

fn reqwest_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .user_agent(user_agent())
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .expect("build reqwest client")
}

fn user_agent() -> String {
    format!("apt-transport-kyc/{}", env!("CARGO_PKG_VERSION"))
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

// MD5 — apt's older Packages metadata sometimes only ships MD5Sum.
// We include it in 201 responses for forward+backward compatibility.
// Wraps `md-5` so we could swap impl later without touching callers.
type Md5 = md5::Md5;
fn md5_init() -> Md5 {
    <Md5 as Digest>::new()
}
fn md5_update(ctx: &mut Md5, data: &[u8]) {
    Digest::update(ctx, data);
}
fn md5_finalize(ctx: Md5) -> String {
    hex::encode(Digest::finalize(ctx))
}
