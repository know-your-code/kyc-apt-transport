//! APT external method protocol: parser + emitter.
//!
//! Apt invokes a method binary (this crate's bin target, installed at
//! `/usr/lib/apt/methods/kyc`) and communicates over stdin/stdout
//! using a text protocol of RFC-822-ish header blocks terminated by a
//! blank line. The full spec lives in apt's source tree at
//! `doc/method.txt`. We only handle the message kinds needed for an
//! HTTPS-backed transport:
//!
//! ```text
//! Method → apt:
//!   100 Capabilities    (announced at startup)
//!   102 Status          (per-URI progress, surfaces in apt's UI)
//!   200 URI Start       (download in progress, optional)
//!   201 URI Done        (success — must include Size + SHA256-Hash)
//!   400 URI Failure     (sticky error; method stays alive for more URIs)
//!
//! Apt → method:
//!   601 Configuration   (full Acquire::* dump at startup; ignored)
//!   600 URI Acquire     (one per file to download)
//! ```
//!
//! No canonical Rust crate exists for this protocol — checked
//! crates.io; `rust-apt`/`libapt` bind to libapt-pkg for *consumers*
//! of apt, not for writing method binaries. Hand-rolled in ~150 LOC.
//!
//! Reference implementations we modelled after:
//!   - apt-golang-s3 (Go): https://github.com/google/apt-golang-s3
//!   - apt-transport-s3 (Python): https://github.com/lucidsoftware/apt-transport-s3
//!   - apt's own http method: `methods/http.cc`

use std::collections::HashMap;
use std::io::{BufRead, Write};

/// Inbound message from apt.
#[derive(Debug, Clone)]
pub enum AptRequest {
    /// `601 Configuration` — full `Acquire::*` dump at startup. We
    /// don't read any of it today, but keep the type around for
    /// completeness (so the parser can return *something* sensible).
    Configuration {
        items: HashMap<String, String>,
    },
    /// `600 URI Acquire` — apt wants this file fetched.
    UriAcquire(UriAcquire),
}

#[derive(Debug, Clone)]
pub struct UriAcquire {
    /// Full URI as apt understands it (e.g. `kyc://apt.knowyourco.de/pool/...`).
    /// Percent-escapes have been decoded by [`parse_request`] before
    /// the struct lands here.
    pub uri: String,
    /// Absolute path on disk where the method should write the body.
    pub filename: String,
    /// `Last-Modified` apt knows about (for conditional GET). The
    /// method MAY pass it through to the upstream HTTP request.
    pub last_modified: Option<String>,
    /// Hash apt expects the body to have (from Packages metadata).
    /// Mandatory under apt-secure for `/pool/` downloads — if we
    /// emit a 201 without a matching sha256 the file is rejected.
    pub expected_hash: Option<String>,
}

/// Outbound message to apt.
#[derive(Debug, Clone)]
pub enum AptResponse<'a> {
    /// `100 Capabilities` — announced at startup. The fields we
    /// declare drive apt's behaviour for the rest of this session.
    Capabilities {
        /// `Single-Instance: true` means one method process handles
        /// every URI in this apt run (saves spawn cost). We DO want
        /// this because the device-flow login should run at most once
        /// per apt invocation.
        single_instance: bool,
        /// `Pipeline: true` lets apt send multiple 600 requests
        /// without waiting for each 201. Optional; we set it to true.
        pipeline: bool,
        /// `Send-Config: true` makes apt send `601 Configuration` at
        /// startup. Harmless to enable even when we ignore the content.
        send_config: bool,
    },
    /// `102 Status` — informational, surfaces in apt's live UI.
    Status { uri: &'a str, message: &'a str },
    /// `200 URI Start` — apt counts this for its progress UI.
    UriStart {
        uri: &'a str,
        size: Option<u64>,
        last_modified: Option<&'a str>,
    },
    /// `201 URI Done` — success. Size + sha256 mandatory for
    /// apt-secure to accept the file.
    UriDone {
        uri: &'a str,
        filename: &'a str,
        size: u64,
        sha256: &'a str,
        sha512: Option<&'a str>,
        md5: Option<&'a str>,
        last_modified: Option<&'a str>,
    },
    /// `400 URI Failure` — sticky failure for this URI. The method
    /// keeps reading more 600 messages on the same pipe; do NOT exit.
    UriFailure { uri: &'a str, message: &'a str },
}

/// Read one message from apt. Blocks until a complete block (ended by
/// a blank line) arrives, or stdin closes. Returns `Ok(None)` on EOF.
pub fn read_request<R: BufRead>(input: &mut R) -> std::io::Result<Option<AptRequest>> {
    let mut code_line = String::new();
    loop {
        code_line.clear();
        let n = input.read_line(&mut code_line)?;
        if n == 0 {
            return Ok(None); // EOF
        }
        let trimmed = code_line.trim_end();
        if trimmed.is_empty() {
            // Stray blank line between messages — just skip.
            continue;
        }
        break;
    }

    // First line is `<code> <name>` (e.g. `600 URI Acquire`).
    let code_line_trimmed = code_line.trim_end();
    let code = code_line_trimmed
        .split_whitespace()
        .next()
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| std::io::Error::other(format!("bad code line: {code_line_trimmed:?}")))?;

    // Read headers until blank line.
    let mut headers: HashMap<String, String> = HashMap::new();
    loop {
        let mut line = String::new();
        let n = input.read_line(&mut line)?;
        if n == 0 {
            // EOF mid-message — treat as end-of-stream after we
            // process what we have.
            break;
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            headers.insert(k.trim().to_string(), v.trim().to_string());
        }
        // Lines without ':' are malformed; ignore rather than fail
        // the whole pipe — apt versions occasionally emit
        // extension fields we don't recognise.
    }

    let req = match code {
        600 => {
            let uri = headers
                .get("URI")
                .map(|s| url_decode(s))
                .ok_or_else(|| std::io::Error::other("600 missing URI"))?;
            let filename = headers
                .get("Filename")
                .cloned()
                .ok_or_else(|| std::io::Error::other("600 missing Filename"))?;
            AptRequest::UriAcquire(UriAcquire {
                uri,
                filename,
                last_modified: headers.get("Last-Modified").cloned(),
                expected_hash: headers
                    .get("Expected-SHA256")
                    .or_else(|| headers.get("Expected-Checksum"))
                    .cloned(),
            })
        }
        601 => AptRequest::Configuration { items: headers },
        _ => {
            // Unknown code — surface as a non-fatal so the bin can
            // log and continue. Method binaries must be lenient about
            // protocol additions.
            return Err(std::io::Error::other(format!("unknown code {code}")));
        }
    };
    Ok(Some(req))
}

/// Write one message to apt. The protocol is line-oriented; each
/// block ends with a single blank line. We flush after every block so
/// apt sees status updates promptly (its progress UI polls our pipe).
pub fn write_response<W: Write>(out: &mut W, resp: &AptResponse<'_>) -> std::io::Result<()> {
    match resp {
        AptResponse::Capabilities {
            single_instance,
            pipeline,
            send_config,
        } => {
            writeln!(out, "100 Capabilities")?;
            writeln!(out, "Version: 1.2")?;
            writeln!(out, "Single-Instance: {}", bool_str(*single_instance))?;
            writeln!(out, "Pipeline: {}", bool_str(*pipeline))?;
            writeln!(out, "Send-Config: {}", bool_str(*send_config))?;
        }
        AptResponse::Status { uri, message } => {
            writeln!(out, "102 Status")?;
            writeln!(out, "URI: {uri}")?;
            writeln!(out, "Message: {message}")?;
        }
        AptResponse::UriStart {
            uri,
            size,
            last_modified,
        } => {
            writeln!(out, "200 URI Start")?;
            writeln!(out, "URI: {uri}")?;
            if let Some(s) = size {
                writeln!(out, "Size: {s}")?;
            }
            if let Some(lm) = last_modified {
                writeln!(out, "Last-Modified: {lm}")?;
            }
        }
        AptResponse::UriDone {
            uri,
            filename,
            size,
            sha256,
            sha512,
            md5,
            last_modified,
        } => {
            writeln!(out, "201 URI Done")?;
            writeln!(out, "URI: {uri}")?;
            writeln!(out, "Filename: {filename}")?;
            writeln!(out, "Size: {size}")?;
            writeln!(out, "SHA256-Hash: {sha256}")?;
            if let Some(s) = sha512 {
                writeln!(out, "SHA512-Hash: {s}")?;
            }
            if let Some(m) = md5 {
                writeln!(out, "MD5Sum-Hash: {m}")?;
            }
            if let Some(lm) = last_modified {
                writeln!(out, "Last-Modified: {lm}")?;
            }
        }
        AptResponse::UriFailure { uri, message } => {
            writeln!(out, "400 URI Failure")?;
            writeln!(out, "URI: {uri}")?;
            writeln!(out, "Message: {message}")?;
        }
    }
    writeln!(out)?; // blank-line terminator
    out.flush()
}

fn bool_str(b: bool) -> &'static str {
    if b { "true" } else { "false" }
}

/// Decode apt-style URI percent-escapes. Apt sends `~` and `+` in
/// Debian version strings as `%7E` and `%2B`; if we forward those
/// unchanged to the HTTPS request we get 404. Lenient on malformed
/// input: a stray `%` without two hex digits is passed through.
fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) =
                (hex_val(bytes[i + 1]), hex_val(bytes[i + 2]))
            {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    // Lossy: percent-decoding can produce non-UTF8 sequences in
    // theory, but apt URIs are always ASCII-clean in practice.
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_debian_version_tildes_and_pluses() {
        assert_eq!(
            url_decode("kyc_0.2.5%7Erc1%2Bci.42_amd64.deb"),
            "kyc_0.2.5~rc1+ci.42_amd64.deb"
        );
    }

    #[test]
    fn passes_through_malformed_percent() {
        assert_eq!(url_decode("100% sure"), "100% sure");
    }

    #[test]
    fn parses_uri_acquire() {
        let mut input = std::io::Cursor::new(
            b"600 URI Acquire\nURI: kyc://apt.knowyourco.de/pool/main/k/kyc/kyc_0.2.5-1_amd64.deb\nFilename: /var/cache/apt/archives/partial/kyc_0.2.5-1_amd64.deb\nLast-Modified: Tue, 12 May 2026 15:29:39 GMT\n\n".to_vec(),
        );
        let req = read_request(&mut input).unwrap().unwrap();
        match req {
            AptRequest::UriAcquire(a) => {
                assert!(a.uri.ends_with("kyc_0.2.5-1_amd64.deb"));
                assert!(a.filename.contains("partial/kyc_0.2.5-1_amd64.deb"));
                assert!(a.last_modified.is_some());
            }
            _ => panic!("expected URI Acquire"),
        }
    }

    #[test]
    fn emits_capabilities() {
        let mut out = Vec::new();
        write_response(
            &mut out,
            &AptResponse::Capabilities {
                single_instance: true,
                pipeline: true,
                send_config: true,
            },
        )
        .unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("100 Capabilities\n"));
        assert!(s.contains("Single-Instance: true\n"));
        assert!(s.ends_with("\n\n")); // blank-line terminator
    }
}
