//! GitHub Issues client: list, create, comment on, and change the state of the issues the
//! CVE lifecycle manages (`specs/cve-lifecycle.md`, "Issue marker and re-adoption";
//! `specs/integrations.md`, "GitHub issues").
//!
//! This module only makes the calls. When to open or close an issue is decided elsewhere.
//! Each call goes through the same HTTP trait as [`github_scanning`](super::github_scanning),
//! so the address check applies and errors are the shared [`ScanError`]. The token is sent
//! only as a bearer header and never appears in an error message or an issue body.

use serde_json::{Value, json};

use crate::error::AppError;
use crate::services::github_scanning::{
    LiveHttp, ScanError, ScanHttp, ScanResponse, check_names, classify,
};
use crate::services::github_url::{GithubTarget, GithubUrls};
use crate::services::outbound::{self, OutboundClient};

/// The label on every issue Dockward creates.
pub const LABEL: &str = "dockward";

/// The label of issues created before the rename to Dockward. Read only, for the re-key and
/// for adoption until the re-key has completed (#311).
pub const LEGACY_LABEL: &str = "harborgate";

/// The longest CVE id or source id the manual route and the lifecycle accept, in bytes.
pub(crate) const MAX_ID_BYTES: usize = 128;

/// True for an id that is safe in the marker line and the route: 1 to 128 bytes of ASCII
/// letters, digits, `.`, `_`, `-` and `:` (a CVE id may be `RHSA-2023:1234`). A Harbor-supplied
/// id with a line break or `-->` fails, so it cannot break the first-line marker. Findings
/// with such an id never get an issue.
pub(crate) fn valid_cve_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID_BYTES
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'))
}

/// The label that marks an issue as a security finding (`specs/integrations.md`, "GitHub
/// issues").
pub const SECURITY_LABEL: &str = "areai:security";

/// The colour of a label HarborGate creates (no `#`).
const LABEL_COLOR: &str = "d93f0b";

/// The plain severity label for a CVE severity: `critical`, `high`, `medium` or `low`.
/// UNKNOWN (and anything else) has none.
pub fn severity_label(severity: &str) -> Option<&'static str> {
    match severity {
        "CRITICAL" => Some("critical"),
        "HIGH" => Some("high"),
        "MEDIUM" => Some("medium"),
        "LOW" => Some("low"),
        _ => None,
    }
}

/// Every severity label HarborGate sets. Only these are ever removed from an issue when its
/// severity changes; any other label is left alone.
pub const SEVERITY_LABELS: [&str; 4] = ["critical", "high", "medium", "low"];

/// Every label a HarborGate issue carries for a CVE of `severity`.
pub fn issue_labels(severity: &str) -> Vec<&'static str> {
    let mut labels = vec![LABEL, SECURITY_LABEL];
    labels.extend(severity_label(severity));
    labels
}

/// The most pages `list_open_labelled` reads (100 issues each) before it gives up. It stops
/// a bad `link` header from looping forever.
const MAX_PAGES: usize = 100;

/// One GitHub issue, as far as the lifecycle needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueRef {
    pub number: u64,
    pub html_url: String,
    pub body: String,
    pub title: String,
    /// Names of the labels on the issue.
    pub labels: Vec<String>,
}

/// The hidden marker that must be the first line of every issue body Dockward creates.
pub fn marker(cve_id: &str) -> String {
    format!("<!-- dockward:{cve_id} -->")
}

/// The marker that issues created before the rename carry on their first line.
pub fn legacy_marker(cve_id: &str) -> String {
    format!("<!-- harborgate:{cve_id} -->")
}

/// The issue whose body's first line is exactly the marker for `cve_id`. A marker anywhere
/// else in the body does not count. An issue with the new marker wins over one with the
/// legacy marker, so a re-keyed issue is preferred when both exist.
pub fn find_marked<'a>(issues: &'a [IssueRef], cve_id: &str) -> Option<&'a IssueRef> {
    let first_line_is = |wanted: String| {
        issues
            .iter()
            .find(|issue| issue.body.lines().next() == Some(wanted.as_str()))
    };
    first_line_is(marker(cve_id)).or_else(|| first_line_is(legacy_marker(cve_id)))
}

/// The body with its first line changed from the legacy marker to the new one, for an issue
/// created before the rename. Only the first line changes: its line ending (a `\r` before the
/// `\n`) and every other byte are kept. Returns `None` unless the first line is exactly the
/// legacy marker for a valid CVE id: a body that already has the new marker, an empty body,
/// or any other first line.
pub fn rekeyed_body(body: &str) -> Option<String> {
    let (line, tail) = match body.split_once('\n') {
        Some((line, _)) => (line, &body[line.len()..]),
        None => (body, ""),
    };
    let (text, line_end) = match line.strip_suffix('\r') {
        Some(text) => (text, "\r"),
        None => (line, ""),
    };
    let cve_id = text
        .strip_prefix("<!-- harborgate:")?
        .strip_suffix(" -->")?;
    if !valid_cve_id(cve_id) {
        return None;
    }
    Some(format!("{}{line_end}{tail}", marker(cve_id)))
}

/// `first` followed by every issue of `second` whose number is not already in `first`.
pub fn merge_by_number(mut first: Vec<IssueRef>, second: Vec<IssueRef>) -> Vec<IssueRef> {
    for issue in second {
        if !first.iter().any(|known| known.number == issue.number) {
            first.push(issue);
        }
    }
    first
}

/// What a label rename did (`PATCH repos/{owner}/{repo}/labels/{from}`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelRename {
    /// The label was renamed.
    Renamed,
    /// The old label does not exist (`404`).
    Absent,
    /// The new label already exists (`422`, `already_exists`), so nothing was renamed.
    TargetExists,
}

/// The body of a new issue: the marker on the first line, then a short Markdown table.
/// `fixed_in` is `None` when no fixed version is known. `description` is the CVE description
/// from the Harbor report; an empty or missing one adds nothing. It holds no token and no URL.
pub fn issue_body(
    cve_id: &str,
    severity: &str,
    package: &str,
    fixed_in: Option<&str>,
    image: &str,
    description: Option<&str>,
) -> String {
    let fixed = fixed_in.unwrap_or("none yet");
    let mut body = format!(
        "{}\n\n| Field | Value |\n| --- | --- |\n| CVE | {} |\n| Severity | {} |\n| Package | {} |\n| Fixed in | {} |\n| Image | {} |\n",
        marker(cve_id),
        cell(cve_id),
        cell(severity),
        cell(package),
        cell(fixed),
        cell(image),
    );
    if let Some(section) = description_section(description) {
        body.push('\n');
        body.push_str(&section);
    }
    body
}

/// The `Description:` heading, a blank line and the fenced, wrapped text, ending in a line break.
/// `None` when the description is missing or blank.
fn description_section(description: Option<&str>) -> Option<String> {
    let text = description.map(str::trim).filter(|text| !text.is_empty())?;
    Some(format!("Description:\n\n{}", fenced(text)))
}

/// The heading line of the description block.
const DESCRIPTION_HEADING: &str = "Description:";

/// The `Affected tags` line of an issue body starts with this text.
const AFFECTED_TAGS_PREFIX: &str = "Affected tags: ";

/// The body with its description block (heading, blank line, fenced text) rewritten the way
/// [`issue_body`] writes it, wrapped the same. Only that block changes. Without a block, the new one
/// goes on its own paragraph before the `Affected tags:` line. A missing or blank `description`
/// keeps what the body has, because a report without text says nothing about the CVE. Returns
/// `None` when nothing changes.
pub fn with_description(body: &str, description: Option<&str>) -> Option<String> {
    let section = description_section(description)?;
    let new_block: Vec<&str> = section.trim_end_matches('\n').split('\n').collect();
    let lines: Vec<&str> = body.split('\n').collect();
    // Only look below the table, so the heading is never taken from the marker or a table cell.
    let header = lines.iter().position(|l| *l == "| Field | Value |")?;
    let table_end = header
        + lines[header..]
            .iter()
            .take_while(|l| l.starts_with('|'))
            .count();
    let heading = lines[table_end..]
        .iter()
        .position(|l| *l == DESCRIPTION_HEADING)
        .map(|offset| table_end + offset);
    let mut next: Vec<&str> = Vec::new();
    match heading {
        Some(start) => {
            // The block ends at the closing fence: a line of backticks as long as the opening one.
            let opening = lines.get(start + 2).copied().unwrap_or("");
            let ticks = opening.chars().take_while(|c| *c == '`').count();
            if lines.get(start + 1) != Some(&"") || ticks < 3 || !opening.ends_with("text") {
                return None;
            }
            let end = lines[start + 3..]
                .iter()
                .position(|l| l.len() == ticks && l.chars().all(|c| c == '`'))
                .map(|offset| start + 3 + offset)?;
            if lines[start..=end] == new_block[..] {
                return None;
            }
            next.extend_from_slice(&lines[..start]);
            next.extend_from_slice(&new_block);
            next.extend_from_slice(&lines[end + 1..]);
        }
        None => {
            let tags = lines[table_end..]
                .iter()
                .position(|l| l.starts_with(AFFECTED_TAGS_PREFIX))
                .map(|offset| table_end + offset)?;
            next.extend_from_slice(&lines[..tags]);
            next.extend_from_slice(&new_block);
            next.push("");
            next.extend_from_slice(&lines[tags..]);
        }
    }
    Some(next.join("\n"))
}

/// The body with its `Affected tags:` line set to `line` (the whole line). Everything else is
/// kept. Returns `None` when the line already reads so, or the body has no such line.
pub fn with_affected_tags(body: &str, line: &str) -> Option<String> {
    let lines: Vec<&str> = body.split('\n').collect();
    let index = lines
        .iter()
        .rposition(|l| l.starts_with(AFFECTED_TAGS_PREFIX))?;
    if lines[index] == line {
        return None;
    }
    let mut next = lines.clone();
    next[index] = line;
    Some(next.join("\n"))
}

/// The severity in the `| Severity | ... |` row of the table of an issue body.
pub fn severity_in(body: &str) -> Option<String> {
    let lines: Vec<&str> = body.split('\n').collect();
    let header = lines.iter().position(|l| *l == "| Field | Value |")?;
    lines[header..]
        .iter()
        .take_while(|l| l.starts_with('|'))
        .find_map(|l| l.strip_prefix("| Severity | ")?.strip_suffix(" |"))
        .map(str::to_owned)
}

/// Text in a code fence longer than any backtick run inside it, so Harbor text cannot
/// mention a user, add a link, or close the block.
fn fenced(text: &str) -> String {
    let mut longest = 0;
    let mut run = 0;
    for c in text.chars() {
        if c == '`' {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    let fence = "`".repeat((longest + 1).max(3));
    let wrapped = wrap(text, DESCRIPTION_WIDTH);
    format!("{fence}text\n{wrapped}\n{fence}\n")
}

/// The width, in characters, a new issue's description is wrapped at inside its fence.
const DESCRIPTION_WIDTH: usize = 80;

/// Hard-wraps `text` at `width` characters (not bytes). Each existing line is wrapped on its own,
/// so a line break in the text stays. A line longer than `width` breaks at its last space that
/// leaves at most `width` characters before it, and that space becomes the line break. A line
/// with no such space is split at `width`, so a long word is cut and nothing is added or lost.
fn wrap(text: &str, width: usize) -> String {
    let width = width.max(1);
    let mut out: Vec<String> = Vec::new();
    for line in text.split('\n') {
        let chars: Vec<char> = line.chars().collect();
        let mut start = 0;
        while chars.len() - start > width {
            let window = &chars[start..=start + width];
            match window.iter().rposition(|c| *c == ' ').filter(|p| *p > 0) {
                Some(p) => {
                    out.push(chars[start..start + p].iter().collect());
                    start += p + 1;
                }
                None => {
                    out.push(chars[start..start + width].iter().collect());
                    start += width;
                }
            }
        }
        out.push(chars[start..].iter().collect());
    }
    out.join("\n")
}

/// Makes a value safe inside one Markdown table cell: no pipe and no line break.
fn cell(value: &str) -> String {
    value
        .replace('|', "\\|")
        .replace(['\r', '\n'], " ")
        .trim()
        .to_owned()
}

fn bad_answer() -> ScanError {
    ScanError::Upstream("GitHub returned an issue that could not be read".to_owned())
}

fn parse_issue(item: &Value) -> Result<IssueRef, ScanError> {
    let number = item
        .get("number")
        .and_then(Value::as_u64)
        .ok_or_else(bad_answer)?;
    let html_url = item
        .get("html_url")
        .and_then(Value::as_str)
        .ok_or_else(bad_answer)?
        .to_owned();
    let body = item
        .get("body")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let title = item
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let labels = item
        .get("labels")
        .and_then(Value::as_array)
        .map(|labels| {
            labels
                .iter()
                .filter_map(|label| {
                    label
                        .as_str()
                        .or_else(|| label.get("name").and_then(Value::as_str))
                })
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    Ok(IssueRef {
        number,
        html_url,
        body,
        title,
        labels,
    })
}

/// The path (with query) of a `next` link, relative to the configured API base URL. The link
/// must be an `https` URL on the configured API host, under its base path, with no user info
/// and no port other than the default, and its path must have no empty segment. Anything else
/// is an error and is never fetched.
///
/// The empty-segment rule matters because the result is appended to the API base: a path
/// such as `//evil.example/x` would otherwise replace the host, and the bearer token would
/// be sent there.
fn next_path(urls: &GithubUrls, link: &str) -> Result<String, ScanError> {
    urls.relative_path(link)
        .ok_or_else(|| ScanError::Upstream("GitHub sent a next link to another host".to_owned()))
}

/// Lists every open issue with `label` (`LABEL` or `LEGACY_LABEL`), following
/// `link: rel="next"`. Pull requests are skipped.
pub async fn list_open_labelled_with<H: ScanHttp>(
    http: &H,
    token: &[u8],
    owner: &str,
    repo: &str,
    label: &str,
    now: i64,
) -> Result<Vec<IssueRef>, ScanError> {
    check_names(owner, repo)?;
    let mut path = format!("repos/{owner}/{repo}/issues?state=open&labels={label}&per_page=100");
    let mut found = Vec::new();
    for _ in 0..MAX_PAGES {
        let response = http.get(&path, token).await?;
        if response.status != 200 {
            return Err(classify(&response, now));
        }
        let items = response.body.as_array().ok_or_else(bad_answer)?;
        for item in items {
            if item.get("pull_request").is_some() {
                continue;
            }
            found.push(parse_issue(item)?);
        }
        match response.link_next.as_deref() {
            Some(link) => path = next_path(&http.urls(), link)?,
            None => return Ok(found),
        }
    }
    Err(ScanError::Upstream(
        "GitHub returned too many pages of issues".to_owned(),
    ))
}

/// Creates an issue with `labels` and returns it. The labels must exist (see
/// [`ensure_labels_with`]).
#[allow(clippy::too_many_arguments)]
pub async fn create_with<H: ScanHttp>(
    http: &H,
    token: &[u8],
    owner: &str,
    repo: &str,
    title: &str,
    body: &str,
    labels: &[&str],
    now: i64,
) -> Result<IssueRef, ScanError> {
    check_names(owner, repo)?;
    let path = format!("repos/{owner}/{repo}/issues");
    let payload = json!({"title": title, "body": body, "labels": labels});
    let response = http.post(&path, token, &payload).await?;
    if response.status != 201 {
        return Err(classify(&response, now));
    }
    parse_issue(&response.body)
}

/// Renames a label (`PATCH repos/{owner}/{repo}/labels/{from}` with `new_name`). `200` is
/// [`LabelRename::Renamed`], `404` is [`LabelRename::Absent`], and a `422` whose answer says
/// `already_exists` is [`LabelRename::TargetExists`]. Any other answer goes through
/// [`classify`].
pub async fn rename_label_with<H: ScanHttp>(
    http: &H,
    token: &[u8],
    owner: &str,
    repo: &str,
    from: &str,
    to: &str,
    now: i64,
) -> Result<LabelRename, ScanError> {
    check_names(owner, repo)?;
    let path = format!("repos/{owner}/{repo}/labels/{from}");
    let response = http.patch(&path, token, &json!({"new_name": to})).await?;
    match response.status {
        200 => Ok(LabelRename::Renamed),
        404 => Ok(LabelRename::Absent),
        422 if already_exists(&response.body) => Ok(LabelRename::TargetExists),
        _ => Err(classify(&response, now)),
    }
}

/// Creates each label in the repository. A label that already exists (`422` with
/// `already_exists`) counts as done, so nothing is duplicated.
pub async fn ensure_labels_with<H: ScanHttp>(
    http: &H,
    token: &[u8],
    owner: &str,
    repo: &str,
    labels: &[&str],
    now: i64,
) -> Result<(), ScanError> {
    check_names(owner, repo)?;
    let path = format!("repos/{owner}/{repo}/labels");
    for label in labels {
        let payload = json!({"name": label, "color": LABEL_COLOR});
        let response = http.post(&path, token, &payload).await?;
        match response.status {
            201 => {}
            422 if already_exists(&response.body) => {}
            _ => return Err(classify(&response, now)),
        }
    }
    Ok(())
}

/// True when a GitHub validation answer says the resource already exists.
fn already_exists(body: &Value) -> bool {
    body.get("errors")
        .and_then(Value::as_array)
        .is_some_and(|errors| {
            errors
                .iter()
                .any(|e| e.get("code").and_then(Value::as_str) == Some("already_exists"))
        })
}

/// Adds labels to an issue. Labels already on it stay; none is removed.
pub async fn add_labels_with<H: ScanHttp>(
    http: &H,
    token: &[u8],
    owner: &str,
    repo: &str,
    number: u64,
    labels: &[&str],
    now: i64,
) -> Result<(), ScanError> {
    check_names(owner, repo)?;
    let path = format!("repos/{owner}/{repo}/issues/{number}/labels");
    let response = http.post(&path, token, &json!({"labels": labels})).await?;
    if response.status != 200 {
        return Err(classify(&response, now));
    }
    Ok(())
}

/// Removes one label from an issue. A label the issue does not carry (`404`) counts as done.
/// The label stays in the repository.
pub async fn remove_label_with<H: ScanHttp>(
    http: &H,
    token: &[u8],
    owner: &str,
    repo: &str,
    number: u64,
    label: &str,
    now: i64,
) -> Result<(), ScanError> {
    check_names(owner, repo)?;
    let encoded: String = label
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.') {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    let path = format!("repos/{owner}/{repo}/issues/{number}/labels/{encoded}");
    let response = http.delete(&path, token).await?;
    match response.status {
        200 | 404 => Ok(()),
        _ => Err(classify(&response, now)),
    }
}

/// Reads one issue and returns the names of its labels and its body, in one call.
pub async fn labels_and_body_with<H: ScanHttp>(
    http: &H,
    token: &[u8],
    owner: &str,
    repo: &str,
    number: u64,
    now: i64,
) -> Result<(Vec<String>, String), ScanError> {
    check_names(owner, repo)?;
    let path = format!("repos/{owner}/{repo}/issues/{number}");
    let response = http.get(&path, token).await?;
    if response.status != 200 {
        return Err(classify(&response, now));
    }
    let labels = response
        .body
        .get("labels")
        .and_then(Value::as_array)
        .ok_or_else(bad_answer)?;
    let names = labels
        .iter()
        .filter_map(|label| {
            label
                .get("name")
                .and_then(Value::as_str)
                .or_else(|| label.as_str())
        })
        .map(str::to_owned)
        .collect();
    let body = response
        .body
        .get("body")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    Ok((names, body))
}

/// Changes the title of an issue.
pub async fn retitle_with<H: ScanHttp>(
    http: &H,
    token: &[u8],
    owner: &str,
    repo: &str,
    number: u64,
    title: &str,
    now: i64,
) -> Result<(), ScanError> {
    check_names(owner, repo)?;
    let path = format!("repos/{owner}/{repo}/issues/{number}");
    let response = http.patch(&path, token, &json!({"title": title})).await?;
    if response.status != 200 {
        return Err(classify(&response, now));
    }
    Ok(())
}

/// Adds a comment to an issue.
pub async fn comment_with<H: ScanHttp>(
    http: &H,
    token: &[u8],
    owner: &str,
    repo: &str,
    number: u64,
    body: &str,
    now: i64,
) -> Result<(), ScanError> {
    check_names(owner, repo)?;
    let path = format!("repos/{owner}/{repo}/issues/{number}/comments");
    let response = http.post(&path, token, &json!({"body": body})).await?;
    if response.status != 201 {
        return Err(classify(&response, now));
    }
    Ok(())
}

/// Opens or closes an issue. Closing sends `state_reason: "completed"`.
pub async fn set_state_with<H: ScanHttp>(
    http: &H,
    token: &[u8],
    owner: &str,
    repo: &str,
    number: u64,
    open: bool,
    now: i64,
) -> Result<(), ScanError> {
    check_names(owner, repo)?;
    let path = format!("repos/{owner}/{repo}/issues/{number}");
    let payload = if open {
        json!({"state": "open"})
    } else {
        json!({"state": "closed", "state_reason": "completed"})
    };
    let response: ScanResponse = http.patch(&path, token, &payload).await?;
    if response.status != 200 {
        return Err(classify(&response, now));
    }
    Ok(())
}

/// Reads one issue and returns whether it is open on GitHub (`state == "open"`). Used to
/// notice an issue that was closed by hand.
pub async fn is_open_with<H: ScanHttp>(
    http: &H,
    token: &[u8],
    owner: &str,
    repo: &str,
    number: u64,
    now: i64,
) -> Result<bool, ScanError> {
    check_names(owner, repo)?;
    let path = format!("repos/{owner}/{repo}/issues/{number}");
    let response = http.get(&path, token).await?;
    if response.status != 200 {
        return Err(classify(&response, now));
    }
    match response.body.get("state").and_then(Value::as_str) {
        Some("open") => Ok(true),
        Some("closed") => Ok(false),
        _ => Err(bad_answer()),
    }
}

/// The `Found by` line of an issue body starts with this text.
const FOUND_BY_PREFIX: &str = "Found by ";

/// The body with the `Found by` line set right after the table (`specs/integrations.md`, "GitHub
/// issues"). An existing `Found by` line is replaced where it stands. Without one, the line goes on
/// its own paragraph after the last table row. Everything else, including a user's edits, is kept.
/// Returns `None` when the body already has this line, or has no table to put it after.
pub fn with_found_by(body: &str, line: &str) -> Option<String> {
    let lines: Vec<&str> = body.split('\n').collect();
    if let Some(index) = lines.iter().position(|l| l.starts_with(FOUND_BY_PREFIX)) {
        if lines[index] == line {
            return None;
        }
        let mut next = lines.clone();
        next[index] = line;
        return Some(next.join("\n"));
    }
    // The table is the run of `|` lines that starts at the header row Dockward wrote. A table-like
    // line in the description fence, further down, is never taken for it.
    let header = lines.iter().position(|l| *l == "| Field | Value |")?;
    let last_row = lines[header..]
        .iter()
        .take_while(|l| l.starts_with('|'))
        .count()
        + header
        - 1;
    let mut next: Vec<&str> = lines[..=last_row].to_vec();
    next.push("");
    next.push(line);
    next.extend_from_slice(&lines[last_row + 1..]);
    Some(next.join("\n"))
}

/// The body with its `| Severity | ... |` table row set to `severity`. Everything else is kept.
/// Returns `None` when the row already says this, or the body has no Dockward table row.
pub fn with_severity(body: &str, severity: &str) -> Option<String> {
    let lines: Vec<&str> = body.split('\n').collect();
    let header = lines.iter().position(|l| *l == "| Field | Value |")?;
    let offset = lines[header..]
        .iter()
        .take_while(|l| l.starts_with('|'))
        .position(|l| l.starts_with("| Severity | "))?;
    let index = header + offset;
    let row = format!("| Severity | {} |", cell(severity));
    if lines[index] == row {
        return None;
    }
    let mut next = lines.clone();
    next[index] = &row;
    Some(next.join("\n"))
}

/// Reads one issue and returns its body (an empty string when it has none).
pub async fn body_with<H: ScanHttp>(
    http: &H,
    token: &[u8],
    owner: &str,
    repo: &str,
    number: u64,
    now: i64,
) -> Result<String, ScanError> {
    check_names(owner, repo)?;
    let path = format!("repos/{owner}/{repo}/issues/{number}");
    let response = http.get(&path, token).await?;
    if response.status != 200 {
        return Err(classify(&response, now));
    }
    Ok(response
        .body
        .get("body")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned())
}

/// Replaces the body of an issue.
pub async fn set_body_with<H: ScanHttp>(
    http: &H,
    token: &[u8],
    owner: &str,
    repo: &str,
    number: u64,
    body: &str,
    now: i64,
) -> Result<(), ScanError> {
    check_names(owner, repo)?;
    let path = format!("repos/{owner}/{repo}/issues/{number}");
    let response = http.patch(&path, token, &json!({"body": body})).await?;
    if response.status != 200 {
        return Err(classify(&response, now));
    }
    Ok(())
}

/// The GitHub Issues client. Built on the guarded outbound client for the configured GitHub
/// API base URL.
pub struct GithubIssues {
    client: OutboundClient,
    target: GithubTarget,
}

impl GithubIssues {
    pub fn new(target: GithubTarget) -> Result<Self, AppError> {
        let client =
            outbound::github_client(target.clone()).map_err(|_| AppError::InternalError)?;
        Ok(Self { client, target })
    }

    fn http(&self) -> LiveHttp<'_> {
        LiveHttp {
            client: &self.client,
            urls: self.target.current(),
        }
    }

    /// Lists open issues with `label`, all pages. See [`list_open_labelled_with`].
    pub async fn list_open_labelled(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        label: &str,
        now: i64,
    ) -> Result<Vec<IssueRef>, ScanError> {
        list_open_labelled_with(&self.http(), token, owner, repo, label, now).await
    }

    /// Renames a label. See [`rename_label_with`].
    pub async fn rename_label(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        from: &str,
        to: &str,
        now: i64,
    ) -> Result<LabelRename, ScanError> {
        rename_label_with(&self.http(), token, owner, repo, from, to, now).await
    }

    /// Creates a labelled issue. See [`create_with`].
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        title: &str,
        body: &str,
        labels: &[&str],
        now: i64,
    ) -> Result<IssueRef, ScanError> {
        create_with(&self.http(), token, owner, repo, title, body, labels, now).await
    }

    /// Creates the labels that are missing. See [`ensure_labels_with`].
    pub async fn ensure_labels(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        labels: &[&str],
        now: i64,
    ) -> Result<(), ScanError> {
        ensure_labels_with(&self.http(), token, owner, repo, labels, now).await
    }

    /// Adds labels to an issue. See [`add_labels_with`].
    pub async fn add_labels(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        number: u64,
        labels: &[&str],
        now: i64,
    ) -> Result<(), ScanError> {
        add_labels_with(&self.http(), token, owner, repo, number, labels, now).await
    }

    /// Removes one label from an issue. See [`remove_label_with`].
    pub async fn remove_label(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        number: u64,
        label: &str,
        now: i64,
    ) -> Result<(), ScanError> {
        remove_label_with(&self.http(), token, owner, repo, number, label, now).await
    }

    /// Reads the label names and body of an issue. See [`labels_and_body_with`].
    pub async fn labels_and_body(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        number: u64,
        now: i64,
    ) -> Result<(Vec<String>, String), ScanError> {
        labels_and_body_with(&self.http(), token, owner, repo, number, now).await
    }

    /// Changes an issue title. See [`retitle_with`].
    pub async fn retitle(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        number: u64,
        title: &str,
        now: i64,
    ) -> Result<(), ScanError> {
        retitle_with(&self.http(), token, owner, repo, number, title, now).await
    }

    /// Comments on an issue. See [`comment_with`].
    pub async fn comment(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        number: u64,
        body: &str,
        now: i64,
    ) -> Result<(), ScanError> {
        comment_with(&self.http(), token, owner, repo, number, body, now).await
    }

    /// True when the issue is open on GitHub. See [`is_open_with`].
    pub async fn is_open(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        number: u64,
        now: i64,
    ) -> Result<bool, ScanError> {
        is_open_with(&self.http(), token, owner, repo, number, now).await
    }

    /// Reads an issue body. See [`body_with`].
    pub async fn body(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        number: u64,
        now: i64,
    ) -> Result<String, ScanError> {
        body_with(&self.http(), token, owner, repo, number, now).await
    }

    /// Replaces an issue body. See [`set_body_with`].
    pub async fn set_body(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        number: u64,
        body: &str,
        now: i64,
    ) -> Result<(), ScanError> {
        set_body_with(&self.http(), token, owner, repo, number, body, now).await
    }

    /// Opens or closes an issue. See [`set_state_with`].
    pub async fn set_state(
        &self,
        token: &[u8],
        owner: &str,
        repo: &str,
        number: u64,
        open: bool,
        now: i64,
    ) -> Result<(), ScanError> {
        set_state_with(&self.http(), token, owner, repo, number, open, now).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    type Sent = (&'static str, String, Value);

    /// Answers each request with the next recorded response, and records the method, path
    /// and body of every request.
    struct Scripted {
        replies: Mutex<VecDeque<ScanResponse>>,
        sent: Mutex<Vec<Sent>>,
    }

    impl Scripted {
        fn new(replies: Vec<ScanResponse>) -> Self {
            Self {
                replies: Mutex::new(replies.into()),
                sent: Mutex::new(Vec::new()),
            }
        }

        fn sent(&self) -> Vec<Sent> {
            self.sent
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .clone()
        }

        fn answer(
            &self,
            method: &'static str,
            path: &str,
            body: Value,
        ) -> Result<ScanResponse, ScanError> {
            self.sent
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .push((method, path.to_owned(), body));
            self.replies
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .pop_front()
                .ok_or_else(|| ScanError::Upstream("no recorded response left".to_owned()))
        }
    }

    impl ScanHttp for Scripted {
        async fn post(
            &self,
            path: &str,
            _token: &[u8],
            body: &Value,
        ) -> Result<ScanResponse, ScanError> {
            self.answer("POST", path, body.clone())
        }

        async fn patch(
            &self,
            path: &str,
            _token: &[u8],
            body: &Value,
        ) -> Result<ScanResponse, ScanError> {
            self.answer("PATCH", path, body.clone())
        }

        async fn get(&self, path: &str, _token: &[u8]) -> Result<ScanResponse, ScanError> {
            self.answer("GET", path, Value::Null)
        }

        async fn delete(&self, path: &str, _token: &[u8]) -> Result<ScanResponse, ScanError> {
            self.answer("DELETE", path, Value::Null)
        }
    }

    fn reply(status: u16, body: Value) -> ScanResponse {
        ScanResponse {
            status,
            retry_after: None,
            ratelimit_remaining: None,
            ratelimit_reset: None,
            link_next: None,
            body,
        }
    }

    fn issue(number: u64, body: &str) -> Value {
        json!({
            "number": number,
            "html_url": format!("https://github.com/octo/app/issues/{number}"),
            "body": body,
        })
    }

    fn ref_of(number: u64, body: &str) -> IssueRef {
        IssueRef {
            number,
            html_url: format!("https://github.com/octo/app/issues/{number}"),
            body: body.to_owned(),
            title: String::new(),
            labels: Vec::new(),
        }
    }

    #[tokio::test]
    async fn list_follows_link_next_and_skips_pull_requests() {
        let page_one = ScanResponse {
            link_next: Some(
                "https://api.github.com/repositories/42/issues?state=open&labels=harborgate&per_page=100&page=2"
                    .to_owned(),
            ),
            ..reply(
                200,
                json!([
                    issue(1, "<!-- harborgate:CVE-2026-1 -->"),
                    {
                        "number": 2,
                        "html_url": "https://github.com/octo/app/pull/2",
                        "body": "a pull request",
                        "pull_request": {"url": "https://api.github.com/repos/octo/app/pulls/2"}
                    },
                ]),
            )
        };
        let page_two = reply(200, json!([issue(3, "<!-- harborgate:CVE-2026-3 -->")]));
        let fake = Scripted::new(vec![page_one, page_two]);

        let found = list_open_labelled_with(&fake, b"token", "octo", "app", LABEL, 1000)
            .await
            .unwrap();

        assert_eq!(
            found,
            vec![
                ref_of(1, "<!-- harborgate:CVE-2026-1 -->"),
                ref_of(3, "<!-- harborgate:CVE-2026-3 -->"),
            ]
        );
        let paths: Vec<String> = fake.sent().into_iter().map(|(_, path, _)| path).collect();
        assert_eq!(
            paths,
            vec![
                "repos/octo/app/issues?state=open&labels=dockward&per_page=100".to_owned(),
                "repositories/42/issues?state=open&labels=harborgate&per_page=100&page=2"
                    .to_owned(),
            ]
        );
    }

    #[tokio::test]
    async fn list_refuses_a_next_link_to_another_host() {
        let page = ScanResponse {
            link_next: Some("https://evil.example.com/issues?page=2".to_owned()),
            ..reply(200, json!([]))
        };
        let fake = Scripted::new(vec![page, reply(200, json!([]))]);
        let outcome = list_open_labelled_with(&fake, b"token", "octo", "app", LABEL, 1000).await;
        assert!(matches!(outcome, Err(ScanError::Upstream(_))));
        assert_eq!(fake.sent().len(), 1, "the foreign link must not be fetched");
    }

    #[tokio::test]
    async fn list_never_requests_a_foreign_url_from_a_crafted_next_link() {
        for link in [
            // Empty segments that `Url::join` would read as a new host.
            "https://api.github.com///evil.example/x",
            "https://api.github.com//evil.example/x",
            // An embedded absolute URL in the path.
            "https://api.github.com/https://evil.example/",
            // User info and a non-default port.
            "https://api.github.com@evil.example/issues?page=2",
            "https://user:pw@api.github.com/issues?page=2",
            "https://api.github.com:8443/issues?page=2",
            // Wrong scheme, wrong host, a lookalike host, and rubbish.
            "http://api.github.com/issues?page=2",
            "https://api.github.com.evil.example/issues?page=2",
            "https://evil.example/issues?page=2",
            "//evil.example/x",
            "not a url",
        ] {
            let page = ScanResponse {
                link_next: Some(link.to_owned()),
                ..reply(200, json!([]))
            };
            let fake = Scripted::new(vec![page, reply(200, json!([]))]);
            let outcome =
                list_open_labelled_with(&fake, b"token", "octo", "app", LABEL, 1000).await;
            assert!(
                matches!(outcome, Err(ScanError::Upstream(_))),
                "{link} should be refused"
            );
            assert_eq!(fake.sent().len(), 1, "{link} must not be requested");
        }
    }

    #[test]
    fn next_path_keeps_only_path_and_query() {
        assert_eq!(
            next_path(
                &GithubUrls::default(),
                "https://api.github.com/repositories/42/issues?page=2&per_page=100"
            ),
            Ok("repositories/42/issues?page=2&per_page=100".to_owned())
        );
        // The default port written out is the same host and port.
        assert_eq!(
            next_path(
                &GithubUrls::default(),
                "https://api.github.com:443/repositories/42/issues"
            ),
            Ok("repositories/42/issues".to_owned())
        );
    }

    #[test]
    fn marker_must_be_the_first_line() {
        let first = ref_of(1, "<!-- harborgate:CVE-2026-1 -->\n\nbody");
        let crlf = ref_of(2, "<!-- harborgate:CVE-2026-2 -->\r\nbody");
        let second_line = ref_of(3, "intro\n<!-- harborgate:CVE-2026-3 -->");
        let prefix_only = ref_of(4, "<!-- harborgate:CVE-2026-44 -->");
        let issues = vec![first, crlf, second_line, prefix_only];

        assert_eq!(
            find_marked(&issues, "CVE-2026-1").map(|i| i.number),
            Some(1)
        );
        assert_eq!(
            find_marked(&issues, "CVE-2026-2").map(|i| i.number),
            Some(2)
        );
        assert_eq!(find_marked(&issues, "CVE-2026-3"), None);
        // CVE-2026-4 is a prefix of CVE-2026-44, and must not match it.
        assert_eq!(find_marked(&issues, "CVE-2026-4"), None);
        assert_eq!(
            find_marked(&issues, "CVE-2026-44").map(|i| i.number),
            Some(4)
        );
    }

    #[tokio::test]
    async fn create_sends_the_dockward_label() {
        let fake = Scripted::new(vec![reply(201, issue(7, "<!-- dockward:CVE-2026-1 -->"))]);
        let created = create_with(
            &fake,
            b"token",
            "octo",
            "app",
            "CVE-2026-1 libfoo",
            "<!-- dockward:CVE-2026-1 -->",
            &issue_labels("HIGH"),
            1000,
        )
        .await
        .unwrap();

        assert_eq!(created, ref_of(7, "<!-- dockward:CVE-2026-1 -->"));
        let sent = fake.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, "POST");
        assert_eq!(sent[0].1, "repos/octo/app/issues");
        assert_eq!(
            sent[0].2["labels"],
            json!(["dockward", "areai:security", "high"])
        );
        assert_eq!(sent[0].2["title"], "CVE-2026-1 libfoo");
        assert_eq!(sent[0].2["body"], "<!-- dockward:CVE-2026-1 -->");
    }

    #[test]
    fn unknown_severity_has_no_severity_label() {
        assert_eq!(issue_labels("UNKNOWN"), vec!["dockward", "areai:security"]);
        assert_eq!(severity_label("LOW"), Some("low"));
    }

    #[tokio::test]
    async fn an_existing_label_is_success_and_other_errors_are_not() {
        let exists = reply(
            422,
            json!({"errors": [{"resource": "Label", "code": "already_exists", "field": "name"}]}),
        );
        let fake = Scripted::new(vec![reply(201, json!({})), exists]);
        ensure_labels_with(&fake, b"token", "octo", "app", &["a", "b"], 1000)
            .await
            .unwrap();
        let sent = fake.sent();
        assert_eq!(sent[0].1, "repos/octo/app/labels");
        assert_eq!(sent[0].2["name"], "a");
        assert_eq!(sent[1].2["name"], "b");

        let other = Scripted::new(vec![reply(422, json!({"errors": [{"code": "invalid"}]}))]);
        assert!(
            ensure_labels_with(&other, b"token", "octo", "app", &["a"], 1000)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn comment_posts_to_the_issue() {
        let fake = Scripted::new(vec![reply(201, json!({"id": 1}))]);
        comment_with(&fake, b"token", "octo", "app", 7, "back again", 1000)
            .await
            .unwrap();
        let sent = fake.sent();
        assert_eq!(sent[0].0, "POST");
        assert_eq!(sent[0].1, "repos/octo/app/issues/7/comments");
        assert_eq!(sent[0].2, json!({"body": "back again"}));
    }

    #[tokio::test]
    async fn close_sends_state_reason_completed() {
        let fake = Scripted::new(vec![reply(200, json!({})), reply(200, json!({}))]);
        set_state_with(&fake, b"token", "octo", "app", 7, false, 1000)
            .await
            .unwrap();
        set_state_with(&fake, b"token", "octo", "app", 7, true, 1000)
            .await
            .unwrap();

        let sent = fake.sent();
        assert_eq!(sent[0].0, "PATCH");
        assert_eq!(sent[0].1, "repos/octo/app/issues/7");
        assert_eq!(
            sent[0].2,
            json!({"state": "closed", "state_reason": "completed"})
        );
        // Reopening sends no state reason.
        assert_eq!(sent[1].2, json!({"state": "open"}));
    }

    #[tokio::test]
    async fn rate_limit_is_classified() {
        let limited = ScanResponse {
            ratelimit_remaining: Some(0),
            ratelimit_reset: Some(1900),
            ..reply(403, json!({"message": "API rate limit exceeded"}))
        };
        let fake = Scripted::new(vec![limited]);
        assert_eq!(
            list_open_labelled_with(&fake, b"token", "octo", "app", LABEL, 1000).await,
            Err(ScanError::RateLimited { until: 1900 })
        );

        let secondary = ScanResponse {
            retry_after: Some(30),
            ..reply(429, json!({"message": "secondary rate limit"}))
        };
        let fake = Scripted::new(vec![secondary]);
        assert_eq!(
            create_with(&fake, b"token", "octo", "app", "t", "b", &[], 1000).await,
            Err(ScanError::RateLimited { until: 1030 })
        );
    }

    #[tokio::test]
    async fn invalid_names_are_refused_before_any_request() {
        let fake = Scripted::new(vec![]);
        let outcome = list_open_labelled_with(&fake, b"token", "../octo", "app", LABEL, 1000).await;
        assert!(matches!(outcome, Err(ScanError::Rejected(_))));
        assert!(fake.sent().is_empty());
    }

    #[test]
    fn with_description_replaces_only_the_block() {
        let old = issue_body("CVE-1", "HIGH", "`p`", None, "img", Some("old"));
        let body = format!("{old}\nFound by 1 scanner: `Trivy`\n\nAffected tags: `v1`\n");
        let next = with_description(&body, Some("new text")).unwrap_or_default();
        let want = issue_body("CVE-1", "HIGH", "`p`", None, "img", Some("new text"));
        assert_eq!(
            next,
            format!("{want}\nFound by 1 scanner: `Trivy`\n\nAffected tags: `v1`\n")
        );
        assert_eq!(with_description(&next, Some("new text")), None);
        assert_eq!(with_description(&next, None), None);
    }

    #[test]
    fn with_description_adds_a_missing_block_before_the_tags() {
        let old = issue_body("CVE-1", "HIGH", "`p`", None, "img", None);
        let body = format!("{old}\nAffected tags: `v1`\n");
        let next = with_description(&body, Some("text")).unwrap_or_default();
        let want = issue_body("CVE-1", "HIGH", "`p`", None, "img", Some("text"));
        assert_eq!(next, format!("{want}\nAffected tags: `v1`\n"));
    }

    #[test]
    fn with_affected_tags_replaces_only_that_line() {
        let body = "a\n\nAffected tags: `v1`\n";
        assert_eq!(
            with_affected_tags(body, "Affected tags: `v1`, `v2`").as_deref(),
            Some("a\n\nAffected tags: `v1`, `v2`\n")
        );
        assert_eq!(with_affected_tags(body, "Affected tags: `v1`"), None);
    }

    #[test]
    fn with_severity_sets_only_the_severity_row() {
        let body = issue_body(
            "CVE-1",
            "HIGH",
            "pkg",
            None,
            "img",
            Some("| Severity | HIGH |"),
        );
        let next = with_severity(&body, "LOW").unwrap();
        assert_eq!(
            next,
            body.replacen("| Severity | HIGH |", "| Severity | LOW |", 1)
        );
        assert!(with_severity(&body, "HIGH").is_none());
        assert!(with_severity("no table", "LOW").is_none());
    }

    #[test]
    fn body_starts_with_the_marker() {
        let body = issue_body(
            "CVE-2026-1",
            "CRITICAL",
            "libfoo",
            Some("1.2.4"),
            "library/app",
            None,
        );
        assert_eq!(body.lines().next(), Some("<!-- dockward:CVE-2026-1 -->"));
        assert!(body.contains("| Severity | CRITICAL |"));
        assert!(body.contains("| Fixed in | 1.2.4 |"));
        assert!(body.contains("| Image | library/app |"));

        // The body it produces is found again by the marker lookup.
        let issues = vec![ref_of(1, &body)];
        assert_eq!(
            find_marked(&issues, "CVE-2026-1").map(|i| i.number),
            Some(1)
        );
    }

    #[test]
    fn body_carries_the_description_in_a_fence() {
        let body = issue_body(
            "CVE-2026-1",
            "HIGH",
            "p",
            None,
            "a/b",
            Some("A flaw ``` @bob"),
        );
        assert!(body.contains("A flaw ``` @bob"));
        assert!(body.contains("````text\n"));
        let long = "word ".repeat(40);
        let wrapped = issue_body("CVE-2026-1", "HIGH", "p", None, "a/b", Some(&long));
        let fence_lines: Vec<&str> = wrapped
            .split("```text\n")
            .nth(1)
            .unwrap()
            .split("\n```")
            .next()
            .unwrap()
            .split('\n')
            .collect();
        assert!(fence_lines.len() > 1);
        assert!(fence_lines.iter().all(|l| l.chars().count() <= 80));
        let none = issue_body("CVE-2026-1", "HIGH", "p", None, "a/b", Some(""));
        assert!(!none.contains("Description"));
    }

    #[test]
    fn wrap_breaks_a_long_description_at_spaces_within_80_characters() {
        let text = (1..=60)
            .map(|n| format!("word{n}"))
            .collect::<Vec<_>>()
            .join(" ");
        let wrapped = wrap(&text, 80);
        assert!(wrapped.contains('\n'));
        for line in wrapped.split('\n') {
            assert!(line.chars().count() <= 80, "{line}");
            assert!(!line.starts_with(' ') && !line.ends_with(' '));
        }
        // Each break replaced exactly one space, so nothing is added or lost.
        assert_eq!(wrapped.replace('\n', " "), text);
        // A short text and its own line breaks are kept.
        assert_eq!(wrap("short\ntext", 80), "short\ntext");
        let exact = "a".repeat(80);
        assert_eq!(wrap(&exact, 80), exact);
    }

    #[test]
    fn wrap_splits_a_word_longer_than_the_width() {
        let word = "x".repeat(200);
        let wrapped = wrap(&word, 80);
        let lines: Vec<&str> = wrapped.split('\n').collect();
        assert_eq!(
            lines.iter().map(|l| l.chars().count()).collect::<Vec<_>>(),
            vec![80, 80, 40]
        );
        assert_eq!(wrapped.replace('\n', ""), word);
        // A long word after a short one: the space is the break, then the word is split.
        let mixed = format!("see {word}");
        let wrapped = wrap(&mixed, 80);
        assert_eq!(wrapped.split('\n').next(), Some("see"));
        assert_eq!(wrapped.replace('\n', ""), mixed.replacen(' ', "", 1));
    }

    #[test]
    fn wrap_counts_characters_and_never_splits_one() {
        let text = "é".repeat(100);
        let wrapped = wrap(&text, 80);
        assert_eq!(wrapped.split('\n').next().unwrap().chars().count(), 80);
        assert_eq!(wrapped.replace('\n', ""), text);
        let words = "日本語 ".repeat(40);
        let wrapped = wrap(words.trim_end(), 80);
        assert!(wrapped.split('\n').all(|l| l.chars().count() <= 80));
        assert_eq!(wrapped.replace('\n', " "), words.trim_end());
    }

    #[test]
    fn a_wrapped_description_keeps_the_longer_fence() {
        let text = format!("{} ```` {}", "a ".repeat(30), "b ".repeat(30));
        let body = issue_body("CVE-2026-1", "HIGH", "p", None, "a/b", Some(&text));
        assert!(body.contains("`````text\n"));
        assert!(body.ends_with("\n`````\n"));
        let inner = body
            .split("`````text\n")
            .nth(1)
            .unwrap()
            .trim_end_matches("\n`````\n");
        assert_eq!(inner.replace('\n', " "), text.trim());
    }

    #[test]
    fn a_wrapped_body_still_gets_its_found_by_line_replaced() {
        let description = "overflow ".repeat(40);
        let body = issue_body("CVE-2026-1", "HIGH", "p", None, "a/b", Some(&description));
        let one = with_found_by(&body, "Found by 1 scanner: `Trivy`").unwrap();
        let two = with_found_by(&one, "Found by 2 scanners: `Grype`, `Trivy`").unwrap();
        assert_eq!(two.matches("Found by ").count(), 1);
        assert!(two.contains("Found by 2 scanners: `Grype`, `Trivy`"));
        assert!(two.contains("overflow overflow overflow"));
        assert!(
            with_severity(&two, "LOW")
                .unwrap()
                .contains("| Severity | LOW |")
        );
    }

    #[test]
    fn body_cells_cannot_break_the_table() {
        let body = issue_body(
            "CVE-2026-1",
            "HIGH",
            "a|b\nc",
            None,
            "library/app",
            Some("  "),
        );
        assert!(body.contains("| Package | a\\|b c |"));
        assert!(body.contains("| Fixed in | none yet |"));
    }

    #[test]
    fn found_by_goes_right_after_the_table_and_is_replaced_in_place() {
        let body = issue_body(
            "CVE-2026-1",
            "HIGH",
            "p",
            None,
            "a/b",
            Some("| Field | Value |\n| x | y |"),
        );
        let one = with_found_by(&body, "Found by 1 scanner: `Trivy`").unwrap();
        let lines: Vec<&str> = one.split('\n').collect();
        let table_end = lines.iter().position(|l| l.starts_with("| Image")).unwrap();
        assert_eq!(lines[table_end + 1], "");
        assert_eq!(lines[table_end + 2], "Found by 1 scanner: `Trivy`");
        assert_eq!(lines[0], marker("CVE-2026-1"), "the marker stays first");
        assert!(one.contains("Description:"), "the rest is kept");
        // The same line again needs no change.
        assert_eq!(with_found_by(&one, "Found by 1 scanner: `Trivy`"), None);
        // A changed scanner set replaces the line where it stands.
        let two = with_found_by(&one, "Found by 2 scanners: `Grype`, `Trivy`").unwrap();
        assert_eq!(two.matches("Found by ").count(), 1);
        assert!(two.contains("Found by 2 scanners: `Grype`, `Trivy`"));
        // A body without Dockward's table is left alone.
        assert_eq!(with_found_by("just text", "Found by 1 scanner: `a`"), None);
    }

    #[test]
    fn markers_use_the_new_and_legacy_names() {
        assert_eq!(marker("CVE-2026-1"), "<!-- dockward:CVE-2026-1 -->");
        assert_eq!(
            legacy_marker("CVE-2026-1"),
            "<!-- harborgate:CVE-2026-1 -->"
        );
        assert_eq!(LABEL, "dockward");
        assert_eq!(LEGACY_LABEL, "harborgate");
    }

    #[test]
    fn find_marked_prefers_the_new_marker_over_the_legacy_one() {
        let legacy = ref_of(1, "<!-- harborgate:CVE-2026-1 -->\n\nold");
        let new = ref_of(2, "<!-- dockward:CVE-2026-1 -->\n\nnew");
        let issues = vec![legacy.clone(), new.clone()];
        assert_eq!(find_marked(&issues, "CVE-2026-1"), Some(&new));
        // Without the new marker, the legacy one is adopted.
        assert_eq!(
            find_marked(std::slice::from_ref(&legacy), "CVE-2026-1"),
            Some(&legacy)
        );
    }

    #[test]
    fn find_marked_rejects_a_marker_on_line_two_or_a_prefix_for_both_names() {
        let second = ref_of(1, "intro\n<!-- dockward:CVE-2026-3 -->");
        let legacy_second = ref_of(2, "intro\n<!-- harborgate:CVE-2026-3 -->");
        let legacy_prefix = ref_of(3, "<!-- harborgate:CVE-2026-44 -->");
        let issues = vec![second, legacy_second, legacy_prefix];
        assert_eq!(find_marked(&issues, "CVE-2026-3"), None);
        assert_eq!(find_marked(&issues, "CVE-2026-4"), None);
    }

    #[test]
    fn rekeyed_body_rewrites_only_the_first_line_with_lf() {
        let body = "<!-- harborgate:CVE-2026-1 -->\n\n| Field | Value |\nbody with <!-- harborgate:X --> inside\n";
        assert_eq!(
            rekeyed_body(body).as_deref(),
            Some(
                "<!-- dockward:CVE-2026-1 -->\n\n| Field | Value |\nbody with <!-- harborgate:X --> inside\n"
            )
        );
    }

    #[test]
    fn rekeyed_body_keeps_a_crlf_line_ending_and_every_other_byte() {
        let body = "<!-- harborgate:CVE-2026-2 -->\r\nline\r\n\r\ntail";
        assert_eq!(
            rekeyed_body(body).as_deref(),
            Some("<!-- dockward:CVE-2026-2 -->\r\nline\r\n\r\ntail")
        );
    }

    #[test]
    fn rekeyed_body_is_none_for_every_other_first_line() {
        assert_eq!(rekeyed_body("<!-- dockward:CVE-2026-1 -->\n\nbody"), None);
        assert_eq!(rekeyed_body(""), None);
        assert_eq!(rekeyed_body("intro\n<!-- harborgate:CVE-2026-1 -->"), None);
        assert_eq!(
            rekeyed_body("<!-- harborgate:CVE-2026-1 --> trailing"),
            None
        );
        assert_eq!(rekeyed_body("<!-- harborgate:CVE-2026-44"), None);
        // An id with `-->` or a line break cannot pass the id rule.
        assert_eq!(
            rekeyed_body("<!-- harborgate:CVE-1 --> --> -->\nbody"),
            None
        );
        assert_eq!(rekeyed_body("<!-- harborgate:CVE-1\n-->"), None);
        assert_eq!(rekeyed_body("<!-- harborgate: -->"), None);
    }

    #[tokio::test]
    async fn rename_label_sends_the_exact_path_and_body_and_classifies_each_answer() {
        let renamed = Scripted::new(vec![reply(200, json!({}))]);
        assert_eq!(
            rename_label_with(
                &renamed,
                b"token",
                "octo",
                "app",
                "harborgate",
                "dockward",
                1000
            )
            .await,
            Ok(LabelRename::Renamed)
        );
        let sent = renamed.sent();
        assert_eq!(sent[0].0, "PATCH");
        assert_eq!(sent[0].1, "repos/octo/app/labels/harborgate");
        assert_eq!(sent[0].2, json!({"new_name": "dockward"}));

        let absent = Scripted::new(vec![reply(404, json!({"message": "Not Found"}))]);
        assert_eq!(
            rename_label_with(
                &absent,
                b"token",
                "octo",
                "app",
                "harborgate",
                "dockward",
                1000
            )
            .await,
            Ok(LabelRename::Absent)
        );

        let exists = Scripted::new(vec![reply(
            422,
            json!({"errors": [{"resource": "Label", "code": "already_exists", "field": "new_name"}]}),
        )]);
        assert_eq!(
            rename_label_with(
                &exists,
                b"token",
                "octo",
                "app",
                "harborgate",
                "dockward",
                1000
            )
            .await,
            Ok(LabelRename::TargetExists)
        );

        let refused = Scripted::new(vec![reply(401, json!({}))]);
        assert_eq!(
            rename_label_with(
                &refused,
                b"token",
                "octo",
                "app",
                "harborgate",
                "dockward",
                1000
            )
            .await,
            Err(ScanError::Unauthorized)
        );

        let limited = Scripted::new(vec![ScanResponse {
            retry_after: Some(30),
            ..reply(403, json!({"message": "secondary rate limit"}))
        }]);
        assert_eq!(
            rename_label_with(
                &limited,
                b"token",
                "octo",
                "app",
                "harborgate",
                "dockward",
                1000
            )
            .await,
            Err(ScanError::RateLimited { until: 1030 })
        );

        let other_422 = Scripted::new(vec![reply(422, json!({"errors": [{"code": "invalid"}]}))]);
        assert!(matches!(
            rename_label_with(
                &other_422,
                b"token",
                "octo",
                "app",
                "harborgate",
                "dockward",
                1000
            )
            .await,
            Err(ScanError::Upstream(_))
        ));
    }
}
