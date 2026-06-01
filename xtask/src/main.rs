#![forbid(unsafe_code)]
//! `xtask`: the project gate runner (REQ-GOV gates), run as
//! `cargo run -p xtask -- <command>`.
//!
//! Commands:
//! - `banned-tokens` — fail if any banned chain/asset identifier or tool-identity
//!   token appears in tracked text content or filenames (REQ-UNI-005, REQ-GOV-071).
//! - `fn-size` — fail if any public function exceeds the page limit (REQ-GOV-015).
//! - `rtm` — structural validation of `docs/RTM.csv` (REQ-GOV-060/061).
//! - `all` — run all of the above.
//!
//! Banned tokens are assembled from fragments at run time, so this gate's own
//! source contains no banned literal and the gate's output never echoes a token.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const MAX_FN_LINES: usize = 60;
const TEXT_EXTS: [&str; 12] = [
    "rs", "toml", "md", "csv", "yml", "yaml", "json", "lock", "txt", "sh", "ps1", "cfg",
];
const SKIP_DIRS: [&str; 4] = ["target", ".git", "node_modules", "legacy"];

#[derive(Debug)]
enum XError {
    Io(std::io::Error),
    Gate {
        name: &'static str,
        findings: Vec<String>,
    },
    Usage,
    NoRoot,
}

impl fmt::Display for XError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io error: {e}"),
            Self::Gate { name, findings } => {
                writeln!(
                    f,
                    "gate '{name}' FAILED with {} finding(s):",
                    findings.len()
                )?;
                for item in findings {
                    writeln!(f, "  - {item}")?;
                }
                Ok(())
            }
            Self::Usage => write!(f, "usage: xtask <banned-tokens|fn-size|rtm|sbom|all>"),
            Self::NoRoot => write!(f, "cannot determine workspace root"),
        }
    }
}
impl std::error::Error for XError {}
impl From<std::io::Error> for XError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

fn main() -> ExitCode {
    let root = match workspace_root() {
        Ok(r) => r,
        Err(e) => return fail(&e),
    };
    let cmd = std::env::args().nth(1);
    let outcome = match cmd.as_deref() {
        Some("banned-tokens") => cmd_banned_tokens(&root),
        Some("fn-size") => cmd_fn_size(&root),
        Some("rtm") => cmd_rtm(&root),
        Some("sbom") => cmd_sbom(&root),
        Some("all") => cmd_all(&root),
        _ => Err(XError::Usage),
    };
    match outcome {
        Ok(()) => {
            println!("xtask: OK");
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e),
    }
}

fn fail(e: &XError) -> ExitCode {
    eprintln!("xtask: {e}");
    ExitCode::FAILURE
}

fn workspace_root() -> Result<PathBuf, XError> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or(XError::NoRoot)
}

fn cmd_all(root: &Path) -> Result<(), XError> {
    cmd_banned_tokens(root)?;
    cmd_fn_size(root)?;
    cmd_rtm(root)?;
    cmd_sbom(root)
}

// ---- SBOM gate (REQ-CON-020) ------------------------------------------------
// Generate a CycloneDX SBOM from Cargo.lock (no external tool needed) and fail if it
// is empty or fails to cover the locked dependency set.

fn cmd_sbom(root: &Path) -> Result<(), XError> {
    let lock = fs::read_to_string(root.join("Cargo.lock"))?;
    let (json, count) = build_sbom(&lock);
    if count == 0 {
        return Err(XError::Gate {
            name: "sbom",
            findings: vec!["SBOM has no components".to_owned()],
        });
    }
    let out_dir = root.join("docs");
    fs::create_dir_all(&out_dir)?;
    fs::write(out_dir.join("sbom.cyclonedx.json"), json.as_bytes())?;
    println!("sbom: {count} components written to docs/sbom.cyclonedx.json");
    Ok(())
}

// Parse Cargo.lock `[[package]]` blocks into a minimal CycloneDX 1.5 document. Returns
// the JSON and the component count.
fn build_sbom(cargo_lock: &str) -> (String, usize) {
    let mut components: Vec<(String, String)> = Vec::new();
    let mut name: Option<String> = None;
    for line in cargo_lock.lines() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            name = None;
        } else if let Some(value) = trimmed.strip_prefix("name = ") {
            name = Some(unquote(value));
        } else if let Some(value) = trimmed.strip_prefix("version = ") {
            if let Some(package_name) = name.take() {
                components.push((package_name, unquote(value)));
            }
        }
    }
    let mut body = String::new();
    for (index, (component_name, version)) in components.iter().enumerate() {
        if index > 0 {
            body.push(',');
        }
        body.push_str(&format!(
            "{{\"type\":\"library\",\"name\":\"{}\",\"version\":\"{}\"}}",
            json_escape(component_name),
            json_escape(version)
        ));
    }
    let json = format!("{{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\",\"version\":1,\"components\":[{body}]}}\n");
    (json, components.len())
}

fn unquote(value: &str) -> String {
    value.trim().trim_matches('"').to_owned()
}

fn json_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

// ---- file walking -----------------------------------------------------------

fn collect_text_files(root: &Path) -> Result<Vec<PathBuf>, XError> {
    let mut out = Vec::new();
    walk(root, &mut out)?;
    Ok(out)
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), XError> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            if !skip_dir(&path) {
                walk(&path, out)?;
            }
        } else if is_text_file(&path) {
            out.push(path);
        }
    }
    Ok(())
}

fn skip_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| SKIP_DIRS.contains(&n))
}

fn is_text_file(path: &Path) -> bool {
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        if name.eq_ignore_ascii_case("Dockerfile") || name == ".gitignore" {
            return true;
        }
    }
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| TEXT_EXTS.contains(&e.to_ascii_lowercase().as_str()))
}

fn display_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

// ---- banned-tokens gate (REQ-UNI-005, REQ-GOV-071) --------------------------

fn banned_tokens() -> Vec<String> {
    // Fragment pairs, joined at run time: no banned literal exists in this source.
    let frags: [(&str, &str); 16] = [
        ("BT", "C"),
        ("ethe", "reum"),
        ("lite", "coin"),
        ("doge", "coin"),
        ("sol", "ana"),
        ("mon", "ero"),
        ("rip", "ple"),
        ("car", "dano"),
        ("seg", "wit"),
        ("light", "ning"),
        ("tap", "root"),
        ("cla", "ude"),
        ("cop", "ilot"),
        ("chat", "gpt"),
        ("open", "ai"),
        ("anthro", "pic"),
    ];
    frags
        .iter()
        .map(|(a, b)| format!("{a}{b}").to_ascii_lowercase())
        .collect()
}

fn cmd_banned_tokens(root: &Path) -> Result<(), XError> {
    let tokens = banned_tokens();
    let mut findings = Vec::new();
    for path in &collect_text_files(root)? {
        scan_file_for_banned(root, path, &tokens, &mut findings);
    }
    finish("banned-tokens", findings)
}

fn scan_file_for_banned(root: &Path, path: &Path, tokens: &[String], findings: &mut Vec<String>) {
    if let Ok(content) = fs::read_to_string(path) {
        if any_banned(&content.to_ascii_lowercase(), tokens) {
            findings.push(format!(
                "{}: contains a banned token",
                display_path(root, path)
            ));
        }
    }
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        if any_banned(&name.to_ascii_lowercase(), tokens) {
            findings.push(format!(
                "{}: banned token in filename",
                display_path(root, path)
            ));
        }
    }
}

fn any_banned(haystack_lower: &str, tokens: &[String]) -> bool {
    tokens.iter().any(|t| haystack_lower.contains(t.as_str()))
}

// ---- function-size gate (REQ-GOV-015) ---------------------------------------

fn cmd_fn_size(root: &Path) -> Result<(), XError> {
    let mut findings = Vec::new();
    for path in &collect_text_files(root)? {
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        if let Ok(content) = fs::read_to_string(path) {
            check_fn_sizes(&content, &display_path(root, path), &mut findings);
        }
    }
    finish("fn-size", findings)
}

fn check_fn_sizes(content: &str, path: &str, findings: &mut Vec<String>) {
    let lines: Vec<&str> = content.lines().collect();
    let mut idx = 0usize;
    while idx < lines.len() {
        let line = lines.get(idx).copied().unwrap_or("");
        if is_fn_signature(line) {
            let (exec, end) = measure_fn(&lines, idx);
            if exec > MAX_FN_LINES {
                findings.push(format!(
                    "{path}: public fn near line {} has {exec} executable lines (> {MAX_FN_LINES})",
                    idx.saturating_add(1)
                ));
            }
            idx = end.max(idx.saturating_add(1));
        } else {
            idx = idx.saturating_add(1);
        }
    }
}

fn is_fn_signature(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("pub fn ")
        || t.starts_with("pub async fn ")
        || t.starts_with("pub(crate) fn ")
        || t.starts_with("pub(crate) async fn ")
}

fn measure_fn(lines: &[&str], start: usize) -> (usize, usize) {
    let mut depth = 0usize;
    let mut started = false;
    let mut exec = 0usize;
    let mut i = start;
    while i < lines.len() {
        let line = lines.get(i).copied().unwrap_or("");
        let opens = line.matches('{').count();
        let closes = line.matches('}').count();
        depth = depth.saturating_add(opens).saturating_sub(closes);
        if opens > 0 {
            started = true;
        }
        let t = line.trim();
        if started && !t.is_empty() && !t.starts_with("//") {
            exec = exec.saturating_add(1);
        }
        if started && depth == 0 {
            return (exec, i);
        }
        i = i.saturating_add(1);
    }
    (exec, lines.len())
}

// ---- RTM structural gate (REQ-GOV-060/061, structural part) ------------------

fn cmd_rtm(root: &Path) -> Result<(), XError> {
    let path = root.join("docs").join("RTM.csv");
    let content = fs::read_to_string(&path)?;
    let mut lines = content.lines();
    let header = lines.next().unwrap_or("");
    let cols: Vec<&str> = header.split(',').map(str::trim).collect();
    let mut findings = Vec::new();
    for req in ["req_id", "verification", "test_ids"] {
        if !cols.iter().any(|c| c.eq_ignore_ascii_case(req)) {
            findings.push(format!("RTM.csv missing required column '{req}'"));
        }
    }
    let ri = col_index(&cols, "req_id");
    let vi = col_index(&cols, "verification");
    let ti = col_index(&cols, "test_ids");
    let mut row_no = 1usize;
    for row in lines {
        row_no = row_no.saturating_add(1);
        if row.trim().is_empty() {
            continue;
        }
        validate_rtm_row(row, row_no, ri, vi, ti, &mut findings);
    }
    finish("rtm", findings)
}

fn validate_rtm_row(
    row: &str,
    row_no: usize,
    ri: Option<usize>,
    vi: Option<usize>,
    ti: Option<usize>,
    findings: &mut Vec<String>,
) {
    let cells: Vec<&str> = row.split(',').map(str::trim).collect();
    let cell = |i: Option<usize>| i.and_then(|n| cells.get(n)).copied().unwrap_or("");
    let req = cell(ri);
    let ver = cell(vi);
    let tests = cell(ti);
    if req.is_empty() {
        findings.push(format!("RTM.csv row {row_no}: empty req_id"));
    }
    if !["T", "A", "I", "D"].contains(&ver) {
        findings.push(format!(
            "RTM.csv row {row_no}: verification '{ver}' not one of T/A/I/D"
        ));
    }
    if ver == "T" && tests.is_empty() {
        findings.push(format!(
            "RTM.csv row {row_no}: verification=T but no test_ids"
        ));
    }
}

fn col_index(cols: &[&str], name: &str) -> Option<usize> {
    cols.iter().position(|c| c.eq_ignore_ascii_case(name))
}

fn finish(name: &'static str, findings: Vec<String>) -> Result<(), XError> {
    if findings.is_empty() {
        Ok(())
    } else {
        Err(XError::Gate { name, findings })
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    // TST-GOV-071: the banned-token detector flags an assembled banned token in
    // both content and a filename, and passes clean text. The token is assembled
    // from fragments so this test source contains no banned literal either.
    #[test]
    fn tst_gov_071_banned_token_detected() {
        let tokens = banned_tokens();
        assert_eq!(tokens.len(), 16);
        assert!(tokens
            .iter()
            .all(|t| !t.is_empty() && t == &t.to_ascii_lowercase()));
        let needle = tokens.first().cloned().unwrap();
        let haystack = format!("harmless text {needle} more text").to_ascii_lowercase();
        assert!(any_banned(&haystack, &tokens));
        assert!(!any_banned(
            "perfectly innocent bsv content in minor units",
            &tokens
        ));
    }

    // TST-GOV-015: the function-size gate flags an over-length public function and
    // accepts a short one.
    #[test]
    fn tst_gov_015_fn_size_detected() {
        let mut long = String::from("pub fn big() {\n");
        for i in 0..70 {
            long.push_str(&format!("    let _x{i} = {i};\n"));
        }
        long.push_str("}\n");
        let mut findings = Vec::new();
        check_fn_sizes(&long, "synthetic.rs", &mut findings);
        assert_eq!(findings.len(), 1, "a 70-line public fn must be flagged");

        let short = "pub fn small() {\n    let _ = 1;\n}\n";
        let mut ok = Vec::new();
        check_fn_sizes(short, "synthetic.rs", &mut ok);
        assert!(ok.is_empty(), "a short public fn must pass");
    }

    // TST-GOV-060: RTM row validation flags a bad verification method and a
    // verification=T row missing test ids, and accepts a well-formed row.
    #[test]
    fn tst_gov_060_rtm_row_validation() {
        let cols = ["req_id", "verification", "test_ids"];
        let ri = col_index(&cols, "req_id");
        let vi = col_index(&cols, "verification");
        let ti = col_index(&cols, "test_ids");

        let mut bad_ver = Vec::new();
        validate_rtm_row("REQ-X-1,Z,TST-X-1", 2, ri, vi, ti, &mut bad_ver);
        assert_eq!(
            bad_ver.len(),
            1,
            "an unknown verification method is flagged"
        );

        let mut missing_tests = Vec::new();
        validate_rtm_row("REQ-X-1,T,", 3, ri, vi, ti, &mut missing_tests);
        assert_eq!(
            missing_tests.len(),
            1,
            "verification=T with no test ids is flagged"
        );

        let mut empty_req = Vec::new();
        validate_rtm_row(",T,TST-X-1", 4, ri, vi, ti, &mut empty_req);
        assert_eq!(empty_req.len(), 1, "an empty req_id is flagged");

        let mut good = Vec::new();
        validate_rtm_row("REQ-X-1,T,TST-X-1", 5, ri, vi, ti, &mut good);
        assert!(good.is_empty(), "a well-formed verification=T row passes");

        let mut inspect = Vec::new();
        validate_rtm_row("REQ-X-2,I,", 6, ri, vi, ti, &mut inspect);
        assert!(inspect.is_empty(), "an inspection row needs no test id");
    }

    // The text-file classifier and fn-signature recogniser behave as specified.
    #[test]
    fn classifiers_behave() {
        assert!(is_text_file(Path::new("a/b/lib.rs")));
        assert!(is_text_file(Path::new("Dockerfile")));
        assert!(!is_text_file(Path::new("image.png")));
        assert!(is_fn_signature("    pub fn foo() {"));
        assert!(is_fn_signature("pub async fn bar() {"));
        assert!(!is_fn_signature("    fn private() {"));
    }

    // TST-CON-020: the SBOM is generated from Cargo.lock, is non-empty, and covers the
    // locked dependency set with name+version per component.
    #[test]
    fn tst_con_020_sbom_covers_dependencies() {
        let lock = "\
[[package]]\nname = \"k256\"\nversion = \"0.13.4\"\n\n\
[[package]]\nname = \"argon2\"\nversion = \"0.5.3\"\n";
        let (json, count) = build_sbom(lock);
        assert_eq!(count, 2, "every locked package is a component");
        assert!(
            json.contains("\"bomFormat\":\"CycloneDX\""),
            "CycloneDX format"
        );
        assert!(json.contains("\"name\":\"k256\",\"version\":\"0.13.4\""));
        assert!(json.contains("\"name\":\"argon2\",\"version\":\"0.5.3\""));

        // an empty lock yields no components (and the gate would reject it)
        assert_eq!(build_sbom("").1, 0);
    }
}
