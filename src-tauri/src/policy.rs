use crate::config::{data_dir, BridgeConfig};
use crate::store::{normalize_path_key, Grant, GrantKind, Store};
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[derive(Debug, Clone)]
pub struct ProgramEntry {
    pub file: PathBuf,
    pub prefix: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ResolvedPath {
    pub abs: PathBuf,
    pub real: PathBuf,
    pub inside_workspace: bool,
    pub forbidden: bool,
    pub exists: bool,
}

pub enum PathAccess {
    Allowed { grant: Option<Grant> },
    Denied { code: &'static str, target: String, message: String },
}

pub enum ProgramAccess {
    Allowed { entry: ProgramEntry, grant: Option<Grant> },
    Denied { code: &'static str, target: String, message: String },
}

pub fn which(name: &str) -> Option<PathBuf> {
    let mut cmd = Command::new("where.exe");
    cmd.arg(name);
    #[cfg(windows)]
    cmd.creation_flags(0x0800_0000);
    let out = cmd.output().ok()?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(PathBuf::from)
}

pub fn resolve_programs(allowlist: &[String]) -> HashMap<String, ProgramEntry> {
    let mut out = HashMap::new();
    let node_bin = which("node");
    let python_bin = which("python").or_else(|| which("python3"));

    for raw in allowlist {
        let name = raw.trim().to_lowercase();
        if name.is_empty() {
            continue;
        }
        if name == "npm" || name == "npx" {
            if let Some(ref node) = node_bin {
                if let Some(node_dir) = node.parent() {
                    let cli = node_dir
                        .join("node_modules")
                        .join("npm")
                        .join("bin")
                        .join(if name == "npm" { "npm-cli.js" } else { "npx-cli.js" });
                    if cli.exists() {
                        out.insert(
                            name,
                            ProgramEntry {
                                file: node.clone(),
                                prefix: vec![cli.to_string_lossy().to_string()],
                            },
                        );
                        continue;
                    }
                }
            }
        }
        if name == "pytest" || name == "pip" {
            if let Some(ref py) = python_bin {
                out.insert(
                    name.clone(),
                    ProgramEntry {
                        file: py.clone(),
                        prefix: vec!["-m".into(), name],
                    },
                );
                continue;
            }
        }
        if let Some(resolved) = which(&name) {
            out.insert(
                name,
                ProgramEntry {
                    file: resolved,
                    prefix: Vec::new(),
                },
            );
        }
    }
    out
}

fn clean_lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

pub fn strip_verbatim(p: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\") {
        PathBuf::from(rest)
    } else {
        p.to_path_buf()
    }
}

/// Resolves symlinks/junctions on the nearest existing ancestor so symlink escapes cannot fool containment.
pub fn realpath_nearest(target: &Path) -> PathBuf {
    let mut current = target.to_path_buf();
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    for _ in 0..48 {
        if let Ok(canon) = std::fs::canonicalize(&current) {
            let mut result = strip_verbatim(&canon);
            for part in tail.into_iter().rev() {
                result.push(part);
            }
            return result;
        }
        if let Some(name) = current.file_name() {
            tail.push(name.to_os_string());
        }
        if !current.pop() {
            break;
        }
    }
    target.to_path_buf()
}

pub fn is_inside(root_key: &str, candidate_key: &str) -> bool {
    candidate_key == root_key || candidate_key.starts_with(&format!("{root_key}\\"))
}

pub struct Policy {
    pub workspace: PathBuf,
    pub workspace_key: String,
    pub workspace_real_key: String,
    pub forbidden_keys: Vec<String>,
    pub programs: HashMap<String, ProgramEntry>,
}

impl Policy {
    pub fn from_config(cfg: &BridgeConfig) -> Self {
        let workspace = clean_lexical(Path::new(&cfg.workspace));
        let workspace_real = realpath_nearest(&workspace);
        let mut forbidden = vec![
            normalize_path_key(&data_dir().to_string_lossy()),
            normalize_path_key(&realpath_nearest(&data_dir()).to_string_lossy()),
        ];
        if let Some(home) = dirs::home_dir() {
            let legacy = home.join(".gemini-bridge");
            forbidden.push(normalize_path_key(&legacy.to_string_lossy()));
        }
        Self {
            workspace_key: normalize_path_key(&workspace.to_string_lossy()),
            workspace_real_key: normalize_path_key(&workspace_real.to_string_lossy()),
            workspace,
            forbidden_keys: forbidden,
            programs: resolve_programs(&cfg.program_allowlist),
        }
    }

    pub fn resolve(&self, requested: &str) -> ResolvedPath {
        let trimmed = requested.trim();
        let raw = if trimmed.is_empty() { "." } else { trimmed };
        let candidate = Path::new(raw);
        let abs = if candidate.is_absolute() {
            clean_lexical(candidate)
        } else {
            clean_lexical(&self.workspace.join(candidate))
        };
        let real = realpath_nearest(&abs);
        let abs_key = normalize_path_key(&abs.to_string_lossy());
        let real_key = normalize_path_key(&real.to_string_lossy());

        let forbidden = self
            .forbidden_keys
            .iter()
            .any(|fk| is_inside(fk, &abs_key) || is_inside(fk, &real_key));

        let inside = !forbidden
            && is_inside(&self.workspace_key, &abs_key)
            && is_inside(&self.workspace_real_key, &real_key);

        let exists = abs.exists();
        ResolvedPath {
            abs,
            real,
            inside_workspace: inside,
            forbidden,
            exists,
        }
    }

    pub fn path_access(&self, store: &Store, requested: &str) -> (ResolvedPath, PathAccess) {
        let resolved = self.resolve(requested);
        if resolved.forbidden {
            let target = resolved.real.to_string_lossy().to_string();
            return (
                resolved,
                PathAccess::Denied {
                    code: "FORBIDDEN_BRIDGE_DATA",
                    target,
                    message: "Bridge configuration, secrets, and logs are strictly inaccessible."
                        .into(),
                },
            );
        }
        if resolved.inside_workspace {
            return (resolved, PathAccess::Allowed { grant: None });
        }
        let target = resolved.real.to_string_lossy().to_string();
        if let Some(grant) = store.find_grant(&GrantKind::Path, &target) {
            return (resolved, PathAccess::Allowed { grant: Some(grant) });
        }
        let msg = format!(
            "Path is outside the workspace ({}). Ask the user to approve this path.",
            self.workspace.display()
        );
        (
            resolved,
            PathAccess::Denied {
                code: "OUTSIDE_WORKSPACE",
                target,
                message: msg,
            },
        )
    }

    pub fn program_access(&self, store: &Store, name: &str) -> ProgramAccess {
        let key = name.trim().to_lowercase();
        let key = key.strip_suffix(".exe").unwrap_or(&key).to_string();
        if let Some(entry) = self.programs.get(&key) {
            return ProgramAccess::Allowed {
                entry: entry.clone(),
                grant: None,
            };
        }
        if let Some(grant) = store.find_grant(&GrantKind::Program, &key) {
            if let Some(resolved) = which(&key) {
                return ProgramAccess::Allowed {
                    entry: ProgramEntry {
                        file: resolved,
                        prefix: Vec::new(),
                    },
                    grant: Some(grant),
                };
            }
        }
        let mut allowed: Vec<String> = self.programs.keys().cloned().collect();
        allowed.sort();
        ProgramAccess::Denied {
            code: "PROGRAM_NOT_ALLOWED",
            target: key.clone(),
            message: format!(
                "Program \"{key}\" is not on the allowlist ({}). Ask the user to approve this program.",
                allowed.join(", ")
            ),
        }
    }

    pub fn program_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.programs.keys().cloned().collect();
        names.sort();
        names
    }
}
