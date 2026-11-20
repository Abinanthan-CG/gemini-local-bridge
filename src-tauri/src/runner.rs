use crate::policy::ProgramEntry;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::process::Command;

pub struct CommandOutput {
    pub exit_code: i32,
    pub duration_ms: u128,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub truncated: bool,
}

#[cfg(windows)]
struct JobGuard {
    handle: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
unsafe impl Send for JobGuard {}
#[cfg(windows)]
unsafe impl Sync for JobGuard {}

#[cfg(windows)]
impl JobGuard {
    fn create_and_assign(process_handle: windows_sys::Win32::Foundation::HANDLE) -> Option<Self> {
        use std::mem::{size_of, zeroed};
        use std::ptr;
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        };

        unsafe {
            let job = CreateJobObjectW(ptr::null(), ptr::null());
            if job.is_null() {
                return None;
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = zeroed();
            info.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
            info.BasicLimitInformation.ActiveProcessLimit = 32;

            let ok = SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const _,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
            if ok == 0 {
                CloseHandle(job);
                return None;
            }
            // Assigning may fail if the parent itself is inside a non-nested job on older Windows;
            // still keep the job guard only if assignment succeeded.
            if AssignProcessToJobObject(job, process_handle) == 0 {
                CloseHandle(job);
                return None;
            }
            Some(Self { handle: job })
        }
    }
}

#[cfg(windows)]
impl Drop for JobGuard {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.handle);
        }
    }
}

async fn read_capped<R: tokio::io::AsyncRead + Unpin>(
    mut reader: R,
    cap: usize,
) -> (String, bool) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let mut truncated = false;
    loop {
        match reader.read(&mut tmp).await {
            Ok(0) => break,
            Ok(n) => {
                if buf.len() < cap {
                    let take = (cap - buf.len()).min(n);
                    buf.extend_from_slice(&tmp[..take]);
                    if take < n {
                        truncated = true;
                    }
                } else {
                    truncated = true;
                }
            }
            Err(_) => break,
        }
    }
    (String::from_utf8_lossy(&buf).to_string(), truncated)
}

/// Runs an allowlisted program with NO shell, stripped environment, Windows Job Object
/// process-tree containment, bounded output, and hard timeout.
pub async fn run_allowlisted(
    entry: &ProgramEntry,
    args: &[String],
    cwd: &Path,
    timeout_secs: u64,
    max_output_bytes: usize,
) -> CommandOutput {
    let started = Instant::now();
    let mut cmd = Command::new(&entry.file);
    cmd.args(&entry.prefix)
        .args(args)
        .current_dir(cwd)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    #[cfg(windows)]
    cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW

    // Minimal safe environment allowlist (never leaks API tokens or custom secrets).
    for key in [
        "PATH",
        "PATHEXT",
        "SystemRoot",
        "windir",
        "ComSpec",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "HOME",
        "USERNAME",
        "APPDATA",
        "LOCALAPPDATA",
        "PROGRAMDATA",
        "PROGRAMFILES",
        "ProgramFiles(x86)",
    ] {
        if let Ok(val) = std::env::var(key) {
            cmd.env(key, val);
        }
    }
    cmd.env("PYTHONUTF8", "1");
    cmd.env("PYTHONIOENCODING", "utf-8");

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return CommandOutput {
                exit_code: -1,
                duration_ms: started.elapsed().as_millis(),
                stdout: String::new(),
                stderr: format!("SPAWN_FAILED: {e}"),
                timed_out: false,
                truncated: false,
            };
        }
    };

    // Attach to a Windows Job Object so every child/grandchild dies automatically on timeout or drop.
    #[cfg(windows)]
    let _job = child
        .raw_handle()
        .and_then(|h| JobGuard::create_and_assign(h as _));

    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();
    let half_cap = max_output_bytes / 2;

    let out_task = tokio::spawn(async move {
        match stdout_pipe {
            Some(r) => read_capped(r, half_cap).await,
            None => (String::new(), false),
        }
    });
    let err_task = tokio::spawn(async move {
        match stderr_pipe {
            Some(r) => read_capped(r, half_cap).await,
            None => (String::new(), false),
        }
    });

    let wait_res = tokio::time::timeout(Duration::from_secs(timeout_secs), child.wait()).await;
    let (exit_code, timed_out) = match wait_res {
        Ok(Ok(status)) => (status.code().unwrap_or(-1), false),
        Ok(Err(_)) => (-1, false),
        Err(_) => {
            let _ = child.kill().await;
            #[cfg(windows)]
            drop(_job); // Dropping JobGuard with KILL_ON_JOB_CLOSE immediately terminates the whole process tree.
            (-1, true)
        }
    };

    let (stdout, out_trunc) = out_task.await.unwrap_or_default();
    let (stderr, err_trunc) = err_task.await.unwrap_or_default();

    CommandOutput {
        exit_code,
        duration_ms: started.elapsed().as_millis(),
        stdout,
        stderr,
        timed_out,
        truncated: out_trunc || err_trunc,
    }
}
