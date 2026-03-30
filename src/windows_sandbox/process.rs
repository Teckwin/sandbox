// Copyright (c) Microsoft Corporation.
// Copyright (c) Codex authors.
// Licensed under the MIT License.

//! Windows Process Management - Process creation with restricted tokens
//!
//! This module provides functionality to spawn processes using CreateProcessAsUserW
//! with restricted tokens for sandboxed execution.

use std::collections::HashMap;
use std::ffi::c_void;
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::CreateWellKnownSid;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, READ_CONTROL,
};
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    CreateProcessAsUserW, GetCurrentProcess, OpenProcessToken, CREATE_UNICODE_ENVIRONMENT,
    PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
};

/// Result of spawning a process with pipes
pub struct PipeSpawnHandles {
    /// Process information
    pub process: PROCESS_INFORMATION,
    /// Stdin write handle (if open)
    pub stdin_write: Option<HANDLE>,
    /// Stdout read handle
    pub stdout_read: HANDLE,
    /// Stderr read handle (if separate)
    pub stderr_read: Option<HANDLE>,
}

/// Stdin mode for process
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StdinMode {
    /// Keep stdin open
    Open,
    /// Close stdin
    Closed,
}

/// Stderr mode for process
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StderrMode {
    /// Merge stderr into stdout
    MergeStdout,
    /// Keep stderr separate
    Separate,
}

/// Convert a string to a wide null-terminated string
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Quote a Windows command line argument
fn quote_windows_arg(arg: &str) -> String {
    if arg.is_empty() || arg.contains(' ') || arg.contains('"') || arg.contains('\'') {
        let escaped = arg.replace('"', "\\\"");
        format!("\"{}\"", escaped)
    } else {
        arg.to_string()
    }
}

/// Make an environment block from a HashMap
pub fn make_env_block(env: &HashMap<String, String>) -> Vec<u16> {
    let mut items: Vec<(String, String)> =
        env.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    items.sort_by(|a, b| {
        a.0.to_uppercase()
            .cmp(&b.0.to_uppercase())
            .then(a.0.cmp(&b.0))
    });
    let mut w: Vec<u16> = Vec::new();
    for (k, v) in items {
        let mut s = to_wide(&format!("{}={}", k, v));
        s.pop(); // Remove trailing null
        w.extend_from_slice(&s);
        w.push(0);
    }
    w.push(0);
    w
}

/// Ensure stdio handles are inheritable
unsafe fn ensure_inheritable_stdio(si: &mut STARTUPINFOW) -> Result<(), String> {
    for kind in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        let h = GetStdHandle(kind);
        if h.is_null() || h == INVALID_HANDLE_VALUE {
            return Err(format!("GetStdHandle failed: {}", GetLastError()));
        }
        if windows_sys::Win32::Foundation::SetHandleInformation(h, 0x00000001, 0x00000001) == 0 {
            // HANDLE_FLAG_INHERIT = 1
            return Err(format!("SetHandleInformation failed: {}", GetLastError()));
        }
    }
    si.dwFlags |= STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    Ok(())
}

/// Create a process as a different user using a restricted token
///
/// # Safety
/// Caller must provide a valid primary token handle with appropriate access,
/// and the argv, cwd, and env_map must remain valid for the duration of the call.
pub unsafe fn create_process_as_user(
    h_token: HANDLE,
    argv: &[String],
    cwd: &Path,
    env_map: &HashMap<String, String>,
    _logs_base_dir: Option<&Path>,
    stdio: Option<(HANDLE, HANDLE, HANDLE)>,
    _use_private_desktop: bool,
) -> Result<PROCESS_INFORMATION, String> {
    let cmdline_str = argv
        .iter()
        .map(|a| quote_windows_arg(a))
        .collect::<Vec<_>>()
        .join(" ");
    let cmdline: Vec<u16> = to_wide(&cmdline_str);
    let env_block = make_env_block(env_map);

    let mut si: STARTUPINFOW = std::mem::zeroed();
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;

    // Set up stdio handles if provided
    if let Some((stdin_handle, stdout_handle, stderr_handle)) = stdio {
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = stdin_handle;
        si.hStdOutput = stdout_handle;
        si.hStdError = stderr_handle;
    } else {
        // Otherwise use current process handles
        let _ = ensure_inheritable_stdio(&mut si);
    }

    // Set up desktop (for private desktop support)
    // Note: Full private desktop implementation requires additional Windows API calls

    let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

    let cwd_wide: Vec<u16> = cwd
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let result = CreateProcessAsUserW(
        h_token,
        ptr::null(), // Application name (use command line)
        cmdline.as_ptr() as *mut u16,
        ptr::null(), // Process security attributes
        ptr::null(), // Thread security attributes
        1,           // Inherit handles
        CREATE_UNICODE_ENVIRONMENT,
        env_block.as_ptr() as *const c_void,
        cwd_wide.as_ptr(),
        &mut si,
        &mut pi,
    );

    if result == 0 {
        return Err(format!("CreateProcessAsUserW failed: {}", GetLastError()));
    }

    // Close thread handle - we don't need it
    if !pi.hThread.is_null() {
        let _ = CloseHandle(pi.hThread);
    }

    Ok(pi)
}

/// Spawn a process with pipe handles
///
/// # Safety
/// Caller must provide a valid primary token handle.
pub unsafe fn spawn_process_with_pipes(
    h_token: HANDLE,
    argv: &[String],
    cwd: &Path,
    env_map: &HashMap<String, String>,
    stdin_mode: StdinMode,
    stderr_mode: StderrMode,
    use_private_desktop: bool,
) -> Result<PipeSpawnHandles, String> {
    let mut in_r: HANDLE = std::ptr::null_mut();
    let mut in_w: HANDLE = std::ptr::null_mut();
    let mut out_r: HANDLE = std::ptr::null_mut();
    let mut out_w: HANDLE = std::ptr::null_mut();
    let mut err_r: HANDLE = std::ptr::null_mut();
    let mut err_w: HANDLE = std::ptr::null_mut();

    unsafe {
        if CreatePipe(&mut in_r, &mut in_w, ptr::null_mut(), 0) == 0 {
            return Err(format!("CreatePipe stdin failed: {}", GetLastError()));
        }
        if CreatePipe(&mut out_r, &mut out_w, ptr::null_mut(), 0) == 0 {
            CloseHandle(in_r);
            CloseHandle(in_w);
            return Err(format!("CreatePipe stdout failed: {}", GetLastError()));
        }
        if stderr_mode == StderrMode::Separate
            && CreatePipe(&mut err_r, &mut err_w, ptr::null_mut(), 0) == 0
        {
            CloseHandle(in_r);
            CloseHandle(in_w);
            CloseHandle(out_r);
            CloseHandle(out_w);
            return Err(format!("CreatePipe stderr failed: {}", GetLastError()));
        }
    }

    let stderr_handle = match stderr_mode {
        StderrMode::MergeStdout => out_w,
        StderrMode::Separate => err_w,
    };

    let stdio = Some((in_r, out_w, stderr_handle));
    let spawn_result = create_process_as_user(
        h_token,
        argv,
        cwd,
        env_map,
        None,
        stdio,
        use_private_desktop,
    );

    let pi = match spawn_result {
        Ok(v) => v,
        Err(err) => {
            unsafe {
                CloseHandle(in_r);
                CloseHandle(in_w);
                CloseHandle(out_r);
                CloseHandle(out_w);
                if stderr_mode == StderrMode::Separate {
                    CloseHandle(err_r);
                    CloseHandle(err_w);
                }
            }
            return Err(err);
        }
    };

    unsafe {
        CloseHandle(in_r);
        CloseHandle(out_w);
        if stderr_mode == StderrMode::Separate {
            CloseHandle(err_w);
        }
        if stdin_mode == StdinMode::Closed {
            CloseHandle(in_w);
        }
    }

    Ok(PipeSpawnHandles {
        process: pi,
        stdin_write: if stdin_mode == StdinMode::Open {
            Some(in_w)
        } else {
            None
        },
        stdout_read: out_r,
        stderr_read: if stderr_mode == StderrMode::Separate {
            Some(err_r)
        } else {
            None
        },
    })
}

/// Get the current user token for restriction
pub fn get_current_user_token() -> Result<HANDLE, String> {
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        let ok = OpenProcessToken(
            GetCurrentProcess(),
            0x1F, // TOKEN_ALL_ACCESS (0xF) | TOKEN_ADJUST_SESSIONID (0x10)
            &mut token,
        );
        if ok == 0 {
            return Err(format!("OpenProcessToken failed: {}", GetLastError()));
        }
        Ok(token)
    }
}

#[cfg(test)]
#[cfg(target_os = "windows")]
mod tests {
    use super::*;

    #[test]
    fn test_make_env_block() {
        let mut env = HashMap::new();
        env.insert("TEST".to_string(), "value".to_string());
        env.insert("PATH".to_string(), "/bin".to_string());

        let block = make_env_block(&env);

        // Should contain null-terminated strings
        assert!(!block.is_empty());
        // Should end with double null
        assert_eq!(block[block.len() - 1], 0);
    }

    #[test]
    fn test_quote_windows_arg() {
        assert_eq!(quote_windows_arg("simple"), "simple");
        assert_eq!(quote_windows_arg("with space"), "\"with space\"");
        assert_eq!(quote_windows_arg("with\"quote"), "\"with\\\"quote\"");
    }
}
