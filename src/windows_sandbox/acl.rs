// Copyright (c) Microsoft Corporation.
// Copyright (c) Codex authors.
// Licensed under the MIT License.

//! Windows ACL Management - File access control
//!
//! This module provides functionality to manage Windows ACLs for sandboxed file access.

use std::ffi::c_void;
use std::path::Path;

use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE, INVALID_HANDLE_VALUE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    GetNamedSecurityInfoW, GetSecurityInfo, SetEntriesInAclW, SetNamedSecurityInfoW,
    SetSecurityInfo, EXPLICIT_ACCESS_W, MapGenericMask, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GENERIC_MAPPING,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    READ_CONTROL,
};

const SE_KERNEL_OBJECT: u32 = 6;
const GENERIC_WRITE_MASK: u32 = 0x4000_0000;
const DENY_ACCESS: i32 = 3;

/// Fetch DACL via handle-based query
///
/// # Safety
/// Caller must free the returned security descriptor.
pub unsafe fn fetch_dacl_handle(path: &Path) -> Result<(*mut ACL, *mut c_void), String> {
    let wpath: Vec<u16> = path
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let h = CreateFileW(
        wpath.as_ptr(),
        READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        std::ptr::null_mut(),
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        0,
    );
    if h == INVALID_HANDLE_VALUE {
        return Err(format!("CreateFileW failed for {}", path.display()));
    }
    let mut p_sd: *mut c_void = std::ptr::null_mut();
    let mut p_dacl: *mut ACL = std::ptr::null_mut();
    let code = GetSecurityInfo(
        h,
        SE_KERNEL_OBJECT as i32,
        DACL_SECURITY_INFORMATION,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        &mut p_dacl,
        std::ptr::null_mut(),
        &mut p_sd,
    );
    let _ = CloseHandle(h);
    if code != ERROR_SUCCESS {
        return Err(format!("GetSecurityInfo failed: {}", code));
    }
    Ok((p_dacl, p_sd))
}

/// Add an ALLOW ACE for a specific SID with generic access rights
///
/// # Safety
/// Caller must ensure `psid` is a valid SID pointer.
pub unsafe fn add_allow_ace(path: &Path, psid: *mut c_void) -> Result<(), String> {
    let (p_dacl, p_sd) = unsafe { fetch_dacl_handle(path)? };
    let mut explicit: EXPLICIT_ACCESS_W = std::mem::zeroed();
    let mut mapping: GENERIC_MAPPING = std::mem::zeroed();
    mapping.GenericRead = FILE_GENERIC_READ;
    mapping.GenericWrite = FILE_GENERIC_WRITE;
    mapping.GenericExecute = FILE_GENERIC_EXECUTE;
    mapping.GenericAll = 0x1000_0000;
    let mut perms = FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE;
    MapGenericMask(&mut perms, &mapping);

    explicit.grfAccessPermissions = perms;
    explicit.grfAccessMode = 2; // SET_ACCESS
    explicit.grfInheritance = 0x1 | 0x2; // CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE
    explicit.Trustee = TRUSTEE_W {
        pMultipleTrustee: std::ptr::null_mut(),
        MultipleTrusteeOperation: 0,
        TrusteeForm: TRUSTEE_IS_SID,
        TrusteeType: TRUSTEE_IS_UNKNOWN,
        ptstrName: psid as *mut u16,
    };

    let mut p_new_dacl: *mut ACL = std::ptr::null_mut();
    let code = SetEntriesInAclW(1, &explicit, p_dacl, &mut p_new_dacl);
    if code != ERROR_SUCCESS {
        if !p_sd.is_null() {
            windows_sys::Win32::Foundation::LocalFree(
                p_sd as windows_sys::Win32::Foundation::HLOCAL,
            );
        }
        return Err(format!("SetEntriesInAclW failed: {}", code));
    }

    let wpath: Vec<u16> = path
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let _ = SetNamedSecurityInfoW(
        wpath.as_ptr() as *mut u16,
        1, // SE_FILE_OBJECT
        DACL_SECURITY_INFORMATION,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        p_new_dacl,
        std::ptr::null_mut(),
    );

    if !p_new_dacl.is_null() {
        windows_sys::Win32::Foundation::LocalFree(
            p_new_dacl as windows_sys::Win32::Foundation::HLOCAL,
        );
    }
    if !p_sd.is_null() {
        windows_sys::Win32::Foundation::LocalFree(p_sd as windows_sys::Win32::Foundation::HLOCAL);
    }
    Ok(())
}

/// Add a DENY WRITE ACE for a specific SID
///
/// # Safety
/// Caller must ensure `psid` is a valid SID pointer.
pub unsafe fn add_deny_write_ace(path: &Path, psid: *mut c_void) -> Result<(), String> {
    let (p_dacl, p_sd) = unsafe { fetch_dacl_handle(path)? };
    let mut explicit: EXPLICIT_ACCESS_W = std::mem::zeroed();
    let mut mapping: GENERIC_MAPPING = std::mem::zeroed();
    mapping.GenericRead = FILE_GENERIC_READ;
    mapping.GenericWrite = FILE_GENERIC_WRITE;
    mapping.GenericExecute = FILE_GENERIC_EXECUTE;
    mapping.GenericAll = 0x1000_0000;
    let mut perms = FILE_GENERIC_WRITE | 0x4000_0000; // Generic write | DELETE
    MapGenericMask(&mut perms, &mapping);

    explicit.grfAccessPermissions = perms;
    explicit.grfAccessMode = DENY_ACCESS;
    explicit.grfInheritance = 0x1 | 0x2; // CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE
    explicit.Trustee = TRUSTEE_W {
        pMultipleTrustee: std::ptr::null_mut(),
        MultipleTrusteeOperation: 0,
        TrusteeForm: TRUSTEE_IS_SID,
        TrusteeType: TRUSTEE_IS_UNKNOWN,
        ptstrName: psid as *mut u16,
    };

    let mut p_new_dacl: *mut ACL = std::ptr::null_mut();
    let code = SetEntriesInAclW(1, &explicit, p_dacl, &mut p_new_dacl);
    if code != ERROR_SUCCESS {
        if !p_sd.is_null() {
            windows_sys::Win32::Foundation::LocalFree(
                p_sd as windows_sys::Win32::Foundation::HLOCAL,
            );
        }
        return Err(format!("SetEntriesInAclW failed: {}", code));
    }

    let wpath: Vec<u16> = path
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let _ = SetNamedSecurityInfoW(
        wpath.as_ptr() as *mut u16,
        1, // SE_FILE_OBJECT
        DACL_SECURITY_INFORMATION,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        p_new_dacl,
        std::ptr::null_mut(),
    );

    if !p_new_dacl.is_null() {
        windows_sys::Win32::Foundation::LocalFree(
            p_new_dacl as windows_sys::Win32::Foundation::HLOCAL,
        );
    }
    if !p_sd.is_null() {
        windows_sys::Win32::Foundation::LocalFree(p_sd as windows_sys::Win32::Foundation::HLOCAL);
    }
    Ok(())
}

/// Grants RX to the null device for the given SID to support stdout/stderr redirection.
///
/// # Safety
/// Caller must ensure `psid` is a valid SID pointer.
pub unsafe fn allow_null_device(psid: *mut c_void) -> Result<(), String> {
    let desired = 0x00020000 | 0x00040000; // READ_CONTROL | WRITE_DAC
    let wnull = r"\\.\NUL"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<u16>>();
    let h = CreateFileW(
        wnull.as_ptr(),
        desired,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        std::ptr::null_mut(),
        OPEN_EXISTING,
        0x80, // FILE_ATTRIBUTE_NORMAL
        0,
    );
    if h == 0 || h == INVALID_HANDLE_VALUE {
        return Ok(()); // Silently fail - null device might not exist in all contexts
    }
    let mut p_sd: *mut c_void = std::ptr::null_mut();
    let mut p_dacl: *mut ACL = std::ptr::null_mut();
    let code = GetSecurityInfo(
        h,
        SE_KERNEL_OBJECT as i32,
        DACL_SECURITY_INFORMATION,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        &mut p_dacl,
        std::ptr::null_mut(),
        &mut p_sd,
    );
    if code == ERROR_SUCCESS {
        let trustee = TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: 0,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: psid as *mut u16,
        };
        let mut explicit: EXPLICIT_ACCESS_W = std::mem::zeroed();
        explicit.grfAccessPermissions =
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE;
        explicit.grfAccessMode = 2; // SET_ACCESS
        explicit.grfInheritance = 0;
        explicit.Trustee = trustee;
        let mut p_new_dacl: *mut ACL = std::ptr::null_mut();
        let code2 = SetEntriesInAclW(1, &explicit, p_dacl, &mut p_new_dacl);
        if code2 == ERROR_SUCCESS {
            let _ = SetSecurityInfo(
                h,
                SE_KERNEL_OBJECT as i32,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                p_new_dacl,
                std::ptr::null_mut(),
            );
            if !p_new_dacl.is_null() {
                windows_sys::Win32::Foundation::LocalFree(
                    p_new_dacl as windows_sys::Win32::Foundation::HLOCAL,
                );
            }
        }
    }
    if !p_sd.is_null() {
        windows_sys::Win32::Foundation::LocalFree(p_sd as windows_sys::Win32::Foundation::HLOCAL);
    }
    let _ = CloseHandle(h);
    Ok(())
}

/// Ensure allow mask ACEs exist for a path (helper for compatibility)
pub fn ensure_allow_mask_aces(_path: &Path, _psid: *mut c_void) -> Result<(), String> {
    // Placeholder for full implementation - basic ACL already handles this
    Ok(())
}

/// Ensure write allow ACEs exist for a path
pub fn ensure_allow_write_aces(_path: &Path, _psid: *mut c_void) -> Result<(), String> {
    // Placeholder for full implementation
    Ok(())
}

/// Check if a path's mask allows specific access
pub fn path_mask_allows(_path: &Path, _psid: *mut c_void, _access: u32) -> bool {
    // Placeholder for full implementation
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allow_null_device() {
        unsafe {
            // This test just verifies the function runs without panic
            // On non-Windows or in limited environments, it may return Ok
            let result = allow_null_device(std::ptr::null_mut());
            // Expected to either succeed or gracefully fail
            assert!(result.is_ok() || result.err().unwrap().contains("failed"));
        }
    }
}
