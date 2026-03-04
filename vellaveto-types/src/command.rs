// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// Resolve the absolute path used to spawn an executable, mirroring `Command::new`.
pub fn resolve_executable(command: &str, path_env: Option<&OsStr>) -> Result<PathBuf, String> {
    let command_path = Path::new(command);

    if command_path.is_absolute() || command.chars().any(std::path::is_separator) {
        return ensure_command_is_executable(command_path);
    }

    let path_env = path_env.ok_or_else(|| {
        "PATH is not set while resolving command; pass absolute path or set PATH".to_string()
    })?;

    for dir in std::env::split_paths(path_env) {
        let candidate = dir.join(command);
        if is_runnable_command_candidate(&candidate) {
            return Ok(candidate);
        }
    }

    Err(format!(
        "command '{command}' not found in PATH; pass absolute path or include it in PATH"
    ))
}

fn ensure_command_is_executable(path: &Path) -> Result<PathBuf, String> {
    if is_runnable_command_candidate(path) {
        Ok(path.canonicalize().unwrap_or_else(|_| path.to_path_buf()))
    } else {
        Err(format!("command '{}' is not executable", path.display()))
    }
}

fn is_runnable_command_candidate(candidate: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        match std::fs::metadata(candidate) {
            Ok(meta) => meta.is_file() && (meta.permissions().mode() & 0o111) != 0,
            Err(_) => false,
        }
    }

    #[cfg(not(unix))]
    {
        candidate.is_file()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "{}_{}_{}",
            prefix,
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        dir
    }

    #[test]
    fn resolves_absolute_path() {
        let resolved = resolve_executable("/bin/true", None)
            .unwrap_or_else(|e| panic!("expected /bin/true to resolve: {e}"));
        assert!(resolved.is_absolute());
    }

    #[test]
    fn resolves_from_path() {
        let temp_dir = unique_temp_dir("resolve-path");
        std::fs::create_dir_all(&temp_dir).unwrap();

        let candidate = temp_dir.join("mock-exec");
        std::fs::write(&candidate, b"#! /bin/sh\necho hi\n").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&candidate).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&candidate, perms).unwrap();
        }

        let path_env: OsString = std::env::join_paths([temp_dir.clone()]).unwrap();
        let resolved = resolve_executable("mock-exec", Some(path_env.as_os_str())).unwrap();
        assert_eq!(resolved, candidate);

        let _ = std::fs::remove_file(&candidate);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn rejects_nonexistent_command() {
        let temp_dir = unique_temp_dir("resolve-missing");
        std::fs::create_dir_all(&temp_dir).unwrap();
        let path_env: OsString = std::env::join_paths([temp_dir.clone()]).unwrap();

        let err = resolve_executable("nope", Some(path_env.as_os_str())).expect_err("missing");
        assert!(err.contains("not found in PATH"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    #[cfg(unix)]
    fn rejects_non_executable_file() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = unique_temp_dir("resolve-nonexec");
        std::fs::create_dir_all(&temp_dir).unwrap();

        let candidate = temp_dir.join("mock");
        std::fs::write(&candidate, b"not exec").unwrap();
        let mut perms = std::fs::metadata(&candidate).unwrap().permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&candidate, perms).unwrap();

        let path_env: OsString = std::env::join_paths([temp_dir.clone()]).unwrap();
        let err = resolve_executable("mock", Some(path_env.as_os_str())).expect_err("nonexec");
        assert!(err.contains("not found in PATH") || err.contains("not executable"));

        let _ = std::fs::remove_file(&candidate);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
