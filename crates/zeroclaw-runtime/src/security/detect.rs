//! Auto-detection of available security features

use super::docker::{DockerMount, DockerSandbox};
use crate::security::traits::Sandbox;
use std::sync::Arc;
use zeroclaw_config::schema::{SandboxBackend, SecurityConfig};

/// Mounts attached to container-isolating sandboxes. Backends that run the
/// tool in-process (Landlock, Firejail, Bubblewrap, Seatbelt, Noop) ignore
/// these — the agent already has host access in those configurations.
#[derive(Debug, Clone, Default)]
pub struct SandboxMounts {
    pub read_only: Vec<std::path::PathBuf>,
    pub read_write: Vec<std::path::PathBuf>,
}

impl SandboxMounts {
    fn docker_mounts(&self) -> Vec<DockerMount> {
        let mut out = Vec::with_capacity(self.read_only.len() + self.read_write.len());
        for p in &self.read_only {
            out.push(DockerMount {
                host_path: p.clone(),
                container_path: p.clone(),
                writable: false,
            });
        }
        for p in &self.read_write {
            out.push(DockerMount {
                host_path: p.clone(),
                container_path: p.clone(),
                writable: true,
            });
        }
        out
    }
}

fn apply_mounts(sandbox: DockerSandbox, mounts: &SandboxMounts) -> DockerSandbox {
    mounts
        .docker_mounts()
        .into_iter()
        .fold(sandbox, |s, m| s.with_mount(m))
}

/// Create a sandbox based on auto-detection or explicit config.
///
/// `mounts` is consulted only by backends that run the tool command in a
/// separate namespace/filesystem (currently Docker). Other backends either
/// already share the host filesystem with the agent or enforce isolation
/// at a different layer.
pub fn create_sandbox(config: &SecurityConfig, mounts: &SandboxMounts) -> Arc<dyn Sandbox> {
    let backend = &config.sandbox.backend;

    // If explicitly disabled, return noop
    if matches!(backend, SandboxBackend::None) || config.sandbox.enabled == Some(false) {
        return Arc::new(super::traits::NoopSandbox);
    }

    // If specific backend requested, try that
    match backend {
        SandboxBackend::Landlock => {
            #[cfg(feature = "sandbox-landlock")]
            {
                #[cfg(target_os = "linux")]
                {
                    if let Ok(sandbox) = super::landlock::LandlockSandbox::new() {
                        return Arc::new(sandbox);
                    }
                }
            }
            tracing::warn!(
                "Landlock requested but not available, falling back to application-layer"
            );
            Arc::new(super::traits::NoopSandbox)
        }
        SandboxBackend::Firejail => {
            #[cfg(target_os = "linux")]
            {
                if let Ok(sandbox) = super::firejail::FirejailSandbox::new() {
                    return Arc::new(sandbox);
                }
            }
            tracing::warn!(
                "Firejail requested but not available, falling back to application-layer"
            );
            Arc::new(super::traits::NoopSandbox)
        }
        SandboxBackend::Bubblewrap => {
            #[cfg(feature = "sandbox-bubblewrap")]
            {
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                {
                    if let Ok(sandbox) = super::bubblewrap::BubblewrapSandbox::new() {
                        return Arc::new(sandbox);
                    }
                }
            }
            tracing::warn!(
                "Bubblewrap requested but not available, falling back to application-layer"
            );
            Arc::new(super::traits::NoopSandbox)
        }
        SandboxBackend::Docker => {
            if let Ok(sandbox) = DockerSandbox::new() {
                return Arc::new(apply_mounts(sandbox, mounts));
            }
            tracing::warn!("Docker requested but not available, falling back to application-layer");
            Arc::new(super::traits::NoopSandbox)
        }
        SandboxBackend::SandboxExec => {
            #[cfg(target_os = "macos")]
            {
                if let Ok(sandbox) = super::seatbelt::SeatbeltSandbox::new() {
                    return Arc::new(sandbox);
                }
            }
            tracing::warn!(
                "sandbox-exec requested but not available, falling back to application-layer"
            );
            Arc::new(super::traits::NoopSandbox)
        }
        SandboxBackend::Auto | SandboxBackend::None => {
            // Auto-detect best available
            detect_best_sandbox(mounts)
        }
    }
}

/// Auto-detect the best available sandbox
fn detect_best_sandbox(mounts: &SandboxMounts) -> Arc<dyn Sandbox> {
    #[cfg(target_os = "linux")]
    {
        // Try Landlock first (native, no dependencies)
        #[cfg(feature = "sandbox-landlock")]
        {
            if let Ok(sandbox) = super::landlock::LandlockSandbox::probe() {
                tracing::info!("Landlock sandbox enabled (Linux kernel 5.13+)");
                return Arc::new(sandbox);
            }
        }

        // Try Firejail second (user-space tool)
        if let Ok(sandbox) = super::firejail::FirejailSandbox::probe() {
            tracing::info!("Firejail sandbox enabled");
            return Arc::new(sandbox);
        }
    }

    #[cfg(target_os = "macos")]
    {
        // Try Bubblewrap on macOS
        #[cfg(feature = "sandbox-bubblewrap")]
        {
            if let Ok(sandbox) = super::bubblewrap::BubblewrapSandbox::probe() {
                tracing::info!("Bubblewrap sandbox enabled");
                return Arc::new(sandbox);
            }
        }

        // Try sandbox-exec (Seatbelt) — built into macOS
        if let Ok(sandbox) = super::seatbelt::SeatbeltSandbox::probe() {
            tracing::info!("macOS sandbox-exec (Seatbelt) enabled");
            return Arc::new(sandbox);
        }
    }

    // Docker is heavy but works everywhere if docker is installed
    if let Ok(sandbox) = DockerSandbox::probe() {
        tracing::info!("Docker sandbox enabled");
        return Arc::new(apply_mounts(sandbox, mounts));
    }

    // Fallback: application-layer security only
    tracing::info!("No sandbox backend available, using application-layer security");
    Arc::new(super::traits::NoopSandbox)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroclaw_config::schema::SandboxConfig;

    #[test]
    fn detect_best_sandbox_returns_something() {
        let sandbox = detect_best_sandbox(&SandboxMounts::default());
        // Should always return at least NoopSandbox
        assert!(sandbox.is_available());
    }

    #[test]
    fn explicit_none_returns_noop() {
        let config = SecurityConfig {
            sandbox: SandboxConfig {
                enabled: Some(false),
                backend: SandboxBackend::None,
                firejail_args: Vec::new(),
            },
            ..Default::default()
        };
        let sandbox = create_sandbox(&config, &SandboxMounts::default());
        assert_eq!(sandbox.name(), "none");
    }

    #[test]
    fn auto_mode_detects_something() {
        let config = SecurityConfig {
            sandbox: SandboxConfig {
                enabled: None, // Auto-detect
                backend: SandboxBackend::Auto,
                firejail_args: Vec::new(),
            },
            ..Default::default()
        };
        let sandbox = create_sandbox(&config, &SandboxMounts::default());
        // Should return some sandbox (at least NoopSandbox)
        assert!(sandbox.is_available());
    }
}
