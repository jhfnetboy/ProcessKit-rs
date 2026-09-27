//! A deliberately narrow, synchronous-stdio child launch surface.

use std::ffi::OsStr;
use std::io::{self, PipeReader, PipeWriter};
use std::path::Path;
use std::process::ExitStatus;
#[cfg(unix)]
use std::process::Stdio;

use crate::{Command, Error, ProcessGroup, Result};

/// The parent ends of a child's stdin, stdout and stderr pipes.
#[derive(Debug)]
pub struct IsolatedPipes {
    /// Write here to send bytes to the child, then drop it to deliver EOF.
    pub stdin: PipeWriter,
    /// Read the child's standard output.
    pub stdout: PipeReader,
    /// Read the child's standard error.
    pub stderr: PipeReader,
}

/// A restricted command builder for [`ProcessGroup::spawn_isolated_piped`].
///
/// Unlike [`Command`], this type exposes only the command shape supported by
/// isolated pipes: an absolute executable, an explicit absolute working
/// directory when supplied, arguments, and environment operations.
#[derive(Debug)]
pub struct IsolatedPipedCommand {
    command: Command,
}

impl IsolatedPipedCommand {
    /// Start a command for an absolute executable path.
    #[must_use]
    pub fn new(program: impl AsRef<OsStr>) -> Self {
        Self {
            command: Command::new(program),
        }
    }

    /// Append one argument.
    #[must_use]
    pub fn arg(mut self, arg: impl AsRef<OsStr>) -> Self {
        self.command = self.command.arg(arg);
        self
    }

    /// Append several arguments.
    #[must_use]
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.command = self.command.args(args);
        self
    }

    /// Set an absolute working directory.
    #[must_use]
    pub fn current_dir(mut self, dir: impl AsRef<Path>) -> Self {
        self.command = self.command.current_dir(dir);
        self
    }

    /// Set one child environment variable.
    #[must_use]
    pub fn env(mut self, key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> Self {
        self.command = self.command.env(key, value);
        self
    }

    /// Set multiple child environment variables.
    #[must_use]
    pub fn envs<I, K, V>(mut self, vars: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        self.command = self.command.envs(vars);
        self
    }

    /// Remove one inherited environment variable.
    #[must_use]
    pub fn env_remove(mut self, key: impl AsRef<OsStr>) -> Self {
        self.command = self.command.env_remove(key);
        self
    }

    /// Clear inherited environment variables before applying explicit values.
    #[must_use]
    pub fn env_clear(mut self) -> Self {
        self.command = self.command.env_clear();
        self
    }

    fn validate(&self) -> Result<()> {
        let program = Path::new(self.command.program());
        let cwd = self.command.working_dir();
        if !program.is_absolute() || cwd.is_some_and(|path| !path.is_absolute()) {
            return Err(invalid(
                "the executable and any supplied working directory must be absolute",
            ));
        }
        let bad_nul = |value: &OsStr| value.as_encoded_bytes().contains(&0);
        if bad_nul(self.command.program())
            || self.command.arguments().iter().any(|arg| bad_nul(arg))
            || cwd.is_some_and(|path| bad_nul(path.as_os_str()))
        {
            return Err(invalid("isolated-pipe command fields cannot contain NUL"));
        }
        for (key, value) in self.command.env_overrides() {
            if key.is_empty() || key.as_encoded_bytes().contains(&b'=') || bad_nul(key) {
                return Err(invalid(
                    "environment keys must be non-empty and cannot contain '=' or NUL",
                ));
            }
            if value.as_deref().is_some_and(bad_nul) {
                return Err(invalid("environment values cannot contain NUL"));
            }
        }
        Ok(())
    }
}

/// A process and its containing group, with optional parent-side pipe handles.
pub struct IsolatedPipedChild {
    group: ProcessGroup,
    child: ChildHandle,
    pipes: Option<IsolatedPipes>,
}

impl std::fmt::Debug for IsolatedPipedChild {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IsolatedPipedChild")
            .field("id", &self.id())
            .field("pipes_available", &self.pipes.is_some())
            .finish_non_exhaustive()
    }
}

#[cfg(unix)]
type ChildHandle = tokio::process::Child;
#[cfg(windows)]
type ChildHandle = crate::sys::windows_piped::RawChild;

impl ProcessGroup {
    /// Spawn a narrowly configured child with three isolated pipes.
    ///
    /// The command must use an absolute executable path; any working directory
    /// it supplies must also be absolute. On Unix, call this synchronous method
    /// from an entered Tokio runtime. Pipe reads and writes are blocking. The
    /// returned group-owning child kills its process tree when dropped; dropping
    /// the pipes independently closes parent ends. The group is consumed even
    /// if validation or spawning fails.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorReason::Io`](crate::ErrorReason::Io) for invalid command
    /// fields or pre-spawn preparation failures, and
    /// [`ErrorReason::Spawn`](crate::ErrorReason::Spawn) if the platform launch,
    /// containment, or Windows native pipe setup fails.
    ///
    /// # Panics
    ///
    /// On Unix, Tokio panics if no runtime is entered when spawning.
    pub fn spawn_isolated_piped(self, command: IsolatedPipedCommand) -> Result<IsolatedPipedChild> {
        command.validate()?;
        let mut tokio_command = command.command.build_tokio()?;
        #[cfg(unix)]
        let (child, pipes) = {
            let (stdin_child, stdin) = std::io::pipe().map_err(Error::io)?;
            let (stdout, stdout_child) = std::io::pipe().map_err(Error::io)?;
            let (stderr, stderr_child) = std::io::pipe().map_err(Error::io)?;
            tokio_command
                .stdin(Stdio::from(stdin_child))
                .stdout(Stdio::from(stdout_child))
                .stderr(Stdio::from(stderr_child));
            let child =
                self.spawn_with_options(&mut tokio_command, &crate::sys::SpawnOptions::default())?;
            drop(tokio_command);
            (
                child,
                IsolatedPipes {
                    stdin,
                    stdout,
                    stderr,
                },
            )
        };
        #[cfg(windows)]
        let (child, pipes) = {
            let spawned = self.spawn_isolated_piped_raw(
                &mut tokio_command,
                command.command.resolved_windows_env(),
                &crate::sys::SpawnOptions::default(),
            )?;
            drop(tokio_command);
            (
                spawned.child,
                IsolatedPipes {
                    stdin: spawned.stdin,
                    stdout: spawned.stdout,
                    stderr: spawned.stderr,
                },
            )
        };
        Ok(IsolatedPipedChild {
            group: self,
            child,
            pipes: Some(pipes),
        })
    }
}

impl IsolatedPipedChild {
    /// The process identifier while the child handle is live.
    #[must_use]
    pub fn id(&self) -> Option<u32> {
        self.child.id()
    }

    /// Take the parent pipe handles. They are returned at most once.
    #[must_use]
    pub fn take_pipes(&mut self) -> Option<IsolatedPipes> {
        self.pipes.take()
    }

    /// Poll the direct child without blocking; exited status is collected where
    /// the platform requires explicit reaping.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorReason::Io`](crate::ErrorReason::Io) if the OS wait probe fails.
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>> {
        self.child.try_wait().map_err(Error::io)
    }

    /// Kill every process currently contained by the owned group.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorReason::Io`](crate::ErrorReason::Io) if tree termination fails.
    pub fn kill_all(&self) -> Result<()> {
        self.group.kill_all()
    }

    /// Whether the owned process tree currently has no live members.
    #[cfg(feature = "stats")]
    ///
    /// # Errors
    ///
    /// Returns [`ErrorReason::Io`](crate::ErrorReason::Io) if group statistics cannot be read.
    pub fn tree_is_empty(&self) -> Result<bool> {
        Ok(self.group.stats()?.active_process_count == 0)
    }
}

fn invalid(message: &'static str) -> Error {
    Error::io(io::Error::new(io::ErrorKind::InvalidInput, message))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_shape_and_nul_before_spawn() {
        let executable = std::env::current_exe().unwrap();
        assert!(IsolatedPipedCommand::new(&executable).validate().is_ok());
        assert!(
            IsolatedPipedCommand::new("relative")
                .current_dir(std::env::current_dir().unwrap())
                .validate()
                .is_err()
        );
        assert!(
            IsolatedPipedCommand::new(&executable)
                .current_dir(std::env::current_dir().unwrap())
                .arg("bad\0arg")
                .validate()
                .is_err()
        );
        assert!(
            IsolatedPipedCommand::new(&executable)
                .current_dir(std::env::current_dir().unwrap())
                .env("BAD=KEY", "value")
                .validate()
                .is_err()
        );
        assert!(
            IsolatedPipedCommand::new(&executable)
                .current_dir(std::env::current_dir().unwrap())
                .env("", "value")
                .validate()
                .is_err()
        );
        assert!(
            IsolatedPipedCommand::new(&executable)
                .current_dir(std::env::current_dir().unwrap())
                .env("KEY", "bad\0value")
                .validate()
                .is_err()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pipes_deliver_stdin_and_observe_eof() {
        let mut child = ProcessGroup::new()
            .unwrap()
            .spawn_isolated_piped(
                IsolatedPipedCommand::new("/bin/cat").current_dir(std::env::current_dir().unwrap()),
            )
            .unwrap();
        let mut pipes = child.take_pipes().unwrap();
        use std::io::{Read as _, Write as _};
        pipes.stdin.write_all(b"isolated").unwrap();
        drop(pipes.stdin);
        let mut output = Vec::new();
        pipes.stdout.read_to_end(&mut output).unwrap();
        assert_eq!(output, b"isolated");
        let mut error = Vec::new();
        pipes.stderr.read_to_end(&mut error).unwrap();
        assert!(error.is_empty());
        let status = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    break status;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(status.success());
    }
}
