//! Windows raw spawn with an explicit inherited-handle list and three pipes.

use std::io::{self, PipeReader, PipeWriter};
use std::mem::{size_of, size_of_val};
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::process::ExitStatus;

use windows_sys::Win32::Foundation::{
    CloseHandle, HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NEW_PROCESS_GROUP, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
    DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, INFINITE,
    InitializeProcThreadAttributeList, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION,
    STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute,
    WaitForSingleObject,
};

use crate::sys::{SpawnOptions, windows_spawn};

/// The contained raw child and the parent's ends of its three standard pipes.
pub(crate) struct PipedSpawn {
    pub(crate) child: RawChild,
    pub(crate) stdin: PipeWriter,
    pub(crate) stdout: PipeReader,
    pub(crate) stderr: PipeReader,
}

/// An owned process handle with the bounded lifecycle operations needed by the
/// runner. The Job Object remains the authority for whole-tree teardown.
pub(crate) struct RawChild {
    process: OwnedProcess,
    pid: u32,
}

// SAFETY: this uniquely owned process handle is used only with thread-safe
// process-handle APIs and is closed exactly once by `OwnedProcess::drop`.
unsafe impl Send for RawChild {}

impl RawChild {
    /// The child pid, matching `tokio::process::Child::id`.
    #[allow(dead_code)]
    pub(crate) fn id(&self) -> Option<u32> {
        Some(self.pid)
    }

    /// Poll for exit without blocking; the zero-time wait distinguishes a real
    /// exit code of `STILL_ACTIVE` from a process that is still running.
    #[allow(dead_code)]
    pub(crate) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        // SAFETY: `process` owns a valid process handle; timeout zero is a poll.
        match unsafe { WaitForSingleObject(self.process.0, 0) } {
            WAIT_OBJECT_0 => {}
            WAIT_TIMEOUT => return Ok(None),
            _ => return Err(io::Error::last_os_error()),
        }
        let mut code = 0;
        // SAFETY: valid process handle and writable exit-code out parameter.
        if unsafe { GetExitCodeProcess(self.process.0, &mut code) } == 0 {
            return Err(io::Error::last_os_error());
        }
        use std::os::windows::process::ExitStatusExt;
        Ok(Some(ExitStatus::from_raw(code)))
    }
}

/// Create a Windows child with three private stdio pipes, then contain it before
/// its primary thread can run. `cmd` must be the prepared capture-piped shape;
/// selecting that shape remains the runner's responsibility because `Stdio`
/// does not expose its configured mode for inspection.
pub(crate) fn spawn(
    cmd: &mut tokio::process::Command,
    env: Option<Vec<(std::ffi::OsString, std::ffi::OsString)>>,
    opts: &SpawnOptions,
    job: &crate::sys::imp::Job,
) -> io::Result<PipedSpawn> {
    if opts.use_pty || opts.pty_size.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "isolated-pipe spawn cannot be used for a PTY command",
        ));
    }
    let program = cmd.as_std().get_program();
    if Path::new(program)
        .extension()
        .and_then(std::ffi::OsStr::to_str)
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case("bat") || extension.eq_ignore_ascii_case("cmd")
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "raw Windows spawn does not invoke batch files through cmd.exe",
        ));
    }

    // Acquire before declaring any pipe owners: on every early return or unwind,
    // those later-declared inheritable handles are dropped before this guard.
    // Keep the shared lock until their temporary child ends have been closed so
    // no concurrent ProcessKit launch can inherit them accidentally.
    let spawn_guard = crate::sys::process_spawn_lock();
    let (stdin_child, stdin) = std::io::pipe()?;
    let (stdout, stdout_child) = std::io::pipe()?;
    let (stderr, stderr_child) = std::io::pipe()?;

    // std::io::pipe creates non-inheritable handles. Explicitly clear the three
    // parent ends and mark only the child ends so the handle-list contract is
    // true even if the std implementation's defaults ever change.
    set_inheritable(stdin.as_raw_handle() as HANDLE, false)?;
    set_inheritable(stdout.as_raw_handle() as HANDLE, false)?;
    set_inheritable(stderr.as_raw_handle() as HANDLE, false)?;
    set_inheritable(stdin_child.as_raw_handle() as HANDLE, true)?;
    set_inheritable(stdout_child.as_raw_handle() as HANDLE, true)?;
    set_inheritable(stderr_child.as_raw_handle() as HANDLE, true)?;

    let mut inherited = [
        stdin_child.as_raw_handle() as HANDLE,
        stdout_child.as_raw_handle() as HANDLE,
        stderr_child.as_raw_handle() as HANDLE,
    ];
    let attributes = AttributeList::new()?;
    // SAFETY: the initialized list lives through CreateProcessW; `inherited` is
    // an array of exactly three valid, inheritable handles and the API copies it.
    if unsafe {
        UpdateProcThreadAttribute(
            attributes.as_ptr(),
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            inherited.as_mut_ptr().cast(),
            size_of_val(&inherited),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }

    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = inherited[0];
    startup.StartupInfo.hStdOutput = inherited[1];
    startup.StartupInfo.hStdError = inherited[2];
    startup.lpAttributeList = attributes.as_ptr();

    let mut command_line = windows_spawn::build_command_line(cmd);
    let env_block = windows_spawn::build_env_block(env);
    let cwd = cmd
        .as_std()
        .get_current_dir()
        .map(|path| windows_spawn::to_wide_nul(path.as_os_str()));
    let mut flags = CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | opts.creation_flags;
    if opts.windows_new_process_group {
        flags |= CREATE_NEW_PROCESS_GROUP;
    }
    let (env_ptr, env_flag) = match &env_block {
        Some(block) => (block.as_ptr().cast(), CREATE_UNICODE_ENVIRONMENT),
        None => (std::ptr::null(), 0),
    };
    flags |= env_flag;
    let cwd_ptr = cwd.as_ref().map_or(std::ptr::null(), |wide| wide.as_ptr());

    let mut information = PROCESS_INFORMATION::default();
    // SAFETY: command line is mutable and NUL-terminated; environment and
    // current-directory buffers outlive the call; STARTUPINFOEXW and its
    // attribute list are initialized; inherited handles are an exact list.
    let created = unsafe {
        CreateProcessW(
            std::ptr::null(),
            command_line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            flags,
            env_ptr,
            cwd_ptr,
            std::ptr::from_ref(&startup.StartupInfo),
            &mut information,
        )
    };
    let create_error = (created == 0).then(io::Error::last_os_error);
    drop(attributes);
    // CreateProcessW duplicated the listed handles into the child; close the
    // parent's temporary copies before any later spawn can inherit them.
    drop((stdin_child, stdout_child, stderr_child));
    drop(spawn_guard);
    if let Some(error) = create_error {
        return Err(error);
    }

    let rollback = SpawnRollback::new(information.hProcess, information.hThread);
    #[cfg(test)]
    observe_post_create(rollback.process_handle(), rollback.thread_handle());
    let pid = information.dwProcessId;
    job.contain_raw_child(
        rollback.process_handle(),
        rollback.thread_handle(),
        pid,
        opts,
    )?;
    let child = rollback.commit(pid);
    Ok(PipedSpawn {
        child,
        stdin,
        stdout,
        stderr,
    })
}

fn set_inheritable(handle: HANDLE, inheritable: bool) -> io::Result<()> {
    let flags = if inheritable { HANDLE_FLAG_INHERIT } else { 0 };
    // SAFETY: callers pass one of the still-owned pipe handles.
    if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, flags) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

struct AttributeList {
    storage: Vec<usize>,
}

impl AttributeList {
    fn new() -> io::Result<Self> {
        let mut bytes = 0;
        // SAFETY: documented size probe; null list obtains the required size.
        unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut bytes) };
        if bytes == 0 {
            return Err(io::Error::last_os_error());
        }
        let words = bytes.div_ceil(size_of::<usize>());
        let mut storage = vec![0usize; words];
        // SAFETY: Vec<usize> supplies adequate alignment and at least the
        // requested byte size for one process-thread attribute.
        if unsafe {
            InitializeProcThreadAttributeList(storage.as_mut_ptr().cast(), 1, 0, &mut bytes)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { storage })
    }

    fn as_ptr(&self) -> windows_sys::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST {
        self.storage.as_ptr().cast_mut().cast()
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        // SAFETY: successful construction initialized this list exactly once.
        unsafe { DeleteProcThreadAttributeList(self.as_ptr()) };
    }
}

struct OwnedProcess(HANDLE);

// SAFETY: owned process handles support the wait/query operations used here on
// any thread; the wrapper remains the single close authority.
unsafe impl Send for OwnedProcess {}
unsafe impl Sync for OwnedProcess {}

impl Drop for OwnedProcess {
    fn drop(&mut self) {
        // SAFETY: this wrapper uniquely owns the live process handle.
        unsafe { CloseHandle(self.0) };
    }
}

struct SpawnRollback {
    process: Option<OwnedProcess>,
    thread: Option<OwnedThread>,
}

impl SpawnRollback {
    fn new(process: HANDLE, thread: HANDLE) -> Self {
        Self {
            process: Some(OwnedProcess(process)),
            thread: Some(OwnedThread(thread)),
        }
    }

    fn process_handle(&self) -> HANDLE {
        self.process.as_ref().expect("rollback owns process").0
    }

    fn thread_handle(&self) -> HANDLE {
        self.thread.as_ref().expect("rollback owns thread").0
    }

    fn commit(mut self, pid: u32) -> RawChild {
        drop(self.thread.take());
        RawChild {
            process: self.process.take().expect("rollback owns process"),
            pid,
        }
    }
}

impl Drop for SpawnRollback {
    fn drop(&mut self) {
        let Some(process) = &self.process else {
            return;
        };
        // SAFETY: rollback exclusively owns the freshly-created process handle.
        unsafe { TerminateProcess(process.0, 1) };
        // Termination is asynchronous; wait before closing the process handle so
        // no suspended child survives an error return or unwind.
        // SAFETY: same owned process handle; INFINITE completes rollback.
        unsafe { WaitForSingleObject(process.0, INFINITE) };
    }
}

struct OwnedThread(HANDLE);

impl Drop for OwnedThread {
    fn drop(&mut self) {
        // SAFETY: this wrapper uniquely owns the CreateProcessW thread handle.
        unsafe { CloseHandle(self.0) };
    }
}

#[cfg(test)]
type PostCreateObserver = Box<dyn FnMut(HANDLE, HANDLE)>;

#[cfg(test)]
thread_local! {
    static POST_CREATE_OBSERVER: std::cell::RefCell<Option<PostCreateObserver>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn observe_post_create(process: HANDLE, thread: HANDLE) {
    POST_CREATE_OBSERVER.with(|observer| {
        if let Some(observer) = observer.borrow_mut().as_mut() {
            observer(process, thread);
        }
    });
}

#[cfg(test)]
fn with_post_create_observer<R>(
    observer: impl FnMut(HANDLE, HANDLE) + 'static,
    run: impl FnOnce() -> R,
) -> R {
    let previous = POST_CREATE_OBSERVER
        .with(|slot| slot.replace(Some(Box::new(observer) as PostCreateObserver)));
    struct Restore(Option<PostCreateObserver>);
    impl Drop for Restore {
        fn drop(&mut self) {
            POST_CREATE_OBSERVER.with(|slot| {
                slot.replace(self.0.take());
            });
        }
    }
    let _restore = Restore(previous);
    run()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::io::{Read as _, Write as _};
    use std::os::windows::io::AsRawHandle;
    use std::rc::Rc;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::{
        DUPLICATE_SAME_ACCESS, DuplicateHandle, GetHandleInformation, HANDLE_FLAG_INHERIT,
        WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::System::Threading::{
        CreateEventW, GetCurrentProcess, SetEvent, WaitForSingleObject,
    };

    const MODE: &str = "PROCESSKIT_ISOLATED_PIPE_TEST_MODE";
    const SENTINEL: &str = "PROCESSKIT_ISOLATED_PIPE_SENTINEL";
    const MARKER: &str = "PROCESSKIT_ISOLATED_PIPE_MARKER";
    const DESCENDANT_PID: &str = "PROCESSKIT_ISOLATED_PIPE_DESCENDANT_PID";
    const HELPER: &str = "sys::windows_piped::tests::helper_child";

    fn helper(mode: &str) -> crate::IsolatedPipedCommand {
        crate::IsolatedPipedCommand::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(HELPER)
            .arg("--nocapture")
            .current_dir(std::env::current_dir().unwrap())
            .env(MODE, mode)
    }

    fn wait_for_exit(child: &mut crate::IsolatedPipedChild) -> std::process::ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < deadline, "helper did not exit in time");
            std::thread::yield_now();
        }
    }

    struct Event(HANDLE);
    impl Drop for Event {
        fn drop(&mut self) {
            // SAFETY: this test wrapper uniquely owns the event handle.
            unsafe { CloseHandle(self.0) };
        }
    }

    #[test]
    #[ignore = "native Windows handle inheritance and isolated-pipe integration"]
    fn handle_list_isolates_sentinel_and_pipes_deliver_eof_and_separate_streams() {
        let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        assert!(!event.is_null());
        let event = Event(event);
        assert_ne!(
            unsafe { SetHandleInformation(event.0, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) },
            0
        );
        let mut child = crate::ProcessGroup::new()
            .unwrap()
            .spawn_isolated_piped(helper("pipes").env(SENTINEL, (event.0 as usize).to_string()))
            .unwrap();
        let mut pipes = child.take_pipes().unwrap();
        for handle in [
            pipes.stdin.as_raw_handle(),
            pipes.stdout.as_raw_handle(),
            pipes.stderr.as_raw_handle(),
        ] {
            let mut flags = 0;
            assert_ne!(
                unsafe { GetHandleInformation(handle as HANDLE, &mut flags) },
                0
            );
            assert_eq!(flags & HANDLE_FLAG_INHERIT, 0);
        }
        pipes.stdin.write_all(b"pipe-payload").unwrap();
        drop(pipes.stdin);
        let (stdout_tx, stdout_rx) = std::sync::mpsc::channel();
        let (stderr_tx, stderr_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut output = Vec::new();
            stdout_tx
                .send(pipes.stdout.read_to_end(&mut output).map(|_| output))
                .unwrap();
        });
        std::thread::spawn(move || {
            let mut output = Vec::new();
            stderr_tx
                .send(pipes.stderr.read_to_end(&mut output).map(|_| output))
                .unwrap();
        });
        let stdout = stdout_rx
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .unwrap();
        let stderr = stderr_rx
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .unwrap();
        assert!(String::from_utf8_lossy(&stdout).contains("pipe-payload"));
        assert!(String::from_utf8_lossy(&stdout).contains("sentinel-probed"));
        assert!(String::from_utf8_lossy(&stdout).contains("stdout-distinct"));
        assert!(String::from_utf8_lossy(&stderr).contains("stderr-distinct"));
        assert_eq!(unsafe { WaitForSingleObject(event.0, 0) }, WAIT_TIMEOUT);
        assert!(wait_for_exit(&mut child).success());
    }

    struct ObservedHandles {
        process: HANDLE,
        thread: HANDLE,
    }
    impl Drop for ObservedHandles {
        fn drop(&mut self) {
            // SAFETY: each handle was duplicated for and is uniquely owned here.
            unsafe {
                CloseHandle(self.process);
                CloseHandle(self.thread);
            }
        }
    }

    fn duplicate(handle: HANDLE) -> HANDLE {
        let mut duplicate = std::ptr::null_mut();
        // SAFETY: source is live during the observer call; both process handles
        // are this process, and `duplicate` is a valid out parameter.
        assert_ne!(
            unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    handle,
                    GetCurrentProcess(),
                    &mut duplicate,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            },
            0
        );
        duplicate
    }

    fn assert_rollback(target: &'static str) {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("must-not-execute");
        let observed = Rc::new(RefCell::new(None));
        let capture = Rc::clone(&observed);
        let faults = crate::sys::fault_injection::Faults::new()
            .fail_every(
                crate::sys::fault_injection::Site::RawChildContainment,
                Some(target),
                5,
            )
            .arm();
        let result = with_post_create_observer(
            move |process, thread| {
                *capture.borrow_mut() = Some(ObservedHandles {
                    process: duplicate(process),
                    thread: duplicate(thread),
                });
            },
            || {
                crate::ProcessGroup::new()
                    .unwrap()
                    .spawn_isolated_piped(helper("marker").env(MARKER, marker.as_os_str()))
            },
        );
        assert!(result.is_err());
        assert_eq!(
            faults.fired(crate::sys::fault_injection::Site::RawChildContainment),
            1
        );
        assert_eq!(
            faults.matched(crate::sys::fault_injection::Site::RawChildContainment),
            1
        );
        drop(faults);
        let observed = observed
            .borrow_mut()
            .take()
            .expect("post-create observer ran");
        assert_eq!(
            unsafe { WaitForSingleObject(observed.process, 5_000) },
            WAIT_OBJECT_0,
            "rollback left process alive after {target} failure"
        );
        assert_eq!(
            unsafe { WaitForSingleObject(observed.thread, 5_000) },
            WAIT_OBJECT_0,
            "rollback left primary thread alive after {target} failure"
        );
        assert!(
            !marker.exists(),
            "suspended child executed after {target} failure"
        );
    }

    #[test]
    #[ignore = "native Windows CreateProcess rollback integration"]
    fn assignment_failure_terminates_and_reaps_suspended_child() {
        assert_rollback("assign");
    }

    #[test]
    #[ignore = "native Windows CreateProcess rollback integration"]
    fn resume_failure_terminates_and_reaps_suspended_child() {
        assert_rollback("resume");
    }

    #[cfg(feature = "stats")]
    #[test]
    #[ignore = "native Windows Job Object descendant cleanup integration"]
    fn root_exit_leaves_descendant_contained_until_public_kill() {
        let mut child = crate::ProcessGroup::new()
            .unwrap()
            .spawn_isolated_piped(helper("descendant-root"))
            .unwrap();
        assert!(wait_for_exit(&mut child).success());
        assert!(!child.tree_is_empty().unwrap());
        child.kill_all().unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !child.tree_is_empty().unwrap() {
            assert!(Instant::now() < deadline, "Job Object tree did not empty");
            std::thread::yield_now();
        }
    }

    #[test]
    #[ignore = "native Windows Job Object drop cleanup integration"]
    fn dropping_owner_terminates_descendant_after_root_exit() {
        let directory = tempfile::tempdir().unwrap();
        let pid_path = directory.path().join("descendant-pid");
        let mut child = crate::ProcessGroup::new()
            .unwrap()
            .spawn_isolated_piped(helper("descendant-root").env(DESCENDANT_PID, &pid_path))
            .unwrap();
        assert!(wait_for_exit(&mut child).success());
        let pid = std::fs::read_to_string(pid_path).unwrap().parse().unwrap();
        // SAFETY: opens a stable wait handle for the helper's recorded pid.
        let process = unsafe {
            windows_sys::Win32::System::Threading::OpenProcess(
                windows_sys::Win32::System::Threading::PROCESS_SYNCHRONIZE,
                0,
                pid,
            )
        };
        assert!(!process.is_null(), "could not open descendant for wait");
        assert_eq!(
            unsafe { WaitForSingleObject(process, 0) },
            WAIT_TIMEOUT,
            "descendant exited before owner drop"
        );
        drop(child);
        assert_eq!(
            unsafe { WaitForSingleObject(process, 5_000) },
            WAIT_OBJECT_0
        );
        unsafe { CloseHandle(process) };
    }

    #[test]
    #[allow(clippy::zombie_processes)] // descendants must outlive this helper process
    fn helper_child() {
        let Ok(mode) = std::env::var(MODE) else {
            return;
        };
        match mode.as_str() {
            "pipes" => {
                let mut input = Vec::new();
                std::io::stdin().read_to_end(&mut input).unwrap();
                let sentinel = std::env::var(SENTINEL).unwrap().parse::<usize>().unwrap() as HANDLE;
                let _ = unsafe { SetEvent(sentinel) };
                std::io::stdout()
                    .write_all(
                        format!(
                            "stdout-distinct:{}:sentinel-probed",
                            String::from_utf8_lossy(&input)
                        )
                        .as_bytes(),
                    )
                    .unwrap();
                std::io::stderr().write_all(b"stderr-distinct").unwrap();
            }
            "marker" => {
                std::fs::write(std::env::var_os(MARKER).unwrap(), b"ran").unwrap();
            }
            "descendant-root" => {
                let child = std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", HELPER, "--nocapture"])
                    .env(MODE, "descendant-worker")
                    .spawn()
                    .unwrap();
                if let Some(path) = std::env::var_os(DESCENDANT_PID) {
                    std::fs::write(path, child.id().to_string()).unwrap();
                }
            }
            "descendant-worker" => loop {
                std::thread::sleep(Duration::from_secs(60));
            },
            _ => panic!("unexpected helper mode {mode}"),
        }
    }
}
