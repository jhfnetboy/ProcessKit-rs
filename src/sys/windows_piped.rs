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

    let (stdin_child, stdin) = std::io::pipe()?;
    let (stdout, stdout_child) = std::io::pipe()?;
    let (stderr, stderr_child) = std::io::pipe()?;
    // Hold the shared spawn lock from the first inheritable-handle mutation
    // through closing those temporary child ends. Otherwise another ProcessKit
    // launch could race through CreateProcessW while they are marked inheritable.
    let spawn_guard = crate::sys::process_spawn_lock();

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
