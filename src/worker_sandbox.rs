use std::ffi::CString;
use std::fs::{self, File};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const READ_ACCESS: u64 = (1 << 0) | (1 << 2) | (1 << 3);
const WRITE_ACCESS: u64 =
    (1 << 1) | (1 << 4) | (1 << 5) | (1 << 7) | (1 << 8) | (1 << 13) | (1 << 14);
const CGROUP2_MAGIC: libc::c_long = 0x63677270;
const PROC_MAGIC: libc::c_long = 0x9fa0;
const SYSFS_MAGIC: libc::c_long = 0x62656572;
const AUDIT_ARCH_X86_64: u32 = 0xc000003e;

#[repr(C)]
struct RulesetAttribute {
    handled_access_fs: u64,
}

#[repr(C, packed)]
struct PathAttribute {
    allowed_access: u64,
    parent_fd: i32,
}

pub(crate) struct WorkerSandbox {
    ruleset: File,
    filter: Vec<libc::sock_filter>,
}

fn get_error() -> io::Error {
    io::Error::other("worker sandbox setup failed")
}

fn open_path(path: &Path) -> io::Result<File> {
    let name = CString::new(path.as_os_str().as_bytes()).map_err(|_| get_error())?;
    // SAFETY: name is NUL-terminated; O_PATH pins without opening device drivers.
    let fd = unsafe { libc::open(name.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the newly returned descriptor is transferred exactly once to File.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn add_rule(ruleset: &File, file: &File, access: u64) -> io::Result<()> {
    let metadata = file.metadata()?;
    let allowed_access = if metadata.is_dir() {
        access
    } else {
        access & ((1 << 0) | (1 << 1) | (1 << 2) | (1 << 14))
    };
    let attribute = PathAttribute {
        allowed_access,
        parent_fd: file.as_raw_fd(),
    };
    // SAFETY: both descriptors and the correctly sized packed attribute are live.
    if unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset.as_raw_fd(),
            1,
            &attribute,
            0,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn create_filter() -> Vec<libc::sock_filter> {
    fn statement(code: u32, value: u32) -> libc::sock_filter {
        libc::sock_filter {
            code: code as u16,
            jt: 0,
            jf: 0,
            k: value,
        }
    }
    fn jump(value: u32, yes: u8, no: u8) -> libc::sock_filter {
        libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt: yes,
            jf: no,
            k: value,
        }
    }
    let load = libc::BPF_LD | libc::BPF_W | libc::BPF_ABS;
    let ret = libc::BPF_RET | libc::BPF_K;
    let mut filter = vec![
        statement(load, 4),
        jump(AUDIT_ARCH_X86_64, 1, 0),
        statement(ret, libc::SECCOMP_RET_KILL_PROCESS),
        statement(load, 0),
        libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K) as u16,
            jt: 0,
            jf: 1,
            k: 0x40000000,
        },
        statement(ret, libc::SECCOMP_RET_KILL_PROCESS),
    ];
    for syscall in [
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_sendmsg,
        libc::SYS_recvmsg,
        libc::SYS_sendto,
        libc::SYS_recvfrom,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_pidfd_getfd,
        libc::SYS_pidfd_send_signal,
        libc::SYS_kill,
        libc::SYS_tkill,
        libc::SYS_tgkill,
        libc::SYS_rt_sigqueueinfo,
        libc::SYS_rt_tgsigqueueinfo,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_open_tree,
        libc::SYS_move_mount,
        libc::SYS_fsopen,
        libc::SYS_fsconfig,
        libc::SYS_fsmount,
        libc::SYS_mount_setattr,
        libc::SYS_open_by_handle_at,
        libc::SYS_io_uring_setup,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_userfaultfd,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_chmod,
        libc::SYS_fchmod,
        libc::SYS_fchmodat,
        libc::SYS_fchmodat2,
        libc::SYS_chown,
        libc::SYS_fchown,
        libc::SYS_lchown,
        libc::SYS_fchownat,
        libc::SYS_setxattr,
        libc::SYS_lsetxattr,
        libc::SYS_fsetxattr,
        libc::SYS_removexattr,
        libc::SYS_lremovexattr,
        libc::SYS_fremovexattr,
        libc::SYS_chroot,
        libc::SYS_pivot_root,
    ] {
        filter.push(jump(syscall as u32, 0, 1));
        filter.push(statement(ret, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32));
    }
    filter.push(jump(libc::SYS_clone3 as u32, 0, 1));
    filter.push(statement(
        ret,
        libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32,
    ));
    filter.push(jump(libc::SYS_clone as u32, 0, 3));
    filter.push(statement(load, 16));
    let namespace_flags = libc::CLONE_NEWNS
        | libc::CLONE_NEWCGROUP
        | libc::CLONE_NEWUTS
        | libc::CLONE_NEWIPC
        | libc::CLONE_NEWUSER
        | libc::CLONE_NEWPID
        | libc::CLONE_NEWNET
        | 0x80;
    filter.push(libc::sock_filter {
        code: (libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K) as u16,
        jt: 0,
        jf: 1,
        k: namespace_flags as u32,
    });
    filter.push(statement(ret, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32));
    filter.push(statement(ret, libc::SECCOMP_RET_ALLOW));
    filter
}

impl WorkerSandbox {
    pub(crate) fn prepare(
        executable: &Path,
        read_paths: &[PathBuf],
        write_paths: &[PathBuf],
    ) -> io::Result<Self> {
        if !cfg!(target_arch = "x86_64") || write_paths.len() > 8 || read_paths.len() > 8 {
            return Err(get_error());
        }
        // SAFETY: version query has no pointer arguments or retained memory.
        let abi = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<u8>(),
                0,
                1,
            )
        };
        if abi < 3 {
            return Err(get_error());
        }
        let handled_access_fs = ((1 << 15) - 1) | if abi >= 5 { 1 << 15 } else { 0 };
        let attribute = RulesetAttribute { handled_access_fs };
        // SAFETY: the attribute has the exact size supplied and remains live for the syscall.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                &attribute,
                size_of::<RulesetAttribute>(),
                0,
            )
        };
        if fd < 0 {
            return Err(get_error());
        }
        // SAFETY: the fresh ruleset descriptor is transferred exactly once to File.
        let ruleset = unsafe { File::from_raw_fd(fd as i32) };
        for path in [
            "/usr",
            "/lib",
            "/lib64",
            "/etc/ld.so.cache",
            "/etc/localtime",
            "/etc/nsswitch.conf",
            "/etc/passwd",
            "/etc/group",
            "/etc/machine-id",
            "/proc/sys/kernel/random/boot_id",
            "/dev/urandom",
            "/dev/random",
            "/sys/fs/cgroup",
        ] {
            if fs::symlink_metadata(path).is_ok() {
                add_rule(&ruleset, &open_path(Path::new(path))?, READ_ACCESS)?;
            }
        }
        add_rule(&ruleset, &open_path(executable)?, READ_ACCESS)?;
        for (path, access) in read_paths.iter().map(|path| (path, READ_ACCESS)).chain(
            write_paths
                .iter()
                .map(|path| (path, READ_ACCESS | WRITE_ACCESS)),
        ) {
            let canonical = fs::canonicalize(path)?;
            if canonical != *path {
                return Err(get_error());
            }
            let file = open_path(path)?;
            let metadata = file.metadata()?;
            // SAFETY: geteuid reads only the current process identity.
            if !metadata.is_dir()
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o7777 != 0o700
            {
                return Err(get_error());
            }
            let mut info = std::mem::MaybeUninit::<libc::statfs>::uninit();
            // SAFETY: file is live and info is writable statfs storage.
            if unsafe { libc::fstatfs(file.as_raw_fd(), info.as_mut_ptr()) } != 0 {
                return Err(get_error());
            }
            // SAFETY: successful fstatfs initialized info.
            if [CGROUP2_MAGIC, PROC_MAGIC, SYSFS_MAGIC]
                .contains(&unsafe { info.assume_init() }.f_type)
            {
                return Err(get_error());
            }
            add_rule(&ruleset, &file, access)?;
        }
        Ok(Self {
            ruleset,
            filter: create_filter(),
        })
    }

    /// Called after fork; this performs no allocation and retains no user pointers.
    pub(crate) unsafe fn apply(&self) -> io::Result<()> {
        // SAFETY: this literal is NUL-terminated and O_PATH does not invoke drivers.
        let proc_fd = unsafe { libc::open(c"/proc/self".as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if proc_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let attribute = PathAttribute {
            allowed_access: (1 << 2) | (1 << 3),
            parent_fd: proc_fd,
        };
        // SAFETY: both descriptors and the packed attribute are valid for these syscalls.
        let result = unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                self.ruleset.as_raw_fd(),
                1,
                &attribute,
                0,
            )
        };
        // SAFETY: proc_fd is the fresh descriptor opened above and no longer needed.
        unsafe {
            libc::close(proc_fd);
        }
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: NO_NEW_PRIVS was set before this call and ruleset is live.
        if unsafe {
            libc::syscall(
                libc::SYS_landlock_restrict_self,
                self.ruleset.as_raw_fd(),
                0,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let program = libc::sock_fprog {
            len: self.filter.len() as u16,
            filter: self.filter.as_ptr().cast_mut(),
        };
        // SAFETY: the kernel copies this complete filter while all storage is live.
        if unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}
