//! Linux: what the system has available (`/proc/meminfo`), what the
//! control groups the program is in leave it (`/sys/fs/cgroup`), and what
//! `ulimit` leaves it (getrlimit, and `/proc/self/status`).

#![forbid(unsafe_code)]

use std::path::{Component, Path, PathBuf};

use rustix::process::{Resource, getrlimit};

use super::{Available, Bound, least};

/// The stack of a thread Rust starts, unless the program sets another.
const THREAD_STACK: u64 = 2 << 20;

/// The arena glibc's allocator reserves for a thread that allocates while
/// the others hold theirs: `HEAP_MAX_SIZE`, twice its largest mmap
/// threshold. Other C libraries (musl) keep no arena for each thread.
#[cfg(all(target_env = "gnu", target_pointer_width = "64"))]
const THREAD_ARENA: u64 = 64 << 20;
#[cfg(all(target_env = "gnu", not(target_pointer_width = "64")))]
const THREAD_ARENA: u64 = 1 << 20;
#[cfg(not(target_env = "gnu"))]
const THREAD_ARENA: u64 = 0;

pub(super) fn available() -> Option<Available> {
    let system = read("/proc/meminfo")
        .and_then(|meminfo| meminfo_available(&meminfo))
        .map(|bytes| (bytes, Bound::System));
    let group = read("/proc/self/cgroup")
        .and_then(|groups| control_groups_left(&groups, Path::new("/sys/fs/cgroup")))
        .map(|bytes| (bytes, Bound::ControlGroup));
    let ulimit = read("/proc/self/status")
        .and_then(|status| ulimit_left(&status, limit))
        .map(|bytes| (bytes, Bound::Ulimit));
    let (bytes, bound) = least([system, group, ulimit])?;
    Some(Available {
        bytes,
        bound,
        thread_overhead: thread_overhead(limit),
    })
}

fn read(path: impl AsRef<Path>) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// `ulimit`'s limit on a resource, `None` for none.
fn limit(resource: Resource) -> Option<u64> {
    getrlimit(resource).current
}

/// `MemAvailable`, in bytes: what the kernel counts as free, and as page
/// cache and other memory it can give back without swapping.
fn meminfo_available(meminfo: &str) -> Option<u64> {
    kib_field(meminfo, "MemAvailable:")
}

/// A field of `/proc/meminfo` or `/proc/self/status`, in kB, in bytes.
fn kib_field(text: &str, field: &str) -> Option<u64> {
    text.lines()
        .find_map(|line| line.strip_prefix(field))?
        .trim()
        .strip_suffix("kB")?
        .trim()
        .parse::<u64>()
        .ok()?
        .checked_mul(1024)
}

/// What the control groups the program is in leave it: the least, between
/// each group's limit and what it holds, from its own group up to the
/// root, in the hierarchy of version 2 under `root` and in version 1's
/// `memory` controller under `root/memory`. `groups` is
/// `/proc/self/cgroup`. `None` where no group has a limit.
///
/// What a group holds is its memory less its file pages that are not in
/// use (`inactive_file`), which the kernel drops before it would refuse
/// memory: the group's working set, as container runtimes count it.
fn control_groups_left(groups: &str, root: &Path) -> Option<u64> {
    let mut least: Option<u64> = None;
    for line in groups.lines() {
        // `id:controllers:path`; version 2's line is `0::path`.
        let mut fields = line.splitn(3, ':');
        let (Some(_), Some(controllers), Some(path)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let left = if controllers.is_empty() {
            walk_up(root, path, &V2)
        } else if controllers.split(',').any(|c| c == "memory") {
            walk_up(&root.join("memory"), path, &V1)
        } else {
            None
        };
        if let Some(left) = left {
            least = Some(least.map_or(left, |l| l.min(left)));
        }
    }
    least
}

/// The files of a version of control groups.
struct Files {
    limit: &'static str,
    usage: &'static str,
    inactive_file: &'static str,
}

const V2: Files = Files {
    limit: "memory.max",
    usage: "memory.current",
    inactive_file: "inactive_file",
};

/// Version 1's own and its subgroups' inactive file pages (`total_`), as
/// its usage counts them.
const V1: Files = Files {
    limit: "memory.limit_in_bytes",
    usage: "memory.usage_in_bytes",
    inactive_file: "total_inactive_file",
};

/// The least left of each group from `path` up to `root`, under `root`.
/// A group not found there is passed over: in a container, the path is
/// the host's, where only the container's groups are mounted, its own at
/// `root`.
fn walk_up(root: &Path, path: &str, files: &Files) -> Option<u64> {
    let path = Path::new(path);
    // A group outside the program's cgroup namespace (`/../..`): only the
    // root, the namespace's, can be read.
    let parts: Vec<&std::ffi::OsStr> = if path.components().any(|c| c == Component::ParentDir) {
        Vec::new()
    } else {
        path.components()
            .filter_map(|c| match c {
                Component::Normal(part) => Some(part),
                _ => None,
            })
            .collect()
    };
    let mut least: Option<u64> = None;
    for depth in (0..=parts.len()).rev() {
        let dir: PathBuf = root.join(parts[..depth].iter().collect::<PathBuf>());
        // `max`, version 2's no limit, is not a number.
        let Some(limit) = read_number(&dir.join(files.limit)) else {
            continue;
        };
        let usage = read_number(&dir.join(files.usage)).unwrap_or(0);
        let inactive = read(dir.join("memory.stat"))
            .and_then(|stat| stat_field(&stat, files.inactive_file))
            .unwrap_or(0);
        let left = limit.saturating_sub(usage.saturating_sub(inactive));
        least = Some(least.map_or(left, |l| l.min(left)));
    }
    least
}

fn read_number(path: &Path) -> Option<u64> {
    read(path)?.trim().parse().ok()
}

/// A field of `memory.stat`: `name value`, in bytes.
fn stat_field(stat: &str, name: &str) -> Option<u64> {
    stat.lines().find_map(|line| {
        let (key, value) = line.split_once(' ')?;
        (key == name).then(|| value.trim().parse().ok())?
    })
}

/// What `ulimit`'s limits on the address space and on the data leave the
/// program: each less what it holds of it now, its `VmSize` and `VmData`
/// in `status` (`/proc/self/status`). `None` where neither is set.
fn ulimit_left(status: &str, limit: impl Fn(Resource) -> Option<u64>) -> Option<u64> {
    let mut least: Option<u64> = None;
    for (resource, field) in [(Resource::As, "VmSize:"), (Resource::Data, "VmData:")] {
        if let Some(limit) = limit(resource) {
            let left = limit.saturating_sub(kib_field(status, field).unwrap_or(0));
            least = Some(least.map_or(left, |l| l.min(left)));
        }
    }
    least
}

/// What each thread takes of `ulimit`'s limits besides what it allocates:
/// under the address space's, its stack and its arena; under the data's,
/// which counts what is mapped to be written, its stack (an arena is
/// reserved without access, and counts as it is used).
fn thread_overhead(limit: impl Fn(Resource) -> Option<u64>) -> u64 {
    if limit(Resource::As).is_some() {
        THREAD_STACK + THREAD_ARENA
    } else if limit(Resource::Data).is_some() {
        THREAD_STACK
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1 << 20;

    /// A tree of control groups in a folder of its own, removed after.
    struct Tree(PathBuf);

    impl Tree {
        fn new(name: &str) -> Tree {
            let dir =
                std::env::temp_dir().join(format!("hivepack-cgroup-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Tree(dir)
        }

        fn write(&self, path: &str, text: &str) {
            let file = self.0.join(path);
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(file, text).unwrap();
        }

        /// A version 2 group at `dir`, `max` bytes or `"max"`.
        fn group(&self, dir: &str, max: &str, current: u64, inactive_file: u64) {
            let dir = if dir.is_empty() {
                String::new()
            } else {
                format!("{dir}/")
            };
            self.write(&format!("{dir}memory.max"), &format!("{max}\n"));
            self.write(&format!("{dir}memory.current"), &format!("{current}\n"));
            self.write(
                &format!("{dir}memory.stat"),
                &format!("anon 1000\nfile 2000\nactive_file 30\ninactive_file {inactive_file}\n"),
            );
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn meminfo() {
        let meminfo = "MemTotal:       32562316 kB\nMemFree:         1236608 kB\n\
                       MemAvailable:   20000000 kB\nBuffers:          500000 kB\n";
        assert_eq!(meminfo_available(meminfo), Some(20_000_000 * 1024));
        assert_eq!(meminfo_available("MemTotal: 10 kB\n"), None);
        assert_eq!(meminfo_available("MemAvailable: lots kB\n"), None);
    }

    #[test]
    fn the_least_of_the_groups_from_its_own_up() {
        // systemd: a scope with MemoryMax=600M, in a slice of 2 GiB, in
        // one without a limit. The root has no memory.max.
        let tree = Tree::new("v2");
        let scope = "user.slice/user-1000.slice/user@1000.service/app.slice/run-1.scope";
        tree.group("user.slice", "max", 5000 * MIB, 0);
        tree.group(
            "user.slice/user-1000.slice",
            &(2048 * MIB).to_string(),
            1000 * MIB,
            0,
        );
        tree.group(scope, &(600 * MIB).to_string(), 200 * MIB, 50 * MIB);
        let groups = format!("0::/{scope}\n");
        // 600 less (200 less 50 not in use).
        assert_eq!(control_groups_left(&groups, &tree.0), Some(450 * MIB));
        // The slice's limit is the least once its other groups hold more.
        tree.group(
            "user.slice/user-1000.slice",
            &(2048 * MIB).to_string(),
            1800 * MIB,
            0,
        );
        assert_eq!(control_groups_left(&groups, &tree.0), Some(248 * MIB));
        // A group above, without a limit, alone: none.
        assert_eq!(control_groups_left("0::/user.slice\n", &tree.0), None);
        // A group not there (a container's path, of the host): the
        // groups above it, the root among them.
        tree.group("", &(4096 * MIB).to_string(), 96 * MIB, 0);
        assert_eq!(
            control_groups_left("0::/docker/0123abcd\n", &tree.0),
            Some(4000 * MIB)
        );
        // In a container's namespace: `0::/`, the root.
        assert_eq!(control_groups_left("0::/\n", &tree.0), Some(4000 * MIB));
        // Outside the namespace: the root alone.
        assert_eq!(
            control_groups_left(&format!("0::/../../{scope}\n"), &tree.0),
            Some(4000 * MIB)
        );
        // Usage past the limit leaves nothing.
        tree.group("user.slice", &(10 * MIB).to_string(), 20 * MIB, 0);
        assert_eq!(control_groups_left("0::/user.slice\n", &tree.0), Some(0));
    }

    #[test]
    fn version_1s_memory_controller() {
        let tree = Tree::new("v1");
        tree.write("memory/docker/abc/memory.limit_in_bytes", "1073741824\n");
        tree.write("memory/docker/abc/memory.usage_in_bytes", "536870912\n");
        tree.write(
            "memory/docker/abc/memory.stat",
            "cache 100\ninactive_file 1\ntotal_inactive_file 104857600\n",
        );
        // The root's limit when none is set: the most the kernel counts.
        tree.write("memory/memory.limit_in_bytes", "9223372036854771712\n");
        tree.write("memory/memory.usage_in_bytes", "8000000000\n");
        let groups = "12:cpu,cpuacct:/docker/abc\n11:memory:/docker/abc\n0::/docker/abc\n";
        assert_eq!(control_groups_left(groups, &tree.0), Some(612 * MIB));
        // Controllers named together.
        let groups = "11:memory,hugetlb:/docker/abc\n";
        assert_eq!(control_groups_left(groups, &tree.0), Some(612 * MIB));
        // Without the memory controller: none.
        assert_eq!(control_groups_left("12:cpu:/docker/abc\n", &tree.0), None);
        assert_eq!(control_groups_left("", &tree.0), None);
        assert_eq!(control_groups_left("garbage\n", &tree.0), None);
    }

    #[test]
    fn ulimit_less_what_is_held() {
        let status = "Name:\ttest\nVmPeak:\t  300000 kB\nVmSize:\t  204800 kB\n\
                      VmData:\t  102400 kB\nVmRSS:\t   10000 kB\n";
        let none = |_| None;
        assert_eq!(ulimit_left(status, none), None);
        assert_eq!(thread_overhead(none), 0);
        let address_space = |r| (r == Resource::As).then_some(1024 * MIB);
        assert_eq!(ulimit_left(status, address_space), Some(824 * MIB));
        assert_eq!(thread_overhead(address_space), THREAD_STACK + THREAD_ARENA);
        let data = |r| (r == Resource::Data).then_some(1024 * MIB);
        assert_eq!(ulimit_left(status, data), Some(924 * MIB));
        assert_eq!(thread_overhead(data), THREAD_STACK);
        let both = |r| {
            Some(if r == Resource::As {
                900 * MIB
            } else {
                950 * MIB
            })
        };
        assert_eq!(ulimit_left(status, both), Some(700 * MIB));
        // A limit below what is held leaves nothing.
        assert_eq!(ulimit_left(status, |_| Some(MIB)), Some(0));
    }

    #[test]
    fn what_this_system_says() {
        let meminfo = read("/proc/meminfo").unwrap();
        let total = kib_field(&meminfo, "MemTotal:").unwrap();
        let available = available().unwrap();
        assert!(
            available.bytes > 0 && available.bytes <= total,
            "{available:?}"
        );
    }
}
