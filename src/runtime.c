/* runtime.c — real container execution.
 *
 * Everything here is a direct kernel syscall. No external runtime.
 *
 * Parent                              Child (clone)
 * ------                              -------------
 * clone(NEWUSER|NEWNS|NEWPID|         wait for uid/gid maps
 *   NEWUTS|NEWIPC|NEWNET|SIGCHLD)     MS_PRIVATE /
 * write uid_map/gid_map   ───────►    bind rootfs, pivot_root
 * optional cgroup v2 limits           fresh /proc, minimal /dev
 * forward signals, waitpid            hostname, rlimits, drop caps
 *                                     exec entrypoint
 */
#define _GNU_SOURCE
#include "synthctl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <linux/capability.h>
#include <sys/syscall.h>
#include <sys/mman.h>

#ifndef CLONE_NEWTIME
#define CLONE_NEWTIME 0x00000080
#endif

static int pivot_root(const char *new_root, const char *put_old)
{ return (int)syscall(SYS_pivot_root, new_root, put_old); }

struct child_ctx {
    const struct run_options *opt;
    int sync_fd;   /* parent writes one byte after uid/gid maps are set */
};

static void child_fail(const char *what)
{
    fprintf(stderr, "synthctl(container): %s: %s\n", what, strerror(errno));
    _exit(127);
}

/* bind a host device node into the container /dev; fall back to mknod */
static void dev_node(const char *host, const char *cont, mode_t mode, int maj, int min)
{
    int fd = open(cont, O_WRONLY | O_CREAT, 0644);
    if (fd >= 0) close(fd);
    if (mount(host, cont, NULL, MS_BIND, NULL) == 0) return;
    unlink(cont);
    if (mknod(cont, S_IFCHR | mode, (dev_t)((maj << 8) | min)) != 0)
        fprintf(stderr, "synthctl(container): warning: cannot create %s: %s\n",
                cont, strerror(errno));
}

static int child_main(void *arg)
{
    struct child_ctx *ctx = arg;
    const struct run_options *opt = ctx->opt;
    const struct manifest *m = opt->m;

    /* wait for parent to write uid/gid maps */
    char b;
    if (read(ctx->sync_fd, &b, 1) != 1) child_fail("sync read");
    close(ctx->sync_fd);

    /* 1. make all mounts private — nothing leaks back to the host */
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)) child_fail("MS_PRIVATE /");

    /* 2. prepare old-root slot and bind-mount the image rootfs onto itself */
    char oldroot[4096];
    snprintf(oldroot, sizeof oldroot, "%s/.synth_oldroot", opt->rootfs);
    mkdir(oldroot, 0755);
    if (mount(opt->rootfs, opt->rootfs, NULL, MS_BIND | MS_REC, NULL))
        child_fail("bind rootfs");
    if (opt->read_only_root)
        if (mount(NULL, opt->rootfs, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL))
            child_fail("remount ro");

    /* 3. pivot_root — the syscall that actually swaps the filesystem view */
    if (chdir(opt->rootfs)) child_fail("chdir rootfs");
    if (pivot_root(".", ".synth_oldroot")) child_fail("pivot_root");
    if (chdir("/")) child_fail("chdir /");
    if (umount2("/.synth_oldroot", MNT_DETACH)) child_fail("umount oldroot");
    rmdir("/.synth_oldroot");

    /* 4. fresh /proc (shows only container PIDs), minimal /dev, writable /tmp.
     *    Some hardened host kernels (and nested containers) refuse proc
     *    mounts from user namespaces via LSM policy. PID isolation does NOT
     *    depend on /proc — the pid namespace is the enforcement — so we
     *    degrade gracefully instead of faking it. */
    mkdir("/proc", 0555);
    if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL))
        fprintf(stderr, "synthctl(container): note: /proc mount blocked by host "
                        "policy (%s); pid namespace isolation unaffected\n",
                strerror(errno));
    mkdir("/dev", 0755);
    if (mount("tmpfs", "/dev", "tmpfs", MS_NOSUID | MS_NOEXEC, "size=64k"))
        child_fail("mount /dev");
    dev_node("/dev/null",    "/dev/null",    0666, 1, 3);
    dev_node("/dev/zero",    "/dev/zero",    0666, 1, 5);
    dev_node("/dev/full",    "/dev/full",    0666, 1, 7);
    dev_node("/dev/urandom", "/dev/urandom", 0666, 1, 9);
    dev_node("/dev/random",  "/dev/random",  0666, 1, 8);
    mkdir("/tmp", 0777);
    mount("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV, "size=16m");
    chmod("/tmp", 0777);

    /* 5. identity: hostname + environment */
    const char *host = opt->hostname_override ? opt->hostname_override : m->hostname;
    if (host[0] && sethostname(host, strlen(host))) child_fail("sethostname");

    clearenv();
    setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
    setenv("HOME", "/root", 1);
    setenv("HOSTNAME", host, 1);
    setenv("container", "synthctl", 1);
    for (int i = 0; i < m->env_len; i++) {
        char *eq = strchr(m->env[i], '=');
        if (eq) { *eq = 0; setenv(m->env[i], eq + 1, 1); }
    }

    /* 6. resource limits — real enforcement even where cgroup delegation
     *    is unavailable (rootless hosts). cgroups v2 is attempted by the
     *    parent; these rlimits are the guaranteed floor. */
    if (opt->pids_max > 0) {
        struct rlimit rl = { (rlim_t)opt->pids_max, (rlim_t)opt->pids_max };
        setrlimit(RLIMIT_NPROC, &rl);
    }
    if (opt->mem_limit_mb > 0) {
        rlim_t b = (rlim_t)opt->mem_limit_mb * 1024 * 1024;
        struct rlimit rl = { b, b };
        setrlimit(RLIMIT_AS, &rl);
    }

    /* 7. harden: no new privileges, drop the whole bounding set, empty caps */
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    for (int c = 0; c <= 40; c++) prctl(PR_CAPBSET_DROP, c, 0, 0, 0);
    struct __user_cap_header_struct hdr = { _LINUX_CAPABILITY_VERSION_3, 0 };
    struct __user_cap_data_struct data[2] = { {0,0,0}, {0,0,0} };
    syscall(SYS_capset, &hdr, data);
    /* keep uid 0 *inside* the container (mapped to the caller outside) */

    /* 8. exec */
    if (chdir(m->workdir[0] ? m->workdir : "/")) child_fail("chdir workdir");
    char *argv[MAX_CMD + 1];
    int n = 0;
    if (opt->argc > 0) {
        for (int i = 0; i < opt->argc && n < MAX_CMD; i++) argv[n++] = opt->argv[i];
    } else {
        for (int i = 0; i < m->entrypoint_len && n < MAX_CMD; i++) argv[n++] = m->entrypoint[i];
    }
    if (n == 0) argv[n++] = (char *)"/bin/sh";
    argv[n] = NULL;
    execvpe(argv[0], argv, environ);
    fprintf(stderr, "synthctl(container): exec %s: %s\n", argv[0], strerror(errno));
    _exit(127);
}

/* --- parent-side helpers --- */

static pid_t g_child = -1;
static void fwd_sig(int sig)
{ if (g_child > 0) kill(g_child, sig); }

static int write_file(const char *path, const char *data)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    ssize_t w = write(fd, data, strlen(data));
    close(fd);
    return w == (ssize_t)strlen(data) ? 0 : -1;
}

/* cgroups v2: best-effort, silently degrades on rootless hosts without
 * delegation. Returns 1 if a cgroup was created. */
static int cgroup_setup(pid_t child, const struct run_options *opt, char *cgpath, size_t cgsz)
{
    struct stat st;
    if (stat("/sys/fs/cgroup/cgroup.controllers", &st)) return 0;
    snprintf(cgpath, cgsz, "/sys/fs/cgroup/synthctl-%ld", (long)child);
    if (mkdir(cgpath, 0755)) return 0;
    char p[4400], v[64];
    if (opt->mem_limit_mb > 0) {
        snprintf(p, sizeof p, "%s/memory.max", cgpath);
        snprintf(v, sizeof v, "%ld", opt->mem_limit_mb * 1024 * 1024);
        write_file(p, v);
    }
    if (opt->pids_max > 0) {
        snprintf(p, sizeof p, "%s/pids.max", cgpath);
        snprintf(v, sizeof v, "%ld", opt->pids_max);
        write_file(p, v);
    }
    snprintf(p, sizeof p, "%s/cgroup.procs", cgpath);
    snprintf(v, sizeof v, "%ld", (long)child);
    write_file(p, v);
    return 1;
}

int run_container(const struct run_options *opt)
{
    int sync_pipe[2];
    if (pipe(sync_pipe)) die("pipe: %s", strerror(errno));

    void *stack = mmap(NULL, 1024 * 1024, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    if (stack == MAP_FAILED) die("mmap stack: %s", strerror(errno));
    void *stack_top = (char *)stack + 1024 * 1024;

    struct child_ctx ctx = { opt, sync_pipe[0] };
    int flags = CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID |
                CLONE_NEWUTS | CLONE_NEWIPC | SIGCHLD;
    if (opt->net_isolated) flags |= CLONE_NEWNET;

    pid_t child = clone(child_main, stack_top, flags, &ctx);
    if (child < 0) die("clone: %s", strerror(errno));
    close(sync_pipe[0]);
    g_child = child;

    /* map container uid/gid 0 to our real uid/gid (rootless-style) */
    char map[128], path[128];
    snprintf(path, sizeof path, "/proc/%ld/setgroups", (long)child);
    write_file(path, "deny");
    snprintf(path, sizeof path, "/proc/%ld/uid_map", (long)child);
    snprintf(map, sizeof map, "0 %ld 1", (long)getuid());
    if (write_file(path, map)) die("uid_map: %s", strerror(errno));
    snprintf(path, sizeof path, "/proc/%ld/gid_map", (long)child);
    snprintf(map, sizeof map, "0 %ld 1", (long)getgid());
    if (write_file(path, map)) die("gid_map: %s", strerror(errno));

    /* release the child */
    if (write(sync_pipe[1], "!", 1) != 1) die("sync write");
    close(sync_pipe[1]);

    char cgpath[512] = {0};
    int cg = cgroup_setup(child, opt, cgpath, sizeof cgpath);
    if (!cg && (opt->mem_limit_mb || opt->pids_max))
        fprintf(stderr, "synthctl: cgroup v2 not writable here — "
                        "limits enforced via rlimit instead\n");

    struct sigaction sa = {0};
    sa.sa_handler = fwd_sig;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);

    int status;
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    if (cgpath[0]) rmdir(cgpath);
    munmap(stack, 1024 * 1024);
    g_child = -1;

    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return -1;
}
