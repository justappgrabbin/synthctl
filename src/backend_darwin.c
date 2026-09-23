/* backend_darwin.c — Apple runtime for synthctl (macOS).
 *
 * This file only compiles on macOS (__APPLE__). It exists because macOS has
 * NO Linux namespaces, no pivot_root, no cgroups — pretending otherwise would
 * be fake. What macOS does have is the Apple Sandbox (Seatbelt), the same
 * kernel MAC framework that sandboxes every App Store app, exposed through
 * sandbox-exec(1). That is the honest Apple runtime:
 *
 *   filesystem isolation  — deny-by-default Seatbelt profile; file reads and
 *                           writes allowed only under the unpacked .synthimg
 *                           rootfs (plus the dyld shared cache)
 *   network isolation     — network denied by default, opt-in allow
 *   process               — sandboxed child via posix_spawn, signaled + reaped
 *   identity              — no user namespaces on macOS; the process runs as
 *                           the invoking user, scoped by the sandbox profile
 *
 * NOTE: this runs MACH-O images captured on macOS (synthctl snapshot on a
 * Mac). A Linux-captured .synthimg contains ELF binaries and cannot run on
 * Darwin natively — that needs a VM layer (Virtualization.framework), which
 * is documented in README as future work, not faked here.
 */
#ifdef __APPLE__

#include "synthctl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <spawn.h>
#include <sys/wait.h>

extern char **environ;

/* Build a Seatbelt profile for the container. */
static int build_profile(const struct run_options *opt, char *buf, size_t buflen)
{
    const char *net = opt->net_isolated ? "(deny network*)" : "(allow network*)";
    int n = snprintf(buf, buflen,
        "(version 1)\n"
        "(deny default)\n"
        "(allow process-exec* (subpath \"%s\"))\n"
        "(allow file-read* (subpath \"%s\"))\n"
        "(allow file-read* (subpath \"/usr/lib\") (subpath \"/System/Library\"))"
        "\n"                                     /* dyld shared cache */
        "(allow file-read* (literal \"/dev/null\") (literal \"/dev/urandom\"))\n"
        "(allow file-write* (subpath \"%s\"))\n" /* container rootfs rw */
        "(allow file-write* (literal \"/dev/null\"))\n"
        "(allow sysctl-read)\n"
        "(allow mach-lookup (global-name \"com.apple.system.opendirectoryd\"))\n"
        "%s\n",
        opt->rootfs, opt->rootfs, opt->rootfs, net);
    return (n > 0 && (size_t)n < buflen) ? 0 : -1;
}

static pid_t g_child = -1;
static void fwd_sig(int sig) { if (g_child > 0) kill(g_child, sig); }

int run_container_darwin(const struct run_options *opt)
{
    char profile[8192];
    if (build_profile(opt, profile, sizeof profile)) {
        fprintf(stderr, "synthctl: sandbox profile too large\n");
        return -1;
    }

    /* resolve entrypoint inside the rootfs */
    const char *entry = (opt->argc > 0) ? opt->argv[0]
                      : (opt->m->entrypoint_len ? opt->m->entrypoint[0] : "/bin/sh");
    char exe[4400];
    snprintf(exe, sizeof exe, "%s/%s", opt->rootfs, entry);
    if (access(exe, X_OK)) {
        fprintf(stderr, "synthctl: %s: %s (Linux ELF images need the VM backend)\n",
                exe, strerror(errno));
        return 127;
    }

    char *argv[MAX_CMD + 3];
    int n = 0;
    argv[n++] = (char *)"sandbox-exec";
    argv[n++] = (char *)"-p";
    argv[n++] = profile;
    if (opt->argc > 0)
        for (int i = 0; i < opt->argc && n < MAX_CMD + 2; i++) argv[n++] = opt->argv[i];
    else
        for (int i = 0; i < opt->m->entrypoint_len && n < MAX_CMD + 2; i++)
            argv[n++] = opt->m->entrypoint[i];
    argv[n] = NULL;

    pid_t pid;
    if (posix_spawnp(&pid, "sandbox-exec", NULL, NULL, argv, environ)) {
        fprintf(stderr, "synthctl: spawn sandbox-exec: %s\n", strerror(errno));
        return -1;
    }
    g_child = pid;
    struct sigaction sa = {0};
    sa.sa_handler = fwd_sig;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    int status;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    g_child = -1;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return -1;
}

#endif /* __APPLE__ */
