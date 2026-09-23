/* snapshot.c — clone the live machine's state space into a .synthimg.
 *
 * This is the "clone of my computer" command: it captures the real host —
 * system binaries, libraries, config, and the invoking user's home — into
 * a portable image that `synthctl run` boots as an isolated clone.
 *
 * Default capture set (the machine's usable state, not kernel views):
 *   /bin /sbin /lib /lib64 /etc /opt
 *   /usr/bin /usr/sbin /usr/lib /usr/lib64 /usr/libexec
 *   /usr/share/zoneinfo /usr/share/terminfo
 *   $HOME
 *
 * Never captured (they are the kernel's, not the machine's):
 *   /proc /sys /dev /run /tmp /mnt (and the output file itself)
 *
 * Machine identity goes into the manifest: os-release, uname, original
 * hostname, capture time — the clone can introspect its own origin.
 */
#define _GNU_SOURCE
#include "synthctl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

#define MAX_PATHS 256
#define MAX_PRUNE 128

static const char *default_includes[] = {
    "/bin", "/sbin", "/lib", "/lib64", "/etc", "/opt",
    "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib64", "/usr/libexec",
    "/usr/share/zoneinfo", "/usr/share/terminfo",
};

static const char *default_prunes[] = {
    "/proc", "/sys", "/dev", "/run", "/tmp", "/mnt", "/media",
    "/var/cache", "/var/lib/apt/lists",
};

int snapshot_build(const char *out_path, const char *label,
                   const char **extra_inc, int n_extra_inc,
                   const char **extra_prune, int n_extra_prune,
                   uint64_t max_file_mb, int gzip)
{
    const char *paths[MAX_PATHS]; int np = 0;
    const char *prune[MAX_PRUNE]; int npr = 0;
    char home_inc[1200], home_cache_prune[1200];

    for (size_t i = 0; i < sizeof default_includes / sizeof *default_includes; i++)
        if (np < MAX_PATHS) paths[np++] = default_includes[i];

    const char *home = getenv("HOME");
    if (home && np < MAX_PATHS) {
        snprintf(home_inc, sizeof home_inc, "%s", home);
        paths[np++] = home_inc;
    }
    for (int i = 0; i < n_extra_inc && np < MAX_PATHS; i++) paths[np++] = extra_inc[i];

    for (size_t i = 0; i < sizeof default_prunes / sizeof *default_prunes; i++)
        prune[npr++] = default_prunes[i];
    if (home) {
        snprintf(home_cache_prune, sizeof home_cache_prune, "%s/.cache", home);
        prune[npr++] = home_cache_prune;
    }
    /* toolchain caches are regenerable, not machine state */
    static const char *home_prune_names[] = {
        "/.npm-cache", "/.npm", "/.nuget", "/.dotnet", "/.synthctl", "/.kimi-slides",
    };
    if (home) {
        for (size_t i = 0; i < sizeof home_prune_names / sizeof *home_prune_names; i++) {
            char *p = malloc(strlen(home) + 40);
            sprintf(p, "%s%s", home, home_prune_names[i]);
            if (npr < MAX_PRUNE) prune[npr++] = p; else free(p);
        }
    }
    prune[npr++] = out_path; /* never capture our own output */
    for (int i = 0; i < n_extra_prune && npr < MAX_PRUNE; i++) prune[npr++] = extra_prune[i];

    /* machine identity: baked into the manifest (name, hostname, env).
     * os-release/uname travel as env vars so the clone can introspect
     * its origin without faking filesystem paths. */
    struct manifest m; manifest_init(&m);
    struct utsname un; uname(&un);
    char host[256] = {0}; gethostname(host, sizeof host - 1);
    snprintf(m.name, sizeof m.name, "clone-of-%s", host[0] ? host : un.nodename);
    if (label) snprintf(m.name, sizeof m.name, "%s", label);
    snprintf(m.arch, sizeof m.arch, "%s", un.machine);
    snprintf(m.hostname, sizeof m.hostname, "%s-clone", host[0] ? host : "synth");
    time_t t = time(NULL); struct tm *tm = gmtime(&t);
    strftime(m.created, sizeof m.created, "%Y-%m-%dT%H:%M:%SZ", tm);
    m.entrypoint[m.entrypoint_len++] = strdup("/bin/sh");
    m.env[m.env_len++] = strdup("SYNTH_CLONE=1");
    char rel[600];
    snprintf(rel, sizeof rel, "SYNTH_SOURCE_KERNEL=%s %s", un.sysname, un.release);
    m.env[m.env_len++] = strdup(rel);
    char src[300];
    snprintf(src, sizeof src, "SYNTH_SOURCE_HOST=%s", host);
    m.env[m.env_len++] = strdup(src);
    {
        /* distro identity from os-release */
        FILE *osr = fopen("/etc/os-release", "rb");
        if (osr) {
            char line[512];
            while (fgets(line, sizeof line, osr)) {
                if (!strncmp(line, "PRETTY_NAME=", 12)) {
                    char *v = line + 12; v[strcspn(v, "\n")] = 0;
                    char buf[600];
                    snprintf(buf, sizeof buf, "SYNTH_SOURCE_OS=%s", v);
                    m.env[m.env_len++] = strdup(buf);
                    break;
                }
            }
            fclose(osr);
        }
    }

    image_set_prune(prune, npr);
    image_set_max_file_bytes(max_file_mb ? max_file_mb * 1024 * 1024 : 0);

    fprintf(stderr, "synthctl: capturing %d roots (pruning %d prefixes)...\n", np, npr);
    int rc = image_build_paths(paths, np, &m, out_path, gzip);
    manifest_free(&m);
    if (rc) fprintf(stderr, "synthctl: snapshot failed\n");
    else {
        struct stat st; stat(out_path, &st);
        fprintf(stderr, "synthctl: clone image %s (%.1f MB)\n",
                out_path, st.st_size / 1048576.0);
    }
    return rc;
}
