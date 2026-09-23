/* main.c — synthctl CLI
 *
 *   synthctl build <rootfs-dir> -o app.synthimg [--name N] [--entry "/bin/sh"]
 *                  [--env K=V]... [--workdir /w] [--hostname h] [--plain]
 *   synthctl inspect app.synthimg
 *   synthctl unpack app.synthimg <dir>
 *   synthctl run app.synthimg [-- cmd...] [--name hn] [--mem MB] [--pids N]
 *                  [--ro] [--host-net]
 *   synthctl images                     (list unpacked image cache)
 */
#define _GNU_SOURCE
#include "synthctl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

static void usage(void)
{
    fprintf(stderr,
        "synthctl — custom container runtime (no Docker)\n\n"
        "  build <rootfs> -o app.synthimg [opts]   pack a rootfs into an image\n"
        "     --name N --entry \"cmd\" --env K=V --workdir /w --hostname h --plain\n"
        "  inspect app.synthimg                    show manifest + verify sha256\n"
        "  unpack app.synthimg <dir>               extract image to a directory\n"
        "  run app.synthimg [opts] [-- cmd...]     run a real container\n"
        "     --mem MB --pids N --ro --host-net --hostname h\n"
        "  images                                  list unpacked image cache\n");
    exit(2);
}

static int cmd_build(int argc, char **argv)
{
    if (argc < 1) usage();
    const char *rootfs = argv[0];
    const char *out = "image.synthimg";
    struct manifest m; manifest_init(&m);
    struct utsname un; uname(&un);
    snprintf(m.arch, sizeof m.arch, "%s", un.machine);
    time_t t = time(NULL); struct tm *tm = gmtime(&t);
    strftime(m.created, sizeof m.created, "%Y-%m-%dT%H:%M:%SZ", tm);
    int gzip = 1;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-o") && i + 1 < argc) out = argv[++i];
        else if (!strcmp(argv[i], "--name") && i + 1 < argc)
            snprintf(m.name, sizeof m.name, "%s", argv[++i]);
        else if (!strcmp(argv[i], "--entry") && i + 1 < argc) {
            /* split on spaces */
            char *s = strdup(argv[++i]);
            char *tok = strtok(s, " ");
            while (tok && m.entrypoint_len < MAX_CMD) {
                m.entrypoint[m.entrypoint_len++] = strdup(tok);
                tok = strtok(NULL, " ");
            }
            free(s);
        }
        else if (!strcmp(argv[i], "--env") && i + 1 < argc)
            m.env[m.env_len++] = strdup(argv[++i]);
        else if (!strcmp(argv[i], "--workdir") && i + 1 < argc)
            snprintf(m.workdir, sizeof m.workdir, "%s", argv[++i]);
        else if (!strcmp(argv[i], "--hostname") && i + 1 < argc)
            snprintf(m.hostname, sizeof m.hostname, "%s", argv[++i]);
        else if (!strcmp(argv[i], "--plain")) gzip = 0;
        else usage();
    }
    if (!m.name[0]) snprintf(m.name, sizeof m.name, "%s", out);

    if (image_build(rootfs, &m, out, gzip)) die("build failed");
    struct stat st; stat(out, &st);
    printf("built %s (%lld bytes, %s)\n", out, (long long)st.st_size,
           gzip ? "gzip tar payload" : "plain tar payload");
    manifest_free(&m);
    return 0;
}

static int cmd_inspect(int argc, char **argv)
{
    if (argc < 1) usage();
    struct manifest m; uint64_t psize; char sha[65];
    if (image_inspect(argv[0], &m, &psize, sha)) return 1;
    printf("image:    %s\n", argv[0]);
    printf("name:     %s\nversion:  %s\narch:     %s\ncreated:  %s\n",
           m.name, m.version, m.arch, m.created);
    printf("hostname: %s\nworkdir:  %s\n", m.hostname, m.workdir);
    printf("entrypoint:");
    for (int i = 0; i < m.entrypoint_len; i++) printf(" %s", m.entrypoint[i]);
    printf("\nenv:");
    for (int i = 0; i < m.env_len; i++) printf(" %s", m.env[i]);
    printf("\npayload:  %llu bytes\nsha256:   %s\nintegrity: OK\n",
           (unsigned long long)psize, sha);
    manifest_free(&m);
    return 0;
}

static int cmd_unpack(int argc, char **argv)
{
    if (argc < 2) usage();
    char sha[65];
    if (image_unpack(argv[0], argv[1], sha)) die("unpack failed");
    printf("unpacked to %s (sha256 %s)\n", argv[1], sha);
    return 0;
}

static int cmd_run(int argc, char **argv)
{
    if (argc < 1) usage();
    const char *img = argv[0];
    struct run_options opt = {0};
    opt.net_isolated = 1;
    struct manifest m; uint64_t ps; char sha[65];
    if (image_inspect(img, &m, &ps, sha)) die("cannot read image %s", img);
    opt.m = &m;

    int i = 1;
    for (; i < argc; i++) {
        if (!strcmp(argv[i], "--")) { i++; break; }
        if (!strcmp(argv[i], "--mem") && i + 1 < argc) opt.mem_limit_mb = atol(argv[++i]);
        else if (!strcmp(argv[i], "--pids") && i + 1 < argc) opt.pids_max = atol(argv[++i]);
        else if (!strcmp(argv[i], "--ro")) opt.read_only_root = 1;
        else if (!strcmp(argv[i], "--host-net")) opt.net_isolated = 0;
        else if (!strcmp(argv[i], "--hostname") && i + 1 < argc)
            opt.hostname_override = argv[++i];
        else usage();
    }
    opt.argv = &argv[i];
    opt.argc = argc - i;

    /* unpack into cache keyed by payload sha256 */
    char dest[1200];
    snprintf(dest, sizeof dest, "%s/images/%s", synthctl_home(), sha);
    struct stat st;
    if (stat(dest, &st)) {
        printf("unpacking image %s -> %s\n", sha, dest);
        if (image_unpack(img, dest, NULL)) die("unpack failed");
    }
    opt.rootfs = dest;

    int rc = run_container(&opt);
    manifest_free(&m);
    return rc;
}

static int cmd_images(void)
{
    char dir[1200];
    snprintf(dir, sizeof dir, "%s/images", synthctl_home());
    DIR *d = opendir(dir);
    if (!d) return 0;
    struct dirent *e;
    int n = 0;
    while ((e = readdir(d)))
        if (e->d_name[0] != '.') { printf("%s\n", e->d_name); n++; }
    closedir(d);
    if (!n) printf("(no unpacked images)\n");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) usage();
    if (!strcmp(argv[1], "build"))   return cmd_build(argc - 2, argv + 2);
    if (!strcmp(argv[1], "inspect")) return cmd_inspect(argc - 2, argv + 2);
    if (!strcmp(argv[1], "unpack"))  return cmd_unpack(argc - 2, argv + 2);
    if (!strcmp(argv[1], "run"))     return cmd_run(argc - 2, argv + 2);
    if (!strcmp(argv[1], "images"))  return cmd_images();
    usage();
    return 2;
}
