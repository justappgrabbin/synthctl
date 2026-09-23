/*
 * synthctl — a real, self-contained container runtime and image format.
 *
 * No Docker, no runc, no libcontainer. Direct syscalls only:
 *   clone(2)   — creates user/mount/pid/uts/ipc/net namespaces
 *   pivot_root — switches the container onto the unpacked image rootfs
 *   mount(2)   — private mounts, bind-mounted /dev nodes, fresh /proc
 *   capset(2)  — capability drop before exec
 *   cgroups v2 — memory/pids/cpu limits when the kernel delegates them
 *
 * Image format: .synthimg (see image.c and FORMAT.md)
 */
#ifndef SYNTHCTL_H
#define SYNTHCTL_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#define SYNTHIMG_MAGIC   "SYNTHIMG"
#define SYNTHIMG_MAGIC_LEN 8
#define SYNTHIMG_VERSION 1
#define SYNTHIMG_FLAG_GZIP 0x1

/* On-disk header: magic(8) | version u8 | flags u32 | manifest_len u32 |
 * payload_sha256(32 bytes raw) | manifest JSON | payload tar(.gz) */
#define SYNTHIMG_HDR_LEN (8 + 1 + 4 + 4 + 32)

#define SYNTHCTL_HOME_DEFAULT ".synthctl"

/* ---- manifest ---- */
#define MAX_ENV 64
#define MAX_CMD 64

struct manifest {
    char  name[128];
    char  version[64];
    char  arch[32];
    char  created[40];
    char  hostname[64];
    char  workdir[256];
    char *entrypoint[MAX_CMD];
    int   entrypoint_len;
    char *env[MAX_ENV];
    int   env_len;
};

/* ---- image.c ---- */
int  image_build(const char *rootfs_dir, const struct manifest *m,
                 const char *out_path, int gzip_payload);
/* Build an image from a list of absolute host paths (preserving layout). */
int  image_build_paths(const char **paths, int n, const struct manifest *m,
                       const char *out_path, int gzip_payload);
void image_set_prune(const char **prefixes, int n);
void image_set_max_file_bytes(uint64_t b);
int  image_inspect(const char *img_path, struct manifest *m_out,
                   uint64_t *payload_size_out, char *sha_out /*65*/);
/* Unpack image payload into dest_dir (created). Returns 0 on success.
 * If sha_out non-NULL, receives hex sha256 of the payload (cache key). */
int  image_unpack(const char *img_path, const char *dest_dir, char *sha_out);

void manifest_init(struct manifest *m);
void manifest_free(struct manifest *m);
int  manifest_to_json(const struct manifest *m, char *buf, size_t buflen);
int  manifest_from_json(const char *json, struct manifest *m);

/* ---- runtime.c ---- */
struct run_options {
    const char *rootfs;       /* unpacked image rootfs dir */
    const struct manifest *m; /* image manifest */
    char *const *argv;        /* override command (may be NULL) */
    int   argc;
    int   net_isolated;       /* 1 = fresh net namespace (default), 0 = host net */
    long  mem_limit_mb;       /* 0 = unlimited */
    long  pids_max;           /* 0 = unlimited */
    int   read_only_root;     /* remount rootfs read-only inside */
    const char *hostname_override;
};
/* Runs the container, returns its exit status (0..255) or -1 on setup error. */
int  run_container(const struct run_options *opt);
#ifdef __APPLE__
int  run_container_darwin(const struct run_options *opt);
#endif

/* ---- snapshot.c ---- */
int  snapshot_build(const char *out_path, const char *label,
                    const char **extra_inc, int n_extra_inc,
                    const char **extra_prune, int n_extra_prune,
                    uint64_t max_file_mb, int gzip);

/* ---- util ---- */
const char *synthctl_home(void); /* ~/.synthctl, created on demand */
int  sha256_file(FILE *f, long off, long len, unsigned char out[32]);
int  gzip_stream(FILE *src, FILE *dst);
int  gunzip_stream(FILE *src, FILE *dst);
int  gunzip_stream_at(int fd, long off, FILE *dst);
void die(const char *fmt, ...);

#endif
