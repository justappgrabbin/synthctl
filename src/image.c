/* image.c — .synthimg build / inspect / unpack.
 *
 * Layout:
 *   magic(8) "SYNTHIMG"
 *   version u8
 *   flags u32 LE        (bit0: payload is gzip-compressed tar)
 *   manifest_len u32 LE
 *   payload_sha256[32]  (sha256 of the *stored* payload bytes)
 *   manifest JSON (UTF-8, manifest_len bytes)
 *   payload: ustar stream of the rootfs (gzip if flag)
 */
#define _GNU_SOURCE
#include "synthctl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* ---------------- manifest ---------------- */

void manifest_init(struct manifest *m)
{
    memset(m, 0, sizeof *m);
    strcpy(m->version, "1");
    strcpy(m->workdir, "/");
    strcpy(m->hostname, "synthbox");
}

void manifest_free(struct manifest *m)
{
    for (int i = 0; i < m->entrypoint_len; i++) free(m->entrypoint[i]);
    for (int i = 0; i < m->env_len; i++) free(m->env[i]);
    m->entrypoint_len = m->env_len = 0;
}

static void json_escape(const char *s, char *out, size_t outsz)
{
    size_t o = 0;
    for (; *s && o + 2 < outsz; s++) {
        if (*s == '"' || *s == '\\') { out[o++] = '\\'; out[o++] = *s; }
        else if ((unsigned char)*s >= 0x20) out[o++] = *s;
    }
    out[o] = 0;
}

int manifest_to_json(const struct manifest *m, char *buf, size_t buflen)
{
    char esc[1024];
    size_t o = 0;
    o += snprintf(buf + o, buflen - o, "{\n");
    json_escape(m->name, esc, sizeof esc);
    o += snprintf(buf + o, buflen - o, "  \"name\": \"%s\",\n", esc);
    json_escape(m->version, esc, sizeof esc);
    o += snprintf(buf + o, buflen - o, "  \"version\": \"%s\",\n", esc);
    json_escape(m->arch, esc, sizeof esc);
    o += snprintf(buf + o, buflen - o, "  \"arch\": \"%s\",\n", esc);
    json_escape(m->created, esc, sizeof esc);
    o += snprintf(buf + o, buflen - o, "  \"created\": \"%s\",\n", esc);
    json_escape(m->hostname, esc, sizeof esc);
    o += snprintf(buf + o, buflen - o, "  \"hostname\": \"%s\",\n", esc);
    json_escape(m->workdir, esc, sizeof esc);
    o += snprintf(buf + o, buflen - o, "  \"working_dir\": \"%s\",\n", esc);
    o += snprintf(buf + o, buflen - o, "  \"entrypoint\": [");
    for (int i = 0; i < m->entrypoint_len; i++) {
        json_escape(m->entrypoint[i], esc, sizeof esc);
        o += snprintf(buf + o, buflen - o, "%s\"%s\"", i ? ", " : "", esc);
    }
    o += snprintf(buf + o, buflen - o, "],\n  \"env\": [");
    for (int i = 0; i < m->env_len; i++) {
        json_escape(m->env[i], esc, sizeof esc);
        o += snprintf(buf + o, buflen - o, "%s\"%s\"", i ? ", " : "", esc);
    }
    o += snprintf(buf + o, buflen - o, "]\n}\n");
    return (o < buflen) ? 0 : -1;
}

/* Minimal JSON value extractor: finds "key": "string" or "key": [ "a","b" ] */
static const char *json_find(const char *j, const char *key)
{
    char pat[140];
    snprintf(pat, sizeof pat, "\"%s\"", key);
    const char *p = strstr(j, pat);
    if (!p) return NULL;
    p += strlen(pat);
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == ':') p++;
    return p;
}

static int json_get_str(const char *j, const char *key, char *out, size_t outsz)
{
    const char *p = json_find(j, key);
    if (!p || *p != '"') return -1;
    p++;
    size_t o = 0;
    while (*p && *p != '"' && o + 1 < outsz) {
        if (*p == '\\' && p[1]) p++;
        out[o++] = *p++;
    }
    out[o] = 0;
    return 0;
}

static int json_get_str_array(const char *j, const char *key, char **arr, int *n, int max)
{
    const char *p = json_find(j, key);
    if (!p || *p != '[') return -1;
    p++;
    *n = 0;
    while (*p && *p != ']' && *n < max) {
        if (*p == '"') {
            p++;
            char tmp[512]; size_t o = 0;
            while (*p && *p != '"' && o + 1 < sizeof tmp) {
                if (*p == '\\' && p[1]) p++;
                tmp[o++] = *p++;
            }
            tmp[o] = 0;
            arr[(*n)++] = strdup(tmp);
            if (*p == '"') p++;
        } else p++;
    }
    return 0;
}

int manifest_from_json(const char *json, struct manifest *m)
{
    manifest_init(m);
    json_get_str(json, "name", m->name, sizeof m->name);
    json_get_str(json, "version", m->version, sizeof m->version);
    json_get_str(json, "arch", m->arch, sizeof m->arch);
    json_get_str(json, "created", m->created, sizeof m->created);
    json_get_str(json, "hostname", m->hostname, sizeof m->hostname);
    json_get_str(json, "working_dir", m->workdir, sizeof m->workdir);
    json_get_str_array(json, "entrypoint", m->entrypoint, &m->entrypoint_len, MAX_CMD);
    json_get_str_array(json, "env", m->env, &m->env_len, MAX_ENV);
    return 0;
}

/* ---------------- ustar writer ---------------- */

static uint32_t rd32le(const unsigned char *p)
{ return p[0] | (p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static void wr32le(unsigned char *p, uint32_t v)
{ p[0] = v & 0xff; p[1] = (v >> 8) & 0xff; p[2] = (v >> 16) & 0xff; p[3] = (v >> 24) & 0xff; }

static FILE *tar_w;         /* output stream */
static long  tar_bytes;     /* bytes written */

/* prune list: absolute path prefixes excluded from capture */
static const char **g_prune;
static int g_prune_n;
static uint64_t g_max_file_bytes;   /* 0 = unlimited */

void image_set_prune(const char **prefixes, int n)
{ g_prune = prefixes; g_prune_n = n; }
void image_set_max_file_bytes(uint64_t b)
{ g_max_file_bytes = b; }

static int pruned(const char *fullpath)
{
    for (int i = 0; i < g_prune_n; i++) {
        size_t l = strlen(g_prune[i]);
        if (!strncmp(fullpath, g_prune[i], l) &&
            (fullpath[l] == '/' || fullpath[l] == 0)) return 1;
    }
    return 0;
}

static void tar_pad(void)
{
    static const char zeros[512] = {0};
    long r = tar_bytes % 512;
    if (r) { fwrite(zeros, 1, 512 - r, tar_w); tar_bytes += 512 - r; }
}

static void tar_chksum(unsigned char h[512])
{
    memset(h + 148, ' ', 8);
    unsigned s = 0;
    for (int i = 0; i < 512; i++) s += h[i];
    snprintf((char *)h + 148, 8, "%06o", s);
    h[155] = ' ';
}

/* set a possibly-long path into a ustar header using the prefix field:
 * name(100) + prefix(155) joined as prefix/name. Returns -1 if unsplittable. */
static int tar_set_name(unsigned char h[512], const char *path)
{
    size_t len = strlen(path);
    if (len <= 100) { snprintf((char *)h, 100, "%s", path); return 0; }
    /* split at a '/' so that suffix fits in name and head in prefix */
    for (size_t i = len; i-- > 0; ) {
        if (path[i] == '/' && len - i - 1 <= 100 && i <= 155) {
            memcpy(h + 345, path, i);
            memcpy(h, path + i + 1, len - i - 1);
            return 0;
        }
    }
    fprintf(stderr, "synthctl: path too long for tar, skipping: %s\n", path);
    return -1;
}

/* walk rootfs dir and emit tar entries (relative paths, no leading ./) */
static int tar_emit_dir(const char *dir, const char *prefix)
{
    DIR *d = opendir(dir);
    if (!d) { fprintf(stderr, "synthctl: skip unreadable dir %s: %s\n", dir, strerror(errno)); return 0; }
    struct dirent *e;
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        char full[4096], rel[4096];
        snprintf(full, sizeof full, "%s/%s", dir, e->d_name);
        snprintf(rel, sizeof rel, "%s%s", prefix, e->d_name);
        struct stat st;
        if (lstat(full, &st)) { fprintf(stderr, "synthctl: lstat %s: %s\n", full, strerror(errno)); closedir(d); return -1; }
        if (pruned(full)) continue;
        if (S_ISREG(st.st_mode) && g_max_file_bytes &&
            (uint64_t)st.st_size > g_max_file_bytes) continue;
        if (S_ISLNK(st.st_mode)) {
            char ln[1024]; ssize_t l = readlink(full, ln, sizeof ln - 1);
            if (l < 0) { closedir(d); return -1; }
            ln[l] = 0;
            /* header with rel path, link target */
            unsigned char h[512] = {0};
            if (tar_set_name(h, rel)) continue;
            snprintf((char *)h + 100, 8, "%07o", st.st_mode & 07777);
            snprintf((char *)h + 108, 8, "%07o", 0);
            snprintf((char *)h + 116, 8, "%07o", 0);
            snprintf((char *)h + 124, 12, "%011o", 0);
            snprintf((char *)h + 136, 12, "%011lo", (unsigned long)st.st_mtime);
            h[156] = '2';
            snprintf((char *)h + 157, 100, "%s", ln);
            memcpy(h + 257, "ustar", 6); memcpy(h + 263, "00", 2);
            tar_chksum(h);
            fwrite(h, 1, 512, tar_w); tar_bytes += 512;
            continue;
        }
        if (S_ISDIR(st.st_mode)) {
            char drelp[4100];
            snprintf(drelp, sizeof drelp, "%s/", rel);
            /* emit dir header */
            unsigned char h[512] = {0};
            if (tar_set_name(h, drelp)) continue;
            snprintf((char *)h + 100, 8, "%07o", st.st_mode & 07777);
            snprintf((char *)h + 108, 8, "%07o", 0);
            snprintf((char *)h + 116, 8, "%07o", 0);
            snprintf((char *)h + 124, 12, "%011o", 0);
            snprintf((char *)h + 136, 12, "%011lo", (unsigned long)st.st_mtime);
            h[156] = '5';
            memcpy(h + 257, "ustar", 6); memcpy(h + 263, "00", 2);
            tar_chksum(h);
            fwrite(h, 1, 512, tar_w); tar_bytes += 512;
            char newprefix[4096];
            snprintf(newprefix, sizeof newprefix, "%s/", rel);
            if (tar_emit_dir(full, newprefix)) { closedir(d); return -1; }
            continue;
        }
        if (S_ISREG(st.st_mode)) {
            /* open first: unreadable files (e.g. /etc/shadow) are skipped,
             * they must not abort a snapshot of the whole machine */
            FILE *f = fopen(full, "rb");
            if (!f) continue;
            /* write header then file contents read from `full` */
            unsigned char h[512] = {0};
            if (tar_set_name(h, rel)) { fclose(f); continue; }
            snprintf((char *)h + 100, 8, "%07o", st.st_mode & 07777);
            snprintf((char *)h + 108, 8, "%07o", 0);
            snprintf((char *)h + 116, 8, "%07o", 0);
            snprintf((char *)h + 124, 12, "%011lo", (unsigned long)st.st_size);
            snprintf((char *)h + 136, 12, "%011lo", (unsigned long)st.st_mtime);
            h[156] = '0';
            memcpy(h + 257, "ustar", 6); memcpy(h + 263, "00", 2);
            tar_chksum(h);
            fwrite(h, 1, 512, tar_w); tar_bytes += 512;
            char buf[65536]; size_t n;
            while ((n = fread(buf, 1, sizeof buf, f)) > 0) { fwrite(buf, 1, n, tar_w); tar_bytes += n; }
            fclose(f);
            tar_pad();
        }
    }
    closedir(d);
    return 0;
}

static void tar_end(void)
{
    static const char zeros[1024] = {0};
    fwrite(zeros, 1, 1024, tar_w); tar_bytes += 1024;
}

/* emit one absolute path (file/dir/symlink), recursing into dirs.
 * `rel` is the in-image path with no leading slash. */
static int tar_emit_path(const char *full, const char *rel)
{
    if (pruned(full)) return 0;
    struct stat st;
    if (lstat(full, &st)) return 0; /* vanished: skip */
    unsigned char h[512] = {0};
    char namebuf[600];
    snprintf(namebuf, sizeof namebuf, "%s%s", rel, S_ISDIR(st.st_mode) ? "/" : "");
    if (tar_set_name(h, namebuf)) return 0;
    snprintf((char *)h + 100, 8, "%07o", st.st_mode & 07777);
    snprintf((char *)h + 108, 8, "%07o", 0);
    snprintf((char *)h + 116, 8, "%07o", 0);
    snprintf((char *)h + 124, 12, "%011lo",
             S_ISREG(st.st_mode) ? (unsigned long)st.st_size : 0UL);
    snprintf((char *)h + 136, 12, "%011lo", (unsigned long)st.st_mtime);
    h[156] = S_ISDIR(st.st_mode) ? '5' : S_ISLNK(st.st_mode) ? '2' :
             S_ISREG(st.st_mode) ? '0' : '?';
    if (h[156] == '?') return 0;
    if (S_ISLNK(st.st_mode)) {
        char ln[1024]; ssize_t l = readlink(full, ln, sizeof ln - 1);
        if (l < 0) return 0;
        ln[l] = 0;
        snprintf((char *)h + 157, 100, "%s", ln);
    }
    memcpy(h + 257, "ustar", 6); memcpy(h + 263, "00", 2);
    tar_chksum(h);
    fwrite(h, 1, 512, tar_w); tar_bytes += 512;
    if (S_ISREG(st.st_mode)) {
        if (g_max_file_bytes && (uint64_t)st.st_size > g_max_file_bytes) return 0;
        FILE *f = fopen(full, "rb");
        if (!f) return 0;
        char buf[65536]; size_t n;
        while ((n = fread(buf, 1, sizeof buf, f)) > 0) { fwrite(buf, 1, n, tar_w); tar_bytes += n; }
        fclose(f);
        tar_pad();
    } else if (S_ISDIR(st.st_mode)) {
        char prefix[4096];
        snprintf(prefix, sizeof prefix, "%s/", rel);
        return tar_emit_dir(full, prefix);
    }
    return 0;
}

/* build from a list of absolute host paths, preserving layout in-image */
int image_build_paths(const char **paths, int n, const struct manifest *m,
                      const char *out_path, int gzip_payload)
{
    FILE *tar_tmp = tmpfile();
    if (!tar_tmp) { perror("tmpfile"); return -1; }
    tar_w = tar_tmp; tar_bytes = 0;
    for (int i = 0; i < n; i++) {
        const char *p = paths[i];
        while (*p == '/') p++;              /* strip leading slashes */
        if (!*p) continue;
        char abs[4096];
        snprintf(abs, sizeof abs, "/%s", p);
        if (tar_emit_path(abs, p)) { fclose(tar_tmp); return -1; }
    }
    tar_end();
    fflush(tar_tmp);

    FILE *payload = tar_tmp, *gz_tmp = NULL;
    if (gzip_payload) {
        gz_tmp = tmpfile();
        if (!gz_tmp || gzip_stream(tar_tmp, gz_tmp)) { fclose(tar_tmp); return -1; }
        payload = gz_tmp;
    }
    fflush(payload);
    fseek(payload, 0, SEEK_END);
    long payload_len = ftell(payload);

    char mjson[8192];
    if (manifest_to_json(m, mjson, sizeof mjson)) return -1;
    unsigned char hdr[SYNTHIMG_HDR_LEN] = {0};
    memcpy(hdr, SYNTHIMG_MAGIC, SYNTHIMG_MAGIC_LEN);
    hdr[8] = SYNTHIMG_VERSION;
    wr32le(hdr + 9, gzip_payload ? SYNTHIMG_FLAG_GZIP : 0);
    wr32le(hdr + 13, (uint32_t)strlen(mjson));
    if (sha256_file(payload, 0, payload_len, hdr + 17)) return -1;

    FILE *out = fopen(out_path, "wb");
    if (!out) { perror(out_path); return -1; }
    fwrite(hdr, 1, sizeof hdr, out);
    fwrite(mjson, 1, strlen(mjson), out);
    fseek(payload, 0, SEEK_SET);
    char buf[65536]; size_t nn;
    while ((nn = fread(buf, 1, sizeof buf, payload)) > 0) fwrite(buf, 1, nn, out);
    fclose(out); fclose(tar_tmp);
    if (gz_tmp) fclose(gz_tmp);
    return 0;
}

/* ---------------- ustar reader ---------------- */

static FILE *tar_r;

static int tar_oct(const unsigned char *p, int n)
{
    char buf[16]; memcpy(buf, p, n); buf[n] = 0;
    return (int)strtol(buf, NULL, 8);
}

static int mkdir_p(const char *path, mode_t mode)
{
    char tmp[4096];
    snprintf(tmp, sizeof tmp, "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') { *p = 0; mkdir(tmp, mode); *p = '/'; }
    }
    return mkdir(tmp, mode);
}

/* extract tar stream from tar_r into dest dir. Returns 0 ok. */
static int tar_extract_all(const char *dest)
{
    unsigned char h[512];
    for (;;) {
        if (fread(h, 1, 512, tar_r) != 512) { fprintf(stderr, "synthctl: tar: short header read\n"); return -1; }
        if (h[0] == 0) break; /* zero block = end */
        char name[101]; memcpy(name, h, 100); name[100] = 0;
        char prefix[156]; memcpy(prefix, h + 345, 155); prefix[155] = 0;
        char fullname[300];
        if (prefix[0]) snprintf(fullname, sizeof fullname, "%s/%s", prefix, name);
        else snprintf(fullname, sizeof fullname, "%s", name);
        long size = strtol((char *)h + 124, NULL, 8);
        mode_t mode = (mode_t)tar_oct(h + 100, 7);
        char type = h[156];
        /* refuse traversal: no absolute paths, no .. components */
        if (fullname[0] == '/' || strstr(fullname, "../") || !strcmp(fullname, "..") ||
            (strlen(fullname) > 2 && !strcmp(fullname + strlen(fullname) - 3, "/.."))) {
            long skip = size + ((512 - (size % 512)) % 512);
            if (size > 0) fseek(tar_r, skip, SEEK_CUR);
            continue;
        }
        char out[4096];
        snprintf(out, sizeof out, "%s/%s", dest, fullname);
        switch (type) {
        case '5':
            mkdir_p(out, mode ? mode : 0755); chmod(out, mode ? mode : 0755);
            break;
        case '2': {
            char ln[101]; memcpy(ln, h + 157, 100); ln[100] = 0;
            unlink(out); symlink(ln, out);
            break;
        }
        case '0': case '\0': {
            char dirpart[4096];
            snprintf(dirpart, sizeof dirpart, "%s", out);
            char *sl = strrchr(dirpart, '/');
            if (sl) { *sl = 0; mkdir_p(dirpart, 0755); }
            FILE *f = fopen(out, "wb");
            if (!f) { fprintf(stderr, "synthctl: tar: cannot write %s: %s\n", out, strerror(errno)); return -1; }
            long left = size;
            char buf[65536];
            while (left > 0) {
                size_t want = left > (long)sizeof buf ? sizeof buf : (size_t)left;
                if (fread(buf, 1, want, tar_r) != want) { fprintf(stderr, "synthctl: tar: short data read at %s\n", fullname); fclose(f); return -1; }
                fwrite(buf, 1, want, f);
                left -= want;
            }
            fclose(f);
            chmod(out, mode ? mode : 0644);
            long pad = (512 - (size % 512)) % 512;
            if (pad) fseek(tar_r, pad, SEEK_CUR);
            break;
        }
        default:
            /* skip other types */
            if (size > 0) {
                long skip = size + ((512 - (size % 512)) % 512);
                fseek(tar_r, skip, SEEK_CUR);
            }
        }
    }
    return 0;
}

/* ---------------- public API ---------------- */

int image_build(const char *rootfs_dir, const struct manifest *m,
                const char *out_path, int gzip_payload)
{
    /* 1. tar the rootfs into a temp file */
    FILE *tar_tmp = tmpfile();
    if (!tar_tmp) { perror("tmpfile"); return -1; }
    tar_w = tar_tmp; tar_bytes = 0;
    if (tar_emit_dir(rootfs_dir, "")) { fclose(tar_tmp); return -1; }
    tar_end();
    fflush(tar_tmp);

    /* 2. optionally gzip into second temp file */
    FILE *payload = tar_tmp;
    FILE *gz_tmp = NULL;
    if (gzip_payload) {
        gz_tmp = tmpfile();
        if (!gz_tmp || gzip_stream(tar_tmp, gz_tmp)) { fclose(tar_tmp); return -1; }
        payload = gz_tmp;
    }
    fflush(payload);
    long payload_len;
    fseek(payload, 0, SEEK_END); payload_len = ftell(payload);

    /* 3. header + manifest */
    char mjson[8192];
    if (manifest_to_json(m, mjson, sizeof mjson)) return -1;

    unsigned char hdr[SYNTHIMG_HDR_LEN] = {0};
    memcpy(hdr, SYNTHIMG_MAGIC, SYNTHIMG_MAGIC_LEN);
    hdr[8] = SYNTHIMG_VERSION;
    wr32le(hdr + 9, gzip_payload ? SYNTHIMG_FLAG_GZIP : 0);
    wr32le(hdr + 13, (uint32_t)strlen(mjson));
    if (sha256_file(payload, 0, payload_len, hdr + 17)) return -1;

    FILE *out = fopen(out_path, "wb");
    if (!out) { perror(out_path); return -1; }
    fwrite(hdr, 1, sizeof hdr, out);
    fwrite(mjson, 1, strlen(mjson), out);
    fseek(payload, 0, SEEK_SET);
    char buf[65536]; size_t n;
    while ((n = fread(buf, 1, sizeof buf, payload)) > 0) fwrite(buf, 1, n, out);
    fclose(out);
    fclose(tar_tmp);
    if (gz_tmp) fclose(gz_tmp);
    return 0;
}

/* read header+manifest; leaves *fp positioned at payload. */
static int image_open(const char *path, FILE **fp_out, uint32_t *flags_out,
                      unsigned char sha[32], struct manifest *m_out,
                      uint64_t *payload_size_out)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return -1; }
    unsigned char hdr[SYNTHIMG_HDR_LEN];
    if (fread(hdr, 1, sizeof hdr, f) != sizeof hdr) { fclose(f); return -1; }
    if (memcmp(hdr, SYNTHIMG_MAGIC, SYNTHIMG_MAGIC_LEN)) {
        fprintf(stderr, "synthctl: not a .synthimg file (bad magic)\n");
        fclose(f); return -1;
    }
    if (hdr[8] != SYNTHIMG_VERSION) {
        fprintf(stderr, "synthctl: unsupported image version %u\n", hdr[8]);
        fclose(f); return -1;
    }
    uint32_t flags = rd32le(hdr + 9);
    uint32_t mlen = rd32le(hdr + 13);
    memcpy(sha, hdr + 17, 32);
    char *mjson = malloc(mlen + 1);
    if (fread(mjson, 1, mlen, f) != mlen) { free(mjson); fclose(f); return -1; }
    mjson[mlen] = 0;
    if (m_out) manifest_from_json(mjson, m_out);
    free(mjson);
    fseek(f, 0, SEEK_END);
    long end = ftell(f);
    if (payload_size_out) *payload_size_out = (uint64_t)(end - (long)sizeof hdr - mlen);
    fseek(f, (long)sizeof hdr + mlen, SEEK_SET);
    *fp_out = f;
    *flags_out = flags;
    return 0;
}

/* payload start offset: header + manifest */
static long payload_start(FILE *f)
{
    unsigned char hdr[SYNTHIMG_HDR_LEN];
    fseek(f, 0, SEEK_SET);
    if (fread(hdr, 1, sizeof hdr, f) != sizeof hdr) return -1;
    return SYNTHIMG_HDR_LEN + rd32le(hdr + 13);
}

int image_inspect(const char *img_path, struct manifest *m_out,
                  uint64_t *payload_size_out, char *sha_out)
{
    FILE *f; uint32_t flags; unsigned char sha[32];
    if (image_open(img_path, &f, &flags, sha, m_out, payload_size_out)) return -1;
    /* verify payload integrity */
    unsigned char actual[32];
    fseek(f, 0, SEEK_END); long end = ftell(f);
    long start = payload_start(f);
    if (start < 0 || sha256_file(f, start, end - start, actual) || memcmp(sha, actual, 32)) {
        fprintf(stderr, "synthctl: image payload sha256 mismatch — corrupt image\n");
        fclose(f); return -1;
    }
    fclose(f);
    if (sha_out)
        for (int i = 0; i < 32; i++) sprintf(sha_out + i * 2, "%02x", sha[i]);
    return 0;
}

int image_unpack(const char *img_path, const char *dest_dir, char *sha_out)
{
    FILE *f; uint32_t flags; unsigned char sha[32];
    if (image_open(img_path, &f, &flags, sha, NULL, NULL)) return -1;
    /* verify integrity before unpacking */
    long start = payload_start(f);
    fseek(f, 0, SEEK_END); long end = ftell(f);
    unsigned char actual[32];
    if (start < 0 || sha256_file(f, start, end - start, actual) || memcmp(sha, actual, 32)) {
        fprintf(stderr, "synthctl: image corrupt (sha mismatch)\n");
        fclose(f); return -1;
    }
    fseek(f, start, SEEK_SET);

    mkdir_p(dest_dir, 0755);
    int rc;
    if (flags & SYNTHIMG_FLAG_GZIP) {
        FILE *plain = tmpfile();
        if (!plain || gunzip_stream_at(fileno(f), start, plain)) { fclose(f); return -1; }
        fflush(plain); rewind(plain);
        tar_r = plain;
        rc = tar_extract_all(dest_dir);
        fclose(plain);
    } else {
        tar_r = f;
        rc = tar_extract_all(dest_dir);
    }
    fclose(f);
    if (sha_out)
        for (int i = 0; i < 32; i++) sprintf(sha_out + i * 2, "%02x", sha[i]);
    return rc;
}
