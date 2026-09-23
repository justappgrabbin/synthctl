/* util.c — helpers shared by builder and runtime */
#define _GNU_SOURCE
#include "synthctl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <zlib.h>

void die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "synthctl: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(1);
}

const char *synthctl_home(void)
{
    static char buf[1024];
    const char *home = getenv("HOME");
    if (!home) die("HOME not set");
    snprintf(buf, sizeof buf, "%s/%s", home, SYNTHCTL_HOME_DEFAULT);
    char sub[1200];
    mkdir(buf, 0755);
    snprintf(sub, sizeof sub, "%s/images", buf); mkdir(sub, 0755);
    snprintf(sub, sizeof sub, "%s/containers", buf); mkdir(sub, 0755);
    return buf;
}

/* sha256 over a byte range of an already-open FILE* (via zlib-independent
 * minimal SHA-256 implementation so the format stays verifiable anywhere). */

typedef struct { uint32_t h[8]; uint64_t len; uint8_t buf[64]; size_t n; } sha256_ctx;

static const uint32_t K[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };

#define ROR(x,n) (((x)>>(n))|((x)<<(32-(n))))

static void sha256_block(sha256_ctx *c, const uint8_t *p)
{
    uint32_t w[64], a,b,cc,d,e,f,g,h;
    for (int i=0;i<16;i++) w[i]=(p[i*4]<<24)|(p[i*4+1]<<16)|(p[i*4+2]<<8)|p[i*4+3];
    for (int i=16;i<64;i++){
        uint32_t s0=ROR(w[i-15],7)^ROR(w[i-15],18)^(w[i-15]>>3);
        uint32_t s1=ROR(w[i-2],17)^ROR(w[i-2],19)^(w[i-2]>>10);
        w[i]=w[i-16]+s0+w[i-7]+s1;
    }
    a=c->h[0];b=c->h[1];cc=c->h[2];d=c->h[3];e=c->h[4];f=c->h[5];g=c->h[6];h=c->h[7];
    for (int i=0;i<64;i++){
        uint32_t S1=ROR(e,6)^ROR(e,11)^ROR(e,25);
        uint32_t ch=(e&f)^(~e&g);
        uint32_t t1=h+S1+ch+K[i]+w[i];
        uint32_t S0=ROR(a,2)^ROR(a,13)^ROR(a,22);
        uint32_t maj=(a&b)^(a&cc)^(b&cc);
        uint32_t t2=S0+maj;
        h=g;g=f;f=e;e=d+t1;d=cc;cc=b;b=a;a=t1+t2;
    }
    c->h[0]+=a;c->h[1]+=b;c->h[2]+=cc;c->h[3]+=d;c->h[4]+=e;c->h[5]+=f;c->h[6]+=g;c->h[7]+=h;
}

static void sha256_init(sha256_ctx *c)
{
    static const uint32_t H0[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                                 0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    memcpy(c->h,H0,sizeof H0); c->len=0; c->n=0;
}

static void sha256_update(sha256_ctx *c, const uint8_t *p, size_t n)
{
    c->len += (uint64_t)n * 8;
    while (n) {
        size_t take = 64 - c->n; if (take > n) take = n;
        memcpy(c->buf + c->n, p, take); c->n += take; p += take; n -= take;
        if (c->n == 64) { sha256_block(c, c->buf); c->n = 0; }
    }
}

static void sha256_final(sha256_ctx *c, uint8_t out[32])
{
    uint8_t lenbuf[8];
    for (int i=0;i<8;i++) lenbuf[i] = (c->len >> (56 - i*8)) & 0xff;
    /* pad WITHOUT letting update() touch the length we already captured */
    uint8_t pad = 0x80, z = 0;
    sha256_update(c, &pad, 1);
    while (c->n != 56) sha256_update(c, &z, 1);
    c->len = 0;
    sha256_update(c, lenbuf, 8);
    for (int i=0;i<8;i++){
        out[i*4]=(c->h[i]>>24)&0xff; out[i*4+1]=(c->h[i]>>16)&0xff;
        out[i*4+2]=(c->h[i]>>8)&0xff; out[i*4+3]=c->h[i]&0xff;
    }
}

/* sha256 of `len` bytes of f starting at off (len<0 = to EOF). */
int sha256_file(FILE *f, long off, long len, unsigned char out[32])
{
    sha256_ctx c; sha256_init(&c);
    if (fseek(f, off, SEEK_SET)) return -1;
    uint8_t buf[65536];
    while (len != 0) {
        size_t want = sizeof buf;
        if (len > 0 && (long)want > len) want = (size_t)len;
        size_t got = fread(buf, 1, want, f);
        if (!got) break;
        sha256_update(&c, buf, got);
        if (len > 0) len -= (long)got;
    }
    sha256_final(&c, out);
    return 0;
}

/* gzip a file from src FILE* into dest FILE* (streaming). Returns 0 ok. */
int gzip_stream(FILE *src, FILE *dst)
{
    gzFile g = gzdopen(dup(fileno(dst)), "wb");
    if (!g) return -1;
    uint8_t buf[65536]; size_t n;
    rewind(src);
    while ((n = fread(buf, 1, sizeof buf, src)) > 0)
        if (gzwrite(g, buf, (unsigned)n) != (int)n) { gzclose(g); return -1; }
    return gzclose(g) == Z_OK ? 0 : -1;
}

/* NOTE: gzread/gzwrite operate on the RAW fd. stdio fseek() may leave the
 * fd offset ahead of the logical position (in-buffer seeks), so callers
 * must pass an explicit fd offset. */
int gunzip_stream_at(int fd, long off, FILE *dst)
{
    if (lseek(fd, off, SEEK_SET) < 0) return -1;
    gzFile g = gzdopen(dup(fd), "rb");
    if (!g) return -1;
    uint8_t buf[65536]; int n;
    while ((n = gzread(g, buf, sizeof buf)) > 0)
        if (fwrite(buf, 1, (size_t)n, dst) != (size_t)n) { gzclose(g); return -1; }
    int ok = gzclose(g);
    return (ok == Z_OK || ok == Z_STREAM_END || ok == Z_BUF_ERROR || n == 0) ? 0 : -1;
}

int gunzip_stream(FILE *src, FILE *dst)
{
    /* legacy path: assumes src stdio and fd offsets agree */
    return gunzip_stream_at(fileno(src), lseek(fileno(src), 0, SEEK_CUR), dst);
}
