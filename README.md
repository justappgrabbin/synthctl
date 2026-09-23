# synthctl

A real container runtime and image format — **no Docker, no runc, no libcontainer, no external runtime dependency**. One C binary, direct Linux syscalls, rootless.

```
synthctl build rootfs/ -o app.synthimg --name myapp --entry "/bin/server"
synthctl inspect app.synthimg        # manifest + sha256 integrity check
synthctl run app.synthimg --mem 64 --pids 32
```

## How it works (the real mechanics)

Everything Docker does, synthctl does directly, in ~1200 lines of C:

| Boundary | Mechanism |
|---|---|
| Process isolation | `clone(CLONE_NEWPID)` — container's init is PID 1 |
| Filesystem isolation | `clone(CLONE_NEWNS)` + bind-mount + **`pivot_root(2)`** — the actual syscall that swaps the root filesystem |
| Hostname | `clone(CLONE_NEWUTS)` + `sethostname` |
| IPC | `clone(CLONE_NEWIPC)` |
| Network | `clone(CLONE_NEWNET)` — fresh stack with only `lo` |
| Privilege | `clone(CLONE_NEWUSER)` + uid/gid map — uid 0 inside maps to *your* unprivileged uid outside |
| Resources | cgroups v2 (`memory.max`, `pids.max`) when the kernel delegates them; `setrlimit(RLIMIT_AS/RLIMIT_NPROC)` as the guaranteed floor |
| Hardening | `PR_SET_NO_NEW_PRIVS`, full capability bounding-set drop, empty capset before `execvpe` |

## .synthimg format

See [FORMAT.md](FORMAT.md). Short version: 49-byte header (magic, version, flags, manifest length, payload SHA-256), a JSON manifest (name, entrypoint, env, workdir, hostname), and a ustar rootfs payload (optionally gzip). The embedded SHA-256 is verified on every `inspect`, `unpack`, and `run` — corrupt images are refused. The hash interoperates with standard tooling (`sha256sum` of the payload region matches).

## Build & test

```
make            # needs a C compiler and zlib
make test       # end-to-end: builds an image from host binaries and proves
                # every isolation boundary (see tests/e2e.sh)
```

The test suite is not a mock. It runs a real container and verifies:

1. Container init is PID 1; host PIDs unreachable
2. Only image files visible; host filesystem gone
3. Hostname change inside doesn't leak outside
4. uid 0 inside = your uid outside (user namespace)
5. Fresh network namespace (no interfaces) vs `--host-net` (lo + eth0)
6. Manifest env vars injected
7. Exit codes propagate (`exit 42` → rc 42)
8. `--mem 16` kills a memory hog at 12 MB; `--mem 512` lets it pass 256 MB

## Honest limitations

- **Rootless networking is isolated-only.** Creating veth pairs / bridges requires real root. Containers get a fresh net namespace (`lo` only) or `--host-net`. This is the same constraint as rootless Docker without slirp4netns.
- **cgroups v2 delegation is best-effort.** On hosts that don't delegate controllers to unprivileged users, limits fall back to rlimits (still real enforcement, just per-process rather than per-cgroup). It says so on stderr when this happens.
- Some hardened/nested kernels block mounting `proc` from a user namespace via LSM policy. synthctl reports it and continues — PID isolation never depended on `/proc`.
- x86_64 Linux. Images are arch-tagged in the manifest.

## CLI

```
build <rootfs> -o app.synthimg [--name N] [--entry "cmd"] [--env K=V]
      [--workdir /w] [--hostname h] [--plain]
inspect app.synthimg
unpack app.synthimg <dir>
run app.synthimg [--mem MB] [--pids N] [--ro] [--host-net] [--hostname h] [-- cmd...]
images                     # list unpacked image cache (~/.synthctl/images)
```

Images are unpacked once into `~/.synthctl/images/<payload-sha256>/` — content-addressed, so identical images share one rootfs and tampered images get a new key.
