// Test-only fault-injection shim, preloaded into the messagetag process by
// the regression suite (tests/regression_test.py) to simulate a write(2)
// failure on standard output that happens *after* part of the result line
// has already been accepted. A closed real pipe can deliver EPIPE but not
// a controlled partial-then-fail sequence (the 65-byte result fits in the
// pipe buffer as one write), and exercising ENOSPC would otherwise require
// a genuinely full filesystem. Overriding write() makes "N bytes accepted,
// then the next write fails with a chosen errno" deterministic.
//
// Behaviour is controlled through environment variables:
//   MESSAGETAG_WRITE_FAULT_FD     fd to fault on (default 1 = stdout)
//   MESSAGETAG_WRITE_FAULT_AFTER  number of bytes to deliver to that fd
//                                 before writes start failing
//   MESSAGETAG_WRITE_FAULT_ERRNO  errno for the failure (default EPIPE,
//                                 e.g. 28 for ENOSPC, 5 for EIO)
//
// Only writes to the chosen fd are affected: the failure diagnostic that
// messagetag subsequently writes to stderr (fd 2) passes through untouched,
// so the test can still observe it. Every other fd is written normally.
// Bytes up to the allowed total are delivered through the real write()
// (shortened as needed so the boundary lands mid-write); the next write
// returns -1 with the configured errno and keeps doing so.
//
// This is Linux-specific in spirit but only relies on POSIX write(2) and
// dlsym; it builds on any platform the suite builds the read shim on.

#if defined(__linux__)

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

namespace {

using WriteFn = ssize_t (*)(int, const void*, size_t);

WriteFn realWrite = nullptr;
int targetFd = 1;
long failAfter = -1;   // -1 => shim inert (no fault configured)
int faultErrno = EPIPE;
long delivered = 0;

void init() {
    if (realWrite != nullptr) {
        return;
    }
    realWrite = reinterpret_cast<WriteFn>(dlsym(RTLD_NEXT, "write"));
    const char* fdEnv = getenv("MESSAGETAG_WRITE_FAULT_FD");
    if (fdEnv != nullptr && fdEnv[0] != '\0') {
        targetFd = atoi(fdEnv);
    }
    const char* after = getenv("MESSAGETAG_WRITE_FAULT_AFTER");
    if (after != nullptr) {
        failAfter = atol(after);
    }
    const char* err = getenv("MESSAGETAG_WRITE_FAULT_ERRNO");
    if (err != nullptr && err[0] != '\0') {
        faultErrno = atoi(err);
    }
}

}  // namespace

extern "C" ssize_t write(int fd, const void* buf, size_t count) {
    init();
    if (realWrite == nullptr) {
        errno = ENOSYS;
        return -1;
    }
    if (failAfter >= 0 && fd == targetFd) {
        if (delivered >= failAfter) {
            errno = faultErrno;
            return -1;
        }
        // Deliver no more than the remaining allowed prefix in this call;
        // the next write then fails. A short write(2) result is ordinary
        // and the caller is expected to continue with the rest.
        long remaining = failAfter - delivered;
        if (static_cast<long>(count) > remaining) {
            count = static_cast<size_t>(remaining);
        }
        ssize_t got = realWrite(fd, buf, count);
        if (got > 0) {
            delivered += got;
        }
        return got;
    }
    return realWrite(fd, buf, count);
}

#else  // !defined(__linux__)

// Empty translation unit off Linux, mirroring read_fault_shim.cpp.

#endif
