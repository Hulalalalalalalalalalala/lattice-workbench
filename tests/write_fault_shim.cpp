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
// A second, scripted mode covers *recoverable* output trouble -- short
// writes and transient EINTRs interleaved with progress, optionally ending
// in a permanent error -- which the AFTER/ERRNO mode cannot express:
//   MESSAGETAG_WRITE_FAULT_SCRIPT comma-separated steps, consumed one per
//                                 write() to the target fd:
//                                   <N>    deliver at most N bytes of this
//                                          write (an ordinary short write)
//                                   EINTR  fail this write with EINTR (the
//                                          caller is expected to retry)
//                                   EPIPE / ENOSPC / EIO
//                                          fail with that errno and keep
//                                          failing every later write the
//                                          same way (a permanent error)
//                                 Once the script is exhausted, writes pass
//                                 through to the real write() untouched.
//                                 When set (and non-empty) the script takes
//                                 precedence over AFTER/ERRNO.
//   MESSAGETAG_WRITE_FAULT_TRACE  optional file path; in script mode every
//                                 intercepted write appends one line to it:
//                                 "D<n>" (n bytes delivered), "E<n>" (write
//                                 failed with errno n) or "P<n>" (n bytes
//                                 passed through after the script ended).
//                                 The suite uses this to prove the scripted
//                                 interruptions really happened, in order,
//                                 instead of the shim being silently inert.
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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

namespace {

using WriteFn = ssize_t (*)(int, const void*, size_t);

WriteFn realWrite = nullptr;
int targetFd = 1;
long failAfter = -1;   // -1 => shim inert (no fault configured)
int faultErrno = EPIPE;
long delivered = 0;

// Scripted mode: one step consumed per write() to the target fd.
enum class StepKind { kDeliver, kFail, kLatch };

struct Step {
    StepKind kind;
    long arg;   // kDeliver: max bytes to deliver; kFail/kLatch: errno
};

constexpr size_t kMaxSteps = 256;
Step steps[kMaxSteps];
size_t stepCount = 0;
size_t stepPos = 0;
bool latched = false;
int latchErrno = EPIPE;
int traceFd = -1;

int errnoForName(const char* name) {
    if (strcmp(name, "EINTR") == 0) return EINTR;
    if (strcmp(name, "EPIPE") == 0) return EPIPE;
    if (strcmp(name, "ENOSPC") == 0) return ENOSPC;
    if (strcmp(name, "EIO") == 0) return EIO;
    return 0;
}

void parseScript(const char* spec) {
    char buf[1024];
    size_t len = strlen(spec);
    if (len >= sizeof(buf)) {
        len = sizeof(buf) - 1;
    }
    memcpy(buf, spec, len);
    buf[len] = '\0';
    char* save = nullptr;
    for (char* tok = strtok_r(buf, ",", &save);
         tok != nullptr && stepCount < kMaxSteps;
         tok = strtok_r(nullptr, ",", &save)) {
        bool numeric = tok[0] >= '0' && tok[0] <= '9';
        for (const char* p = tok; numeric && *p != '\0'; ++p) {
            numeric = *p >= '0' && *p <= '9';
        }
        if (numeric) {
            steps[stepCount++] = Step{StepKind::kDeliver, atol(tok)};
            continue;
        }
        int err = errnoForName(tok);
        if (err == 0) {
            continue;   // unknown token: ignore rather than misfire
        }
        // EINTR is transient (the caller retries); the named permanent
        // errors latch so every later write fails the same way.
        StepKind kind =
            (err == EINTR) ? StepKind::kFail : StepKind::kLatch;
        steps[stepCount++] = Step{kind, err};
    }
}

void traceLog(char kind, long value) {
    if (traceFd < 0 || realWrite == nullptr) {
        return;
    }
    char line[32];
    int n = snprintf(line, sizeof(line), "%c%ld\n", kind, value);
    if (n > 0) {
        realWrite(traceFd, line, static_cast<size_t>(n));
    }
}

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
    const char* script = getenv("MESSAGETAG_WRITE_FAULT_SCRIPT");
    if (script != nullptr && script[0] != '\0') {
        parseScript(script);
    }
    const char* trace = getenv("MESSAGETAG_WRITE_FAULT_TRACE");
    if (trace != nullptr && trace[0] != '\0') {
        traceFd = open(trace, O_WRONLY | O_CREAT | O_APPEND, 0644);
    }
}

}  // namespace

extern "C" ssize_t write(int fd, const void* buf, size_t count) {
    init();
    if (realWrite == nullptr) {
        errno = ENOSYS;
        return -1;
    }
    if (stepCount > 0 && fd == targetFd) {
        if (latched) {
            errno = latchErrno;
            return -1;
        }
        if (stepPos < stepCount) {
            Step step = steps[stepPos++];
            if (step.kind == StepKind::kFail) {
                errno = static_cast<int>(step.arg);
                traceLog('E', step.arg);
                return -1;
            }
            if (step.kind == StepKind::kLatch) {
                latched = true;
                latchErrno = static_cast<int>(step.arg);
                errno = latchErrno;
                traceLog('E', step.arg);
                return -1;
            }
            // kDeliver: hand the caller at most the scripted byte count --
            // a short write(2) result it is expected to continue from.
            if (static_cast<long>(count) > step.arg) {
                count = static_cast<size_t>(step.arg);
            }
            ssize_t got = realWrite(fd, buf, count);
            traceLog(got >= 0 ? 'D' : 'E', got >= 0 ? got : errno);
            return got;
        }
        // Script exhausted: the fd behaves normally again.
        ssize_t got = realWrite(fd, buf, count);
        traceLog(got >= 0 ? 'P' : 'E', got >= 0 ? got : errno);
        return got;
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
