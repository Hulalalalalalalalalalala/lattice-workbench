// Test-only fault-injection shim, preloaded into the messagetag process by
// the regression suite (tests/regression_test.py). It serves two purposes.
//
// 1. Simulate a read(2) failure that happens *after* part of the message
//    file has already been read successfully. Neither a missing file nor an
//    unreadable-permission file can produce that situation: both fail at
//    open time. Overriding read() is what lets the tests reach the "open
//    succeeded, some bytes delivered, then the read failed" path
//    deterministically, without relying on the account's permissions or on
//    special filesystems.
//
// 2. Replay *recoverable* read trouble -- transient EINTRs interleaved with
//    bounded (short) reads, optionally ending in a permanent error -- which
//    the AFTER/ERRNO mode cannot express, so the suite can pin "read
//    interrupted, retried, and the complete message still authenticated",
//    including an interruption before the first message byte and one after a
//    non-empty prefix.
//
// Legacy behaviour is controlled through environment variables:
//   MESSAGETAG_READ_FAULT_PATH   absolute path of the file to fault on;
//                                every other file is read normally
//   MESSAGETAG_READ_FAULT_AFTER  number of bytes to deliver before the
//                                first failing read (must be > 0 so a
//                                non-empty prefix has already been read)
//   MESSAGETAG_READ_FAULT_ERRNO  optional errno for the failure
//                                (default EIO)
//
// The failing read returns -1 once the allowed prefix has been delivered;
// every subsequent read of that file fails the same way.
//
// The second, scripted mode is selected by a non-empty
// MESSAGETAG_READ_FAULT_SCRIPT and takes precedence over the legacy
// variables:
//   MESSAGETAG_READ_FAULT_FD      fd the script applies to (default 0 =
//                                 standard input); every other fd is read
//                                 normally. With "--file -" the test hands
//                                 the message file over as fd 0, so reads
//                                 are deterministic like any regular file.
//   MESSAGETAG_READ_FAULT_SCRIPT  comma-separated steps, consumed one per
//                                 read() of the target fd:
//                                   <N>    bound this read to at most N
//                                          bytes (an ordinary short read;
//                                          whatever the underlying read
//                                          returns -- some bytes, or 0 at
//                                          EOF -- is passed through)
//                                   PASS   leave this read completely
//                                          untouched (one read slot passes
//                                          through with its original count)
//                                   EINTR  fail this read with EINTR (the
//                                          caller is expected to retry)
//                                   EPIPE / ENOSPC / EIO
//                                          fail with that errno and keep
//                                          failing every later read the
//                                          same way (a permanent error)
//                                 Once the script is exhausted, reads pass
//                                 through to the real read() untouched.
//   MESSAGETAG_READ_FAULT_TRACE   optional file path; in script mode every
//                                 intercepted read appends one line to it:
//                                 "D<n>" (n bytes delivered), "E<n>" (read
//                                 failed with errno n) or "P<n>" (n bytes
//                                 delivered by a read that passed through
//                                 after the script ended). The suite uses
//                                 this to prove the scripted interruptions
//                                 really happened, in order, instead of the
//                                 shim being silently inert.
//
// This is Linux-specific for the legacy mode (it identifies the target file
// through /proc/self/fd); the scripted mode only needs POSIX read(2) and
// dlsym. On other platforms this file compiles to a pass-through and the
// regression suite skips the fault-injection tests.

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

using ReadFn = ssize_t (*)(int, void*, size_t);

ReadFn realRead = nullptr;

// --- legacy PATH/AFTER/ERRNO mode -----------------------------------------
const char* targetPath = nullptr;
long failAfter = 0;
int faultErrno = EIO;
long delivered = 0;

// --- scripted mode ---------------------------------------------------------
int targetFd = 0;

enum class StepKind { kDeliver, kPass, kFail, kLatch };

struct Step {
    StepKind kind;
    long arg;   // kDeliver: max bytes; kFail/kLatch: errno; else unused
};

constexpr size_t kMaxSteps = 256;
Step steps[kMaxSteps];
size_t stepCount = 0;
size_t stepPos = 0;
bool latched = false;
int latchErrno = EIO;
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
            // Only a positive bound is useful: a read bound to 0 bytes
            // would report EOF, so treat "0" like any other unknown token
            // and ignore it rather than misfire.
            long n = atol(tok);
            if (n > 0) {
                steps[stepCount++] = Step{StepKind::kDeliver, n};
            }
            continue;
        }
        if (strcmp(tok, "PASS") == 0) {
            steps[stepCount++] = Step{StepKind::kPass, 0};
            continue;
        }
        int err = errnoForName(tok);
        if (err == 0) {
            continue;   // unknown token: ignore rather than misfire
        }
        // EINTR is transient (the caller retries); the named permanent
        // errors latch so every later read fails the same way.
        StepKind kind =
            (err == EINTR) ? StepKind::kFail : StepKind::kLatch;
        steps[stepCount++] = Step{kind, err};
    }
}

void traceLog(char kind, long value) {
    if (traceFd < 0) {
        return;
    }
    char line[32];
    int n = snprintf(line, sizeof(line), "%c%ld\n", kind, value);
    if (n > 0) {
        // This shim overrides read() only, so plain write() reaches libc
        // untouched; the trace file is a different fd regardless.
        ssize_t w = 0;
        while (w < n) {
            ssize_t got = write(traceFd, line + w,
                                static_cast<size_t>(n - w));
            if (got < 0 && errno == EINTR) {
                continue;
            }
            if (got <= 0) {
                break;
            }
            w += got;
        }
    }
}

void init() {
    if (realRead != nullptr) {
        return;
    }
    realRead = reinterpret_cast<ReadFn>(dlsym(RTLD_NEXT, "read"));
    targetPath = getenv("MESSAGETAG_READ_FAULT_PATH");
    const char* after = getenv("MESSAGETAG_READ_FAULT_AFTER");
    failAfter = (after != nullptr) ? atol(after) : 0;
    const char* err = getenv("MESSAGETAG_READ_FAULT_ERRNO");
    if (err != nullptr) {
        faultErrno = atoi(err);
    }
    const char* fdEnv = getenv("MESSAGETAG_READ_FAULT_FD");
    if (fdEnv != nullptr && fdEnv[0] != '\0') {
        targetFd = atoi(fdEnv);
    }
    const char* script = getenv("MESSAGETAG_READ_FAULT_SCRIPT");
    if (script != nullptr && script[0] != '\0') {
        parseScript(script);
    }
    const char* trace = getenv("MESSAGETAG_READ_FAULT_TRACE");
    if (trace != nullptr && trace[0] != '\0') {
        traceFd = open(trace, O_WRONLY | O_CREAT | O_APPEND, 0644);
    }
}

// Does fd refer to the file the legacy fault is configured for? Resolved
// through /proc/self/fd so library/loader reads of unrelated files are
// untouched.
bool isTarget(int fd) {
    if (targetPath == nullptr || targetPath[0] == '\0') {
        return false;
    }
    char link[64];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    char path[4096];
    ssize_t len = readlink(link, path, sizeof(path) - 1);
    if (len <= 0) {
        return false;
    }
    path[len] = '\0';
    return strcmp(path, targetPath) == 0;
}

// Scripted mode for the chosen fd: one step per intercepted read.
ssize_t scriptedRead(int fd, void* buf, size_t count) {
    if (latched) {
        errno = latchErrno;
        return -1;
    }
    if (stepPos < stepCount) {
        Step step = steps[stepPos++];
        if (step.kind == StepKind::kFail) {
            errno = EINTR;
            traceLog('E', EINTR);
            return -1;
        }
        if (step.kind == StepKind::kLatch) {
            latched = true;
            latchErrno = static_cast<int>(step.arg);
            errno = latchErrno;
            traceLog('E', latchErrno);
            return -1;
        }
        if (step.kind == StepKind::kDeliver) {
            // Bound the read to the scripted byte count -- a short read(2)
            // result the caller is expected to continue from. A regular
            // file handed over as fd 0 returns exactly the requested count
            // up to EOF; whatever the underlying read reports is genuine.
            if (static_cast<long>(count) > step.arg) {
                count = static_cast<size_t>(step.arg);
            }
            ssize_t got = realRead(fd, buf, count);
            traceLog(got >= 0 ? 'D' : 'E', got >= 0 ? got : errno);
            return got;
        }
        // kPass: leave the caller's count untouched and log the read as a
        // pass-through, exactly like reads after the script is exhausted.
        ssize_t got = realRead(fd, buf, count);
        traceLog(got >= 0 ? 'P' : 'E', got >= 0 ? got : errno);
        return got;
    }
    // Script exhausted: the fd behaves normally again.
    ssize_t got = realRead(fd, buf, count);
    traceLog(got >= 0 ? 'P' : 'E', got >= 0 ? got : errno);
    return got;
}

}  // namespace

extern "C" ssize_t read(int fd, void* buf, size_t count) {
    init();
    if (realRead == nullptr) {
        errno = ENOSYS;
        return -1;
    }
    // The scripted mode is selected explicitly (a non-empty script that
    // parsed to at least one step) and targets a fixed fd.
    if (stepCount > 0 && fd == targetFd) {
        return scriptedRead(fd, buf, count);
    }
    if (failAfter > 0 && isTarget(fd)) {
        if (delivered >= failAfter) {
            errno = faultErrno;
            return -1;
        }
        // Shorten the read so no more than the allowed prefix is delivered;
        // a short read(2) result is normal and the caller will retry, at
        // which point the branch above reports the failure.
        if (count > static_cast<size_t>(failAfter - delivered)) {
            count = static_cast<size_t>(failAfter - delivered);
        }
        ssize_t got = realRead(fd, buf, count);
        if (got > 0) {
            delivered += got;
        }
        return got;
    }
    return realRead(fd, buf, count);
}

#else  // !defined(__linux__)

// Empty translation unit off Linux: the shim exports nothing, and the
// regression suite only runs the fault-injection test where /proc/self/fd
// exists, so the unused library is harmless.

#endif
