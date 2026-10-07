// Test-only fault-injection shim, preloaded into the messagetag process by
// the regression suite (tests/regression_test.py). It serves two purposes
// that ordinary files and pipes cannot arrange:
//
// 1. Simulate a read(2) failure that happens *after* part of the message
//    file has already been read successfully. Neither a missing file nor an
//    unreadable-permission file can produce that situation: both fail at
//    open time. Overriding read() lets the tests reach the "open
//    succeeded, some bytes delivered, then the read failed" path
//    deterministically, without relying on the account's permissions or on
//    special filesystems.
// 2. Replay *recoverable* read trouble -- short reads and transient
//    EINTRs, optionally followed by a permanent error -- against standard
//    input. Mere delay or sending bytes in installments cannot stand in for
//    that event: no pipe scheduling ever makes read(2) return -1/EINTR, and
//    the program must retry after EINTR instead of ending the message.
//
// There are two modes, selected through environment variables.
//
// Path mode (the original one):
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
// Scripted mode replays a fixed per-read(2) script against one chosen
// descriptor. This is the mode the standard-input EINTR-recovery tests
// use:
//   MESSAGETAG_READ_FAULT_FD      descriptor to run the script against
//                                (default 0 = standard input)
//   MESSAGETAG_READ_FAULT_SCRIPT  comma-separated steps, consumed one per
//                                read() on the target fd:
//                                  <N>    make this read(2) return
//                                         exactly N bytes, accumulating
//                                         across as many underlying
//                                         reads as the pipe size and
//                                         send timing require (the
//                                         caller sees one ordinary
//                                         blocking read that returns N;
//                                         N must not exceed the
//                                         caller's buffer)
//                                  EINTR  fail this read with EINTR (the
//                                         caller is expected to retry)
//                                  EIO / EPIPE / EBADF
//                                         fail with that errno and keep
//                                         failing every later read the
//                                         same way (a permanent error)
//                                Once the script is exhausted, reads of
//                                the target fd pass through to the real
//                                read() untouched. When set (and
//                                non-empty) the script takes precedence
//                                over PATH/AFTER.
//   MESSAGETAG_READ_FAULT_TRACE   optional file path; in scripted mode
//                                every intercepted read of the target fd
//                                appends one line:
//                                  "R<n>"  n bytes delivered (short read)
//                                  "E<n>"  read failed with errno n
//                                  "P<n>"  n bytes passed through after
//                                          the script ended
//                                The suite uses this to prove the
//                                scripted interruptions really happened,
//                                in call order, instead of the shim being
//                                silently inert.
//
// Scripted mode targets a descriptor number, not a path: the standard
// input inherited from the test is a pipe, whose /proc/self/fd link does
// not name any file on disk that PATH could match.
//
// This is Linux-specific (path mode identifies the target file through
// /proc/self/fd); on other platforms it compiles to a pass-through and the
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
const char* targetPath = nullptr;
long failAfter = 0;
int faultErrno = EIO;
long delivered = 0;

// Scripted mode: one step consumed per read() on the target descriptor.
enum class StepKind { kRead, kFail, kLatch };

struct Step {
    StepKind kind;
    long arg;   // kRead: at most this many bytes; kFail/kLatch: errno
};

constexpr size_t kMaxSteps = 256;
Step steps[kMaxSteps];
size_t stepCount = 0;
size_t stepPos = 0;
bool scriptConfigured = false;
int targetFd = 0;
bool latched = false;
int latchErrno = EIO;
int traceFd = -1;

int errnoForName(const char* name) {
    if (strcmp(name, "EINTR") == 0) return EINTR;
    if (strcmp(name, "EIO") == 0) return EIO;
    if (strcmp(name, "EPIPE") == 0) return EPIPE;
    if (strcmp(name, "EBADF") == 0) return EBADF;
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
            steps[stepCount++] = Step{StepKind::kRead, atol(tok)};
            continue;
        }
        int err = errnoForName(tok);
        if (err == 0) {
            continue;   // unknown token: ignore rather than misfire
        }
        // EINTR is transient (the caller retries the read); the named
        // permanent errors latch so every later read fails the same way.
        StepKind kind =
            (err == EINTR) ? StepKind::kFail : StepKind::kLatch;
        steps[stepCount++] = Step{kind, err};
    }
}

void traceLog(char kind, long value) {
    if (traceFd < 0 || realRead == nullptr) {
        return;
    }
    char line[32];
    int n = snprintf(line, sizeof(line), "%c%ld\n", kind, value);
    if (n > 0) {
        // Trace lines go through the real write(2); this shim does not
        // override write(), so the call cannot recurse back through it.
        ssize_t w = ::write(traceFd, line, static_cast<size_t>(n));
        (void)w;
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
    // Scripted mode takes precedence over the path/AFTER mode.
    const char* fdEnv = getenv("MESSAGETAG_READ_FAULT_FD");
    if (fdEnv != nullptr && fdEnv[0] != '\0') {
        targetFd = atoi(fdEnv);
    }
    const char* script = getenv("MESSAGETAG_READ_FAULT_SCRIPT");
    if (script != nullptr && script[0] != '\0') {
        parseScript(script);
        scriptConfigured = stepCount > 0;
    }
    const char* trace = getenv("MESSAGETAG_READ_FAULT_TRACE");
    if (trace != nullptr && trace[0] != '\0') {
        traceFd = open(trace, O_WRONLY | O_CREAT | O_APPEND, 0644);
    }
}

// Does fd refer to the file the path-mode fault is configured for?
// Resolved through /proc/self/fd so library/loader reads of unrelated
// files are untouched.
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

}  // namespace

extern "C" ssize_t read(int fd, void* buf, size_t count) {
    init();
    if (realRead == nullptr) {
        errno = ENOSYS;
        return -1;
    }
    if (scriptConfigured && fd == targetFd) {
        if (latched) {
            errno = latchErrno;
            traceLog('E', latchErrno);
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
            // kRead: hand the caller EXACTLY the scripted byte count in
            // this one read(2), accumulating across as many underlying
            // reads as the pipe size and send timing require. A blocking
            // read naturally waits for the bytes, so making one read(2)
            // return N is indistinguishable to the caller from the
            // kernel waiting until N bytes happen to be available; it is
            // what lets a scripted step be deterministic on pipes whose
            // capacity is smaller than N. A clean EOF first ends the
            // accumulation with whatever arrived; an underlying EINTR is
            // retried here (it is not a scripted step), any other error
            // is passed through. Exactly one R<n> line is logged for the
            // whole accumulation.
            if (step.arg > 0) {
                size_t want = static_cast<size_t>(step.arg);
                if (want > count) {
                    want = count;  // never overrun the caller's buffer
                }
                size_t have = 0;
                int underlying = 0;
                while (have < want) {
                    ssize_t got = realRead(fd, static_cast<char*>(buf) + have,
                                           want - have);
                    if (got > 0) {
                        have += static_cast<size_t>(got);
                        continue;
                    }
                    if (got == 0) {
                        break;  // EOF: deliver the short remainder
                    }
                    if (errno == EINTR) {
                        continue;
                    }
                    underlying = errno;
                    break;
                }
                if (underlying != 0) {
                    errno = underlying;
                    traceLog('E', underlying);
                    return -1;
                }
                traceLog('R', static_cast<long>(have));
                return static_cast<ssize_t>(have);
            }
            ssize_t got = realRead(fd, buf, count);
            traceLog(got >= 0 ? 'R' : 'E',
                     got >= 0 ? got : errno);
            return got;
        }
        // Script exhausted: the descriptor behaves normally again.
        ssize_t got = realRead(fd, buf, count);
        traceLog(got >= 0 ? 'P' : 'E',
                 got >= 0 ? got : errno);
        return got;
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
// regression suite only runs the fault-injection tests where /proc/self/fd
// exists, so the unused library is harmless.

#endif
