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
// The three variables above drive the legacy "deliver a prefix, then fail
// forever" mode. A second, scripted mode
//   MESSAGETAG_WRITE_FAULT_SCRIPT ordered, comma-separated events, one per
//                                 write(2) call on the target fd, exercises
//                                 *recoverable* output conditions:
//                                   eintr       this call returns -1/EINTR
//                                   short:<n>   this call accepts at most n
//                                               bytes (a short write)
//                                   fail:<errno> this call (and every later
//                                               one) fails with that errno
//                                   pass (or ok) this call passes through to
//                                               the real write()
//                                 Once the script is exhausted writes pass
//                                 through normally forever, so a finite run
//                                 of eintr/short events models a writer that
//                                 temporarily cannot accept the whole line
//                                 and later accepts the remainder. A fail
//                                 event after some eintr/short events models
//                                 a permanent error that arrives only after
//                                 the recoverable stretch. SCRIPT takes
//                                 precedence over AFTER when both are set.
//
// Only writes to the chosen fd are affected: the failure diagnostic that
// messagetag subsequently writes to stderr (fd 2) passes through untouched,
// so the test can still observe it. Every other fd is written normally.
// In AFTER mode bytes up to the allowed total are delivered through the
// real write() (shortened as needed so the boundary lands mid-write); the
// next write returns -1 with the configured errno and keeps doing so.
// In SCRIPT mode bytes of every short/pass event go through the real
// write() in their original order, so a writer that continues a short
// write and retries after EINTR delivers the line exactly once, byte for
// byte; the prefix already accepted is never replayed by the shim.
//
// This is Linux-specific in spirit but only relies on POSIX write(2) and
// dlsym; it builds on any platform the suite builds the read shim on.

#if defined(__linux__)

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <string>
#include <vector>

namespace {

using WriteFn = ssize_t (*)(int, const void*, size_t);

WriteFn realWrite = nullptr;
int targetFd = 1;
long failAfter = -1;   // -1 => shim inert (no fault configured)
int faultErrno = EPIPE;
long delivered = 0;

// Scripted mode: one event consumed per write(2) call on the target fd.
enum EventType { kEventPass, kEventShort, kEventEintr, kEventFail };
struct Event {
    EventType type;
    long value;  // kEventShort: max bytes accepted; kEventFail: errno
};

std::vector<Event> scriptEvents;
bool scriptMode = false;
std::size_t scriptIndex = 0;
bool permanentFailure = false;
int permanentErrno = EPIPE;

// Parse a "name:number" token; returns false when the prefix does not match
// or no non-empty number follows.
bool matchNumbered(const char* token, const char* prefix, long& value) {
    std::size_t prefixLen = strlen(prefix);
    if (strncmp(token, prefix, prefixLen) != 0 || token[prefixLen] == '\0') {
        return false;
    }
    value = atol(token + prefixLen);
    return true;
}

void parseScript(const char* spec) {
    // Split on commas without mutating the environment string.
    std::string specStr(spec);
    std::size_t pos = 0;
    while (pos <= specStr.size()) {
        std::size_t comma = specStr.find(',', pos);
        std::string token = specStr.substr(
            pos, comma == std::string::npos ? std::string::npos
                                            : comma - pos);
        long number = 0;
        if (token == "eintr") {
            scriptEvents.push_back({kEventEintr, 0});
        } else if (token == "pass" || token == "ok") {
            scriptEvents.push_back({kEventPass, 0});
        } else if (matchNumbered(token.c_str(), "short:", number)) {
            // A cap of 0 would surface as a zero-length write that the
            // program treats as failure; the recoverable-write tests only
            // use positive caps.
            scriptEvents.push_back({kEventShort, number});
        } else if (matchNumbered(token.c_str(), "fail:", number)) {
            scriptEvents.push_back({kEventFail, number});
        }
        if (comma == std::string::npos) {
            break;
        }
        pos = comma + 1;
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
    const char* script = getenv("MESSAGETAG_WRITE_FAULT_SCRIPT");
    if (script != nullptr && script[0] != '\0') {
        parseScript(script);
        scriptMode = !scriptEvents.empty();
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
    if (fd != targetFd) {
        return realWrite(fd, buf, count);
    }
    if (scriptMode) {
        if (permanentFailure) {
            errno = permanentErrno;
            return -1;
        }
        Event event = {kEventPass, 0};
        if (scriptIndex < scriptEvents.size()) {
            event = scriptEvents[scriptIndex++];
        }
        // Past the last event every further write passes through: the
        // temporary trouble is over and the remaining line must complete.
        switch (event.type) {
            case kEventEintr:
                // Nothing is delivered; a correct writer retries the very
                // same bytes with the next call.
                errno = EINTR;
                return -1;
            case kEventFail:
                // Sticky: this call and every later one fail permanently.
                permanentFailure = true;
                permanentErrno = static_cast<int>(event.value);
                errno = permanentErrno;
                return -1;
            case kEventShort:
                if (event.value > 0 &&
                    static_cast<long>(count) > event.value) {
                    count = static_cast<size_t>(event.value);
                }
                return realWrite(fd, buf, count);
            case kEventPass:
                return realWrite(fd, buf, count);
        }
        // Unreachable: every event type returns above.
        return realWrite(fd, buf, count);
    }
    if (failAfter >= 0) {
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
