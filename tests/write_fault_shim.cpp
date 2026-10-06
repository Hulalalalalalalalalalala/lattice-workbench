// Test-only fault-injection shim, preloaded into the messagetag process by
// the regression suite (tests/regression_test.py) to simulate a write(2)
// failure on standard output that happens *after part of the result line has
// already been delivered*. Neither /dev/full nor a closed reading pipe can
// produce that exact situation on demand across buffering layouts:
// /dev/full fails every write with ENOSPC, and a closed pipe may fail on the
// first write depending on how much the stream buffer held. Overriding
// write() for fd 1 is what lets the tests reach the "some result bytes are
// already with the recipient, then the output fails" path deterministically,
// without relying on a small filesystem or special device permissions.
//
// Behaviour is controlled through environment variables:
//   MESSAGETAG_WRITE_FAULT_AFTER  number of bytes to deliver to fd 1 before
//                                 the first failing write (default 0, so the
//                                 first write fails); writes past the
//                                 allowance are shortened and the remainder
//                                 fails on the next call
//   MESSAGETAG_WRITE_FAULT_ERRNO  optional errno for the failure
//                                 (default EIO)
//
// Only file descriptor 1 (standard output) is affected: the diagnostic on
// standard error and every other write in the process pass through
// untouched. Once the allowance is exhausted, every subsequent write to
// fd 1 returns -1 with the configured errno.
//
// This is Linux-specific in the same way as the read-fault shim; on other
// platforms it compiles to a pass-through and the regression suite skips the
// fault-injection test.

#if defined(__linux__)

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

namespace {

using WriteFn = ssize_t (*)(int, const void*, size_t);

WriteFn realWrite = nullptr;
long failAfter = 0;
int faultErrno = EIO;
long delivered = 0;
bool initialized = false;

void init() {
    if (initialized) {
        return;
    }
    initialized = true;
    realWrite = reinterpret_cast<WriteFn>(dlsym(RTLD_NEXT, "write"));
    const char* after = getenv("MESSAGETAG_WRITE_FAULT_AFTER");
    failAfter = (after != nullptr) ? atol(after) : 0;
    if (failAfter < 0) {
        failAfter = 0;
    }
    const char* err = getenv("MESSAGETAG_WRITE_FAULT_ERRNO");
    if (err != nullptr) {
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
    // Standard output alone is faulted; fd 2 (the failure diagnostic) and
    // any unrelated descriptor must behave normally.
    if (fd == 1 && failAfter >= 0) {
        if (delivered >= failAfter) {
            errno = faultErrno;
            return -1;
        }
        // Deliver no more than the allowed prefix; the next write attempt
        // (which retries the remainder, or flushes more of the line) hits
        // the failing branch above.
        if (count > static_cast<size_t>(failAfter - delivered)) {
            count = static_cast<size_t>(failAfter - delivered);
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

// Empty translation unit off Linux: the shim exports nothing, and the
// regression suite only runs the fault-injection test on Linux.

#endif
