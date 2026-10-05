// Test-only fault-injection shim, preloaded into the messagetag process by
// the regression suite (tests/regression_test.py) to simulate a read(2)
// failure that happens *after* part of the message file has already been
// read successfully. Neither a missing file nor an unreadable-permission
// file can produce that situation: both fail at open time. Overriding
// read() is what lets the tests reach the "open succeeded, some bytes
// delivered, then the read fails" path deterministically, without relying
// on the account's permissions or on special filesystems.
//
// Behaviour is controlled through environment variables:
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
// This is Linux-specific (it identifies the target file through
// /proc/self/fd); on other platforms it compiles to a pass-through and the
// regression suite skips the fault-injection test.

#if defined(__linux__)

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
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
}

// Does fd refer to the file the fault is configured for? Resolved through
// /proc/self/fd so library/loader reads of unrelated files are untouched.
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
