// The low-level HMAC functions (HMAC_CTX_new/HMAC_Init_ex/HMAC_Update/
// HMAC_Final) are available in both OpenSSL 1.1.1 and OpenSSL 3.x.
// OpenSSL 3.x marks them deprecated in favour of the EVP_MAC interface
// (which 1.1.1 does not have); suppress those deprecation warnings so the
// portable interface builds cleanly on 3.x. The streaming Init/Update/
// Final form lets the message (file or standard input) be digested in
// fixed-size chunks instead of being held in memory all at once.
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <array>
#include <cerrno>
#include <cstddef>
#include <csignal>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <unistd.h>

namespace {

constexpr std::string_view kTagUsage =
    "Usage: messagetag tag --key-hex <hex-key> --file <message-file|->\n";

constexpr std::string_view kVerifyUsage =
    "Usage: messagetag verify --key-hex <hex-key> --file <message-file|-> "
    "--tag-hex <hex-tag>\n";

// A --file value of exactly this single character selects standard input:
// every byte read from file descriptor 0 until its normal end is the one
// message. Anything else (including "./-", an absolute path ending in "/-"
// or a value with surrounding characters) is a plain file path, so a real
// file named "-" stays reachable.
constexpr std::string_view kStdinFile = "-";

// Per-command identity for the shared option/prepare/authenticate flow:
// the name spliced into diagnostics, that command's own usage line and
// exactly the value-taking options it accepts. Whether a token following
// an option counts as "missing a value" is decided against this list, so
// each command keeps judging missing values by its own option set and a
// diagnostic for one command never carries the other command's usage.
struct CommandSpec {
    std::string_view name;
    std::string_view usage;
    std::vector<std::string_view> options;
};

const CommandSpec& tagSpec() {
    static const CommandSpec spec{
        "tag", kTagUsage, {"--key-hex", "--file"}};
    return spec;
}

const CommandSpec& verifySpec() {
    static const CommandSpec spec{
        "verify", kVerifyUsage,
        {"--key-hex", "--file", "--tag-hex"}};
    return spec;
}

// SHA-256 HMAC tags are always 32 bytes / 64 hex characters.
constexpr std::size_t kTagBytes = 32;

// Decode hexadecimal into raw bytes: every two characters are one byte and
// leading zeros must be preserved (e.g. "0001" is two bytes, not the number
// 1). Only digits and a-f/A-F are accepted; empty input, odd length,
// whitespace and a 0x prefix are rejected.
bool decodeHex(std::string_view hex, std::vector<unsigned char>& bytes) {
    if (hex.empty() || hex.size() % 2 != 0) {
        return false;
    }
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    bytes.clear();
    bytes.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        int hi = nibble(hex[i]);
        int lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            return false;
        }
        bytes.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }
    return true;
}

std::string hexEncode(const unsigned char* data, std::size_t length) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.resize(length * 2);
    for (std::size_t i = 0; i < length; ++i) {
        out[2 * i] = kHex[data[i] >> 4];
        out[2 * i + 1] = kHex[data[i] & 0x0F];
    }
    return out;
}

// Write every byte of the one-line success result to file descriptor 1.
// This deliberately bypasses std::cout: the write can fail while the
// stream buffer is flushed, i.e. after the program has already "printed"
// the whole line. A short write of the remaining bytes is continued (pipes
// and space-constrained files legitimately accept partial counts); only
// EINTR is retried after a failed call, so EPIPE/ENOSPC/EIO terminate the
// attempt immediately. Bytes already accepted by the kernel cannot be
// taken back and are not re-emitted.
bool writeAllFd(int fd, std::string_view data) {
    std::size_t written = 0;
    while (written < data.size()) {
        ssize_t n = ::write(fd, data.data() + written, data.size() - written);
        if (n > 0) {
            written += static_cast<std::size_t>(n);
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        return false;
    }
    return true;
}

// Output the single success line and make the exit code depend on it: a
// correctly computed tag, or a passed comparison, is not success unless
// the complete line (including the trailing newline) has actually reached
// standard output. On failure emits exactly one diagnostic that names the
// result-output stage -- never the key, the supplied tag or a recomputed
// tag -- and returns false so the caller exits 1. The errno text is saved
// before anything else can clobber errno.
bool emitResultLine(std::string_view command, std::string_view line) {
    if (writeAllFd(STDOUT_FILENO, line)) {
        return true;
    }
    int savedErrno = errno;
    // One single line, naming only the result-output stage. No key, tag or
    // recomputed tag is referenced, and no usage text follows.
    std::cerr << "messagetag " << command
              << ": error: standard output write failed while outputting "
                 "the result (" << std::strerror(savedErrno) << ")\n";
    return false;
}

// Parse options of the form "--name value" starting at argv[2]. On a usage
// problem (an unknown argument, or an option without a following value) a
// command-specific diagnostic and the usage line are written to stderr and
// this returns false; the caller then exits with code 2. On success the
// collected values are stored keyed by option name, and the caller checks
// which required options are present. Only the value-taking options named
// in `names` are accepted.
//
// An option's value is missing not only when nothing follows it, but also
// when the next token is itself one of this command's option names: in
// "--file --file" the second "--file" is another option, not a file name,
// so the first "--file" is reported as missing a value instead of
// consuming the option as its value. Only an exact match with a recognized
// option name triggers this; any other token (including one that merely
// starts with a dash, such as "--notes", and including an explicitly empty
// string) is taken as the value, so file paths with leading dashes stay
// usable and empty values keep their own distinct diagnostics.
bool parseValueOptions(const CommandSpec& spec, int argc, char* argv[],
                       std::map<std::string, std::string>& values) {
    auto isOptionName = [&spec](std::string_view arg) {
        for (std::string_view name : spec.options) {
            if (arg == name) {
                return true;
            }
        }
        return false;
    };
    for (int i = 2; i < argc; ++i) {
        std::string arg(argv[i]);
        if (!isOptionName(arg)) {
            std::cerr << "messagetag " << spec.name
                      << ": error: unknown argument '" << arg << "'\n"
                      << spec.usage;
            return false;
        }
        // The diagnostic names only the option that lacks a value; the
        // following token (a recognized option name, or nothing at all) is
        // never spliced into the message, and neither is any key or tag
        // material supplied elsewhere on the command line.
        if (i + 1 >= argc || isOptionName(argv[i + 1])) {
            std::cerr << "messagetag " << spec.name
                      << ": error: option '" << arg
                      << "' requires a value\n"
                      << spec.usage;
            return false;
        }
        values[arg] = argv[++i];
    }
    return true;
}

bool requireOption(const CommandSpec& spec,
                   const std::map<std::string, std::string>& values,
                   std::string_view name) {
    if (values.find(std::string(name)) == values.end()) {
        std::cerr << "messagetag " << spec.name
                  << ": error: missing required option '" << name << "'\n"
                  << spec.usage;
        return false;
    }
    return true;
}

// Decode the --key-hex argument, emitting the shared key-format diagnostic
// (which never echoes the submitted key) on failure.
bool parseKey(const CommandSpec& spec, const std::string& keyHex,
              std::vector<unsigned char>& key) {
    if (decodeHex(keyHex, key)) {
        return true;
    }
    std::cerr << "messagetag " << spec.name
              << ": error: invalid --key-hex: expected a non-empty, "
                 "even-length string of hexadecimal characters (0-9, a-f, A-F); "
                 "every two characters denote one key byte and leading zeros must "
                 "be kept; a 0x prefix and whitespace are not accepted\n"
              << spec.usage;
    return false;
}

// Stream a message into HMAC-SHA-256 a fixed-size chunk at a time. The
// message is never stored whole: regardless of its total length, only one
// 64 KiB read buffer is needed on top of the constant-size HMAC context.
// This holds for both a file and standard input, so a piped-in message can
// be arbitrarily large without memory use growing with its length.
//
// The bytes are not interpreted as text: the source is read in binary mode,
// trailing newlines are kept, line endings are not converted and zero bytes
// are preserved. An empty message (an empty file, or standard input that
// ends before any byte arrives) simply yields no Update calls, which
// authenticates the empty message.
enum class HmacStatus { kSuccess, kReadError, kCryptoError };

// Feed one already-read byte range into the context. Anything but a
// complete update is a crypto failure.
HmacStatus updateHmac(HMAC_CTX* ctx, const unsigned char* data,
                      std::size_t length) {
    if (length == 0) {
        return HmacStatus::kSuccess;
    }
    if (HMAC_Update(ctx, data, length) != 1) {
        return HmacStatus::kCryptoError;
    }
    return HmacStatus::kSuccess;
}

// Read loop shared by the file and standard-input sources: pull up to the
// buffer size per iteration and feed every byte that actually arrived,
// stopping only at the source's normal end. `readOnce` returns a positive
// byte count, 0 at the normal end, or -1 with errno set on a read error.
// A read error (including one that happens after a non-empty prefix has
// already been fed to HMAC) aborts authentication: the caller never calls
// Final, so no partial-message tag can be produced. EINTR from a read that
// delivered nothing is retried; a short read is ordinary and simply
// continues the loop, so how the bytes are split across arrivals cannot
// change the result. On a read error the failing errno is captured into
// `readErrno` straight away -- before any later teardown (e.g. freeing the
// HMAC context) can clobber it -- so the caller's diagnostic can state the
// reason.
template <typename ReadOnce>
HmacStatus streamHmac(HMAC_CTX* ctx, std::array<char, 65536>& buffer,
                      ReadOnce readOnce, int& readErrno) {
    while (true) {
        ssize_t got = readOnce(buffer.data(), buffer.size());
        if (got > 0) {
            HmacStatus update = updateHmac(
                ctx, reinterpret_cast<const unsigned char*>(buffer.data()),
                static_cast<std::size_t>(got));
            if (update != HmacStatus::kSuccess) {
                return update;
            }
            continue;
        }
        if (got == 0) {
            return HmacStatus::kSuccess;  // normal end of the message
        }
        int failedErrno = errno;
        if (failedErrno == EINTR) {
            continue;
        }
        readErrno = failedErrno;
        return HmacStatus::kReadError;
    }
}

// Stream either a file or standard input. When `fromStdin` is set, file
// descriptor 0 is read with read(2) directly rather than through a C++
// stream so read errors are observable (an std::ifstream cannot attach to
// fd 0 portably, and errno is what distinguishes a real failure from a
// clean EOF or an EINTR). No prompt is ever written and the message is
// read to its normal end before returning. On a read error `readErrno`
// receives the errno captured at the failing read.
HmacStatus hmacSha256Source(
    const std::vector<unsigned char>& key, bool fromStdin,
    const std::string& path,
    std::array<unsigned char, EVP_MAX_MD_SIZE>& mac,
    std::size_t& macLength, int& readErrno) {
    HMAC_CTX* rawCtx = HMAC_CTX_new();
    if (rawCtx == nullptr) {
        return HmacStatus::kCryptoError;
    }
    std::unique_ptr<HMAC_CTX, decltype(&HMAC_CTX_free)> ctx(rawCtx,
                                                            HMAC_CTX_free);

    // Init with the key and SHA-256. HMAC_Init_ex performs the standard
    // RFC 2104 key normalization itself, so keys longer than the SHA-256
    // block size are hashed exactly as the standard requires; the resulting
    // tag is identical to the one-shot HMAC() interface on both OpenSSL
    // 1.1.1 and OpenSSL 3.x. The key is validated to be non-empty before
    // this is called, so key.data() is always valid.
    if (HMAC_Init_ex(ctx.get(), key.data(), static_cast<int>(key.size()),
                     EVP_sha256(), nullptr) != 1) {
        return HmacStatus::kCryptoError;
    }

    std::array<char, 65536> buffer{};
    HmacStatus readStatus;
    if (fromStdin) {
        // File descriptor 0 is consumed exactly as it arrives: no prompt is
        // written, and no result is emitted before this returns at the
        // descriptor's normal end. How the bytes are split across reads
        // (pipe scheduling, redirection chunking) cannot change the tag.
        readStatus = streamHmac(
            ctx.get(), buffer,
            [](char* buf, std::size_t count) {
                return ::read(STDIN_FILENO, buf, count);
            },
            readErrno);
    } else {
        std::ifstream in(path, std::ios::binary | std::ios::in);
        if (!in) {
            // Could not open the file; the caller names the path in its own
            // diagnostic.
            readErrno = EIO;
            return HmacStatus::kReadError;
        }
        // std::ifstream keeps the exact bytes of a binary file; adapt it to
        // the same read-once shape as fd 0 (positive byte count, 0 at the
        // clean end, -1 on a read error). The trailing short final read is
        // just another positive count, so every byte -- including a final
        // partial chunk -- takes part exactly once.
        readStatus = streamHmac(
            ctx.get(), buffer,
            [&in](char* buf, std::size_t count) -> ssize_t {
                in.read(buf, static_cast<std::streamsize>(count));
                std::streamsize got = in.gcount();
                if (got > 0) {
                    return static_cast<ssize_t>(got);
                }
                if (in.bad()) {
                    errno = EIO;
                    return -1;
                }
                return 0;  // clean EOF
            },
            readErrno);
    }
    if (readStatus != HmacStatus::kSuccess) {
        return readStatus;
    }

    unsigned int outLength = 0;
    if (HMAC_Final(ctx.get(), mac.data(), &outLength) != 1) {
        return HmacStatus::kCryptoError;
    }
    macLength = outLength;
    return HmacStatus::kSuccess;
}

// A path of exactly "-" selects standard input; anything else (including
// "./-" or an absolute path) names a file, so a real file named "-" stays
// reachable.
HmacStatus hmacSha256File(const std::vector<unsigned char>& key,
                          const std::string& path,
                          std::array<unsigned char, EVP_MAX_MD_SIZE>& mac,
                          std::size_t& macLength, int& readErrno) {
    return hmacSha256Source(key, /*fromStdin=*/path == kStdinFile, path, mac,
                            macLength, readErrno);
}

// Output of the shared preparation stage that the command-specific
// decision still needs afterwards.
struct PreparedAuthentication {
    // verify only: the supplied --tag-hex decoded to 32 bytes; unused by
    // tag, which has no tag to compare against.
    std::vector<unsigned char> expectedTag;
};

// Prepare and perform the message authentication that both commands share.
// This is the single place that maintains the ordered checks leading up to
// the command-specific result:
//
//   1. parse exactly this command's value-taking options (unknown argument
//      or missing value -> exit 2 with that command's usage);
//   2. require --key-hex/--file, and additionally --tag-hex when
//      `expectTag` is set (exit 2);
//   3. decode the key, and the supplied tag for verify, BEFORE the message
//      source is touched, so a malformed key/tag is a parameter error
//      (exit 2) even when the file does not exist or standard input never
//      ends;
//   4. stream the whole message (file or standard input) through
//      HMAC-SHA-256 (read or computation failure -> exit 1, with no result
//      produced; a prefix read before a failure is never finalized as the
//      message).
//
// Every diagnostic goes out from here under the failing command's own name
// and usage, so one and the same failure behaviour no longer has to be kept
// in sync between runTag and runVerify. Returns the process exit code; on
// success it is 0 and `mac`/`macLength` (plus `prepared` for verify) hold
// what the caller needs for its own result handling; otherwise the caller
// returns the non-zero code unchanged.
int prepareAuthentication(const CommandSpec& spec, int argc, char* argv[],
                          bool expectTag,
                          std::array<unsigned char, EVP_MAX_MD_SIZE>& mac,
                          std::size_t& macLength,
                          PreparedAuthentication& prepared) {
    std::map<std::string, std::string> opts;
    if (!parseValueOptions(spec, argc, argv, opts)) {
        return 2;
    }
    if (!requireOption(spec, opts, "--key-hex") ||
        !requireOption(spec, opts, "--file") ||
        (expectTag && !requireOption(spec, opts, "--tag-hex"))) {
        return 2;
    }
    const std::string& keyHex = opts["--key-hex"];
    const std::string& filePath = opts["--file"];

    // All input-format checks happen before the message source is touched:
    // before opening a file, and before reading standard input. A malformed
    // key or tag is therefore reported as a parameter error (exit 2) even
    // when the file does not exist or standard input's upstream has not
    // finished, so such a command never blocks waiting for message bytes.
    std::vector<unsigned char> key;
    if (!parseKey(spec, keyHex, key)) {
        return 2;
    }

    if (expectTag) {
        // The supplied tag must decode to exactly 32 bytes (64 hex
        // characters); decodeHex already rejects empty input, odd length,
        // non-hex characters and whitespace, which also rules out a 0x
        // prefix. The submitted tag is deliberately not echoed back.
        if (!decodeHex(opts["--tag-hex"], prepared.expectedTag) ||
            prepared.expectedTag.size() != kTagBytes) {
            std::cerr << "messagetag " << spec.name
                      << ": error: invalid --tag-hex: expected exactly 64 "
                         "hexadecimal characters denoting 32 bytes (0-9, a-f, "
                         "A-F); empty, truncated or over-long values, embedded "
                         "whitespace and a 0x prefix are not accepted\n"
                      << spec.usage;
            return 2;
        }
    }

    const bool fromStdin = (filePath == kStdinFile);
    int readErrno = 0;
    switch (hmacSha256File(key, filePath, mac, macLength, readErrno)) {
        case HmacStatus::kReadError:
            // The partially read prefix must never be authenticated as if it
            // were the whole message. The two sources get their own line: a
            // file diagnostic names the path, while the standard-input one
            // says the input read failed and why. Neither echoes the key,
            // the supplied tag or a recomputed tag.
            if (fromStdin) {
                std::cerr << "messagetag " << spec.name
                          << ": error: failed to read standard input ("
                          << std::strerror(readErrno != 0 ? readErrno : EIO)
                          << ")\n";
            } else {
                std::cerr << "messagetag " << spec.name
                          << ": error: failed to read file: " << filePath
                          << "\n";
            }
            return 1;
        case HmacStatus::kCryptoError:
            std::cerr << "messagetag " << spec.name
                      << ": error: HMAC-SHA-256 computation failed\n";
            return 1;
        case HmacStatus::kSuccess:
            return 0;
    }
    return 1;  // unreachable: every status is handled above
}

int runTag(int argc, char* argv[]) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> mac{};
    std::size_t macLength = 0;
    PreparedAuthentication prepared;
    int rc = prepareAuthentication(tagSpec(), argc, argv, /*expectTag=*/false,
                                   mac, macLength, prepared);
    if (rc != 0) {
        return rc;
    }

    std::string tagLine = hexEncode(mac.data(), macLength);
    tagLine.push_back('\n');
    // Exit 0 only once the whole line is confirmed written; a correct tag
    // does not make a failed/partial result output a success.
    if (!emitResultLine("tag", tagLine)) {
        return 1;
    }
    return 0;
}

// Compare two fixed-length byte strings without leaking the length of any
// matching prefix: the loop always touches every byte and accumulates all
// differences, so the running time does not depend on where (or whether)
// the inputs differ.
bool constantTimeEqual(const unsigned char* a, const unsigned char* b,
                       std::size_t length) {
    unsigned char diff = 0;
    for (std::size_t i = 0; i < length; ++i) {
        diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    }
    return diff == 0;
}

int runVerify(int argc, char* argv[]) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> mac{};
    std::size_t macLength = 0;
    PreparedAuthentication prepared;
    int rc = prepareAuthentication(verifySpec(), argc, argv,
                                   /*expectTag=*/true, mac, macLength,
                                   prepared);
    if (rc != 0) {
        return rc;
    }

    if (macLength != kTagBytes ||
        !constantTimeEqual(mac.data(), prepared.expectedTag.data(),
                           kTagBytes)) {
        // State only that authentication failed; do not assign a cause (the
        // message, the key or the tag could each be the one that differs),
        // and never print the recomputed tag, a matched prefix or the key.
        // The message may have come from a file or standard input, so the
        // wording stays source-neutral.
        std::cerr << "messagetag verify: error: authentication tag mismatch: "
                     "the supplied tag does not match the given key and "
                     "message content\n";
        return 3;
    }

    // Exit 0 only once the whole "OK\n" line is confirmed written; a
    // passed comparison does not make a failed/partial result output a
    // success.
    if (!emitResultLine("verify", "OK\n")) {
        return 1;
    }
    return 0;
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc == 2 && std::string_view(argv[1]) == "--version") {
        std::cout << "messagetag 0.1.0\n";
        return 0;
    }
    if (argc >= 2 && (std::string_view(argv[1]) == "tag" ||
                      std::string_view(argv[1]) == "verify")) {
        // A closed downstream pipe must surface as an EPIPE write failure
        // (reported and mapped to exit 1), not as the default SIGPIPE kill,
        // which would leave the shell with a signal-terminated status and
        // no diagnostic. Ignore SIGPIPE so write(2) returns EPIPE instead.
        std::signal(SIGPIPE, SIG_IGN);
        if (std::string_view(argv[1]) == "tag") {
            return runTag(argc, argv);
        }
        return runVerify(argc, argv);
    }
    std::cerr << "Usage: messagetag --version\n"
              << "       messagetag tag --key-hex <hex-key> "
                 "--file <message-file|->\n"
              << "       messagetag verify --key-hex <hex-key> "
                 "--file <message-file|-> --tag-hex <hex-tag>\n";
    return 2;
}
