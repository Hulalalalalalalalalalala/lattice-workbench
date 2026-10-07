// The low-level HMAC functions (HMAC_CTX_new/HMAC_Init_ex/HMAC_Update/
// HMAC_Final) are available in both OpenSSL 1.1.1 and OpenSSL 3.x.
// OpenSSL 3.x marks them deprecated in favour of the EVP_MAC interface
// (which 1.1.1 does not have); suppress those deprecation warnings so the
// portable interface builds cleanly on 3.x. The streaming Init/Update/
// Final form lets the message file be digested in fixed-size chunks
// instead of being held in memory all at once.
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
    "Usage: messagetag tag --key-hex <hex-key> --file <message-file>\n"
    "       (a <message-file> of exactly '-' reads the message from "
    "standard input)\n";

constexpr std::string_view kVerifyUsage =
    "Usage: messagetag verify --key-hex <hex-key> --file <message-file> "
    "--tag-hex <hex-tag>\n"
    "       (a <message-file> of exactly '-' reads the message from "
    "standard input)\n";

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

// Stream a message into HMAC-SHA-256 a fixed-size chunk at a time through
// the shared authentication driver below. The message is never stored
// whole: regardless of its length, only one fixed-size read buffer is
// needed on top of the constant-size HMAC context.
//
// The bytes are not interpreted as text: trailing newlines are kept, line
// endings are not converted and zero bytes are preserved. An empty input
// simply yields no Update calls, which authenticates the empty message.
enum class HmacStatus { kSuccess, kReadError, kCryptoError };

// A streaming HMAC-SHA-256 computation: Init with the key at construction,
// feed message bytes chunk by chunk with update(), produce the tag once
// with finish(). The file and standard-input sources both feed their bytes
// through this one path, so the same key and the same bytes always yield
// the same tag no matter which source they came from, and no matter how
// the input was split into reads.
//
// HMAC_Init_ex performs the standard RFC 2104 key normalization itself, so
// keys longer than the SHA-256 block size are hashed exactly as the
// standard requires; the resulting tag is identical to the one-shot HMAC()
// interface on both OpenSSL 1.1.1 and OpenSSL 3.x. The key is validated to
// be non-empty before this is constructed, so key.data() is always valid.
class HmacSha256Stream {
  public:
    explicit HmacSha256Stream(const std::vector<unsigned char>& key)
        : ctx_(HMAC_CTX_new(), &HMAC_CTX_free) {
        usable_ = ctx_ != nullptr &&
                  HMAC_Init_ex(ctx_.get(), key.data(),
                               static_cast<int>(key.size()), EVP_sha256(),
                               nullptr) == 1;
    }

    bool usable() const { return usable_; }

    bool update(const char* data, std::size_t length) {
        return HMAC_Update(ctx_.get(),
                           reinterpret_cast<const unsigned char*>(data),
                           length) == 1;
    }

    bool finish(std::array<unsigned char, EVP_MAX_MD_SIZE>& mac,
                std::size_t& macLength) {
        unsigned int outLength = 0;
        if (HMAC_Final(ctx_.get(), mac.data(), &outLength) != 1) {
            return false;
        }
        macLength = outLength;
        return true;
    }

  private:
    std::unique_ptr<HMAC_CTX, decltype(&HMAC_CTX_free)> ctx_;
    bool usable_ = false;
};

// A source of message bytes for the shared authentication driver. Each
// readNext() call delivers up to `capacity` bytes into `buffer` and
// returns:
//   * a positive value -- that many message bytes were delivered (a short
//     result is normal; the driver simply calls again);
//   * 0 -- the input ended normally; every byte delivered so far is the
//     whole message and it is the only place the HMAC is finalized;
//   * -1 -- reading failed (errno is left as set); authentication aborts
//     and finish() is never called, so bytes already delivered can never
//     be finalized as if they were the whole message.
//
// The interface is the single seam between "where the bytes come from"
// (an ordinary file, or standard input with its own end/interruption/
// failure rules) and the authentication logic they share: both sources
// feed one readNext() loop, so the same key and the same bytes always
// yield the same tag no matter which source they came from, and no matter
// how the input was split into reads.
class MessageSource {
  public:
    virtual ~MessageSource() = default;
    virtual ssize_t readNext(char* buffer, std::size_t capacity) = 0;
};

// The ordinary-file source: the path is used only to locate the input and
// never enters the authentication. A short final read is normal EOF and
// those remaining bytes still participate; a genuine read error --
// including one after a non-empty prefix has already been delivered -- is
// reported as a failure rather than mistaken for end of input.
class FileMessageSource : public MessageSource {
  public:
    explicit FileMessageSource(const std::string& path)
        : in_(path, std::ios::binary | std::ios::in) {}

    bool opened() const { return static_cast<bool>(in_); }

    ssize_t readNext(char* buffer, std::size_t capacity) override {
        if (in_.read(buffer, static_cast<std::streamsize>(capacity))) {
            return static_cast<ssize_t>(in_.gcount());
        }
        // EOF: gcount() carries the bytes of a short final read (possibly
        // zero for a message that ended exactly on a buffer boundary); a
        // hard error sets bad() and is a failure even when gcount() is 0.
        if (in_.bad()) {
            return -1;
        }
        return static_cast<ssize_t>(in_.gcount());
    }

  private:
    std::ifstream in_;
};

// The standard-input source (file descriptor 0), selected by a --file
// value of exactly "-". Every byte delivered before the normal end of
// input is part of the message -- zero bytes and what follows them,
// trailing newlines and every line-ending form are authenticated
// unchanged, nothing is trimmed or converted, no line ending terminates
// the message early, and an empty input is the empty message. Bytes
// arriving in several installments are simply several readNext() results,
// which does not change the tag. A read interrupted with EINTR -- before
// any byte arrived, or after a non-empty prefix, once or in a burst -- is
// not an end of input and not a failure: the read is retried, keeping the
// bytes already received as part of the same message. Any other read
// failure is reported, after which authentication aborts.
class StdinMessageSource : public MessageSource {
  public:
    ssize_t readNext(char* buffer, std::size_t capacity) override {
        for (;;) {
            ssize_t n = ::read(STDIN_FILENO, buffer, capacity);
            if (n >= 0 || errno != EINTR) {
                return n;
            }
            // Interrupted before any byte arrived; keep waiting for later
            // content of the same message.
        }
    }
};

// The one authentication path maintained for both message sources. It
// owns exactly the rules the two sources share:
//
//   * start the streaming HMAC-SHA-256 with the key once (the source has
//     already been located/opened, so a failure here is a crypto error);
//   * pull bytes through one fixed-size buffer and feed every delivered
//     byte to update() in arrival order -- split into reads arbitrarily,
//     a short final buffer included, with nothing dropped, repeated or
//     reordered, and memory bounded by the buffer regardless of message
//     length;
//   * finalize exactly once, and only after the source reports the normal
//     end of input, so no tag (and, for verify, no pass/mismatch
//     conclusion) can be produced before the input has ended or from a
//     prefix left by a read failure. Nothing is written to standard output
//     while the input is still open; this function only computes.
HmacStatus hmacSha256Message(MessageSource& source,
                             const std::vector<unsigned char>& key,
                             std::array<unsigned char, EVP_MAX_MD_SIZE>& mac,
                             std::size_t& macLength) {
    HmacSha256Stream hmac(key);
    if (!hmac.usable()) {
        return HmacStatus::kCryptoError;
    }

    std::array<char, 65536> buffer{};
    for (;;) {
        ssize_t n = source.readNext(buffer.data(), buffer.size());
        if (n < 0) {
            // A read error -- including one after a non-empty prefix has
            // already been fed to HMAC -- aborts authentication: finish()
            // is never called, so no partial-message result can follow.
            return HmacStatus::kReadError;
        }
        if (n == 0) {
            break;  // clean end of input: every byte has been fed
        }
        if (!hmac.update(buffer.data(), static_cast<std::size_t>(n))) {
            return HmacStatus::kCryptoError;
        }
    }

    if (!hmac.finish(mac, macLength)) {
        return HmacStatus::kCryptoError;
    }
    return HmacStatus::kSuccess;
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
//      (exit 2) even when the file does not exist -- and, with "--file -",
//      without waiting for standard input to arrive or end;
//   4. stream the whole message through HMAC-SHA-256, from the named file
//      or -- when --file is exactly "-" -- from standard input until its
//      normal end (read or computation failure -> exit 1, with no result
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

    // All input-format checks happen before the message source is touched,
    // so a malformed key or tag is reported as a parameter error (exit 2)
    // even when the message file does not exist -- and, with "--file -",
    // without ever waiting for standard input.
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

    // A --file value of exactly "-" reads the message from standard input
    // until its normal end; a file literally named "-" stays reachable as
    // "./-" or by full path, and every other value is a file path read the
    // usual way. Only the selected source is opened. The sources differ
    // only in how they obtain bytes (and, for a file, in opening it): once
    // obtained, both are authenticated by the single shared driver above.
    const bool fromStdin = filePath == "-";
    HmacStatus status;
    if (fromStdin) {
        StdinMessageSource source;
        status = hmacSha256Message(source, key, mac, macLength);
    } else {
        FileMessageSource source(filePath);
        if (!source.opened()) {
            // An open failure is reported with the same file-read
            // diagnostic as a failure midway through; it is distinguished
            // here only because there is no stream to run in that case.
            status = HmacStatus::kReadError;
        } else {
            status = hmacSha256Message(source, key, mac, macLength);
        }
    }
    switch (status) {
        case HmacStatus::kReadError:
            // The partially read prefix must never be authenticated as if
            // it were the whole message. Neither diagnostic echoes the key,
            // the supplied tag or a recomputed tag.
            if (fromStdin) {
                std::cerr << "messagetag " << spec.name
                          << ": error: failed to read standard input\n";
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
        std::cerr << "messagetag verify: error: authentication tag mismatch: "
                     "the supplied tag does not match the given key and file "
                     "content\n";
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
                 "--file <message-file>\n"
              << "       messagetag verify --key-hex <hex-key> "
                 "--file <message-file> --tag-hex <hex-tag>\n"
              << "       (a <message-file> of exactly '-' reads the message "
                 "from standard input)\n";
    return 2;
}
