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
#include <cstddef>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr std::string_view kTagUsage =
    "Usage: messagetag tag --key-hex <hex-key> --file <message-file>\n";

constexpr std::string_view kVerifyUsage =
    "Usage: messagetag verify --key-hex <hex-key> --file <message-file> "
    "--tag-hex <hex-tag>\n";

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

// Parse options of the form "--name value" starting at argv[2]. On a usage
// problem (an unknown argument, or an option without a following value) a
// command-specific diagnostic and the usage line are written to stderr and
// this returns false; the caller then exits with code 2. On success the
// collected values are stored keyed by option name, and the caller checks
// which required options are present. Only the value-taking options named
// in `names` are accepted.
bool parseValueOptions(int argc, char* argv[], std::string_view command,
                       std::string_view usage,
                       const std::vector<std::string_view>& names,
                       std::map<std::string, std::string>& values) {
    for (int i = 2; i < argc; ++i) {
        std::string arg(argv[i]);
        bool recognized = false;
        for (std::string_view name : names) {
            if (arg == name) {
                recognized = true;
                break;
            }
        }
        if (!recognized) {
            std::cerr << "messagetag " << command
                      << ": error: unknown argument '" << arg << "'\n"
                      << usage;
            return false;
        }
        if (i + 1 >= argc) {
            std::cerr << "messagetag " << command
                      << ": error: option '" << arg
                      << "' requires a value\n"
                      << usage;
            return false;
        }
        values[arg] = argv[++i];
    }
    return true;
}

bool requireOption(const std::map<std::string, std::string>& values,
                   std::string_view command, std::string_view usage,
                   std::string_view name) {
    if (values.find(std::string(name)) == values.end()) {
        std::cerr << "messagetag " << command
                  << ": error: missing required option '" << name << "'\n"
                  << usage;
        return false;
    }
    return true;
}

// Decode the --key-hex argument, emitting the shared key-format diagnostic
// (which never echoes the submitted key) on failure.
bool parseKey(std::string_view command, std::string_view usage,
              const std::string& keyHex, std::vector<unsigned char>& key) {
    if (decodeHex(keyHex, key)) {
        return true;
    }
    std::cerr << "messagetag " << command
              << ": error: invalid --key-hex: expected a non-empty, "
                 "even-length string of hexadecimal characters (0-9, a-f, A-F); "
                 "every two characters denote one key byte and leading zeros must "
                 "be kept; a 0x prefix and whitespace are not accepted\n"
              << usage;
    return false;
}

// Stream the message file into HMAC-SHA-256 a fixed-size chunk at a time.
// The message is never stored whole: regardless of file length, only one
// 64 KiB read buffer is needed on top of the constant-size HMAC context.
//
// The bytes are not interpreted as text: the file is opened in binary mode,
// trailing newlines are kept, line endings are not converted and zero bytes
// are preserved. An empty file simply yields no Update calls, which
// authenticates the empty message.
enum class HmacStatus { kSuccess, kReadError, kCryptoError };

HmacStatus hmacSha256File(const std::vector<unsigned char>& key,
                          const std::string& path,
                          std::array<unsigned char, EVP_MAX_MD_SIZE>& mac,
                          std::size_t& macLength) {
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

    std::ifstream in(path, std::ios::binary | std::ios::in);
    if (!in) {
        return HmacStatus::kReadError;
    }

    std::array<char, 65536> buffer{};
    while (in.read(buffer.data(), static_cast<std::streamsize>(buffer.size()))) {
        if (HMAC_Update(ctx.get(),
                        reinterpret_cast<const unsigned char*>(buffer.data()),
                        static_cast<std::size_t>(in.gcount())) != 1) {
            return HmacStatus::kCryptoError;
        }
    }
    // A read error (including one that happens after part of the message has
    // already been fed to HMAC) aborts authentication: Final is never called,
    // so no partial-message tag can be produced. EOF with a short final read
    // is normal and those remaining bytes must still participate.
    if (in.bad()) {
        return HmacStatus::kReadError;
    }
    if (in.gcount() > 0) {
        if (HMAC_Update(ctx.get(),
                        reinterpret_cast<const unsigned char*>(buffer.data()),
                        static_cast<std::size_t>(in.gcount())) != 1) {
            return HmacStatus::kCryptoError;
        }
    }

    unsigned int outLength = 0;
    if (HMAC_Final(ctx.get(), mac.data(), &outLength) != 1) {
        return HmacStatus::kCryptoError;
    }
    macLength = outLength;
    return HmacStatus::kSuccess;
}

int runTag(int argc, char* argv[]) {
    // argv[1] is the "tag" subcommand name; option parsing starts at argv[2].
    std::map<std::string, std::string> opts;
    if (!parseValueOptions(
            argc, argv, "tag", kTagUsage,
            std::vector<std::string_view>{"--key-hex", "--file"}, opts)) {
        return 2;
    }
    if (!requireOption(opts, "tag", kTagUsage, "--key-hex") ||
        !requireOption(opts, "tag", kTagUsage, "--file")) {
        return 2;
    }
    const std::string& keyHex = opts["--key-hex"];
    const std::string& filePath = opts["--file"];

    std::vector<unsigned char> key;
    if (!parseKey("tag", kTagUsage, keyHex, key)) {
        return 2;
    }

    std::array<unsigned char, EVP_MAX_MD_SIZE> mac{};
    std::size_t macLength = 0;
    switch (hmacSha256File(key, filePath, mac, macLength)) {
        case HmacStatus::kReadError:
            std::cerr << "messagetag tag: error: failed to read file: "
                      << filePath << "\n";
            return 1;
        case HmacStatus::kCryptoError:
            std::cerr << "messagetag tag: error: HMAC-SHA-256 computation failed\n";
            return 1;
        case HmacStatus::kSuccess:
            break;
    }

    std::cout << hexEncode(mac.data(), macLength) << '\n';
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
    // argv[1] is the "verify" subcommand name; parsing starts at argv[2].
    std::map<std::string, std::string> opts;
    if (!parseValueOptions(
            argc, argv, "verify", kVerifyUsage,
            std::vector<std::string_view>{"--key-hex", "--file", "--tag-hex"},
            opts)) {
        return 2;
    }
    if (!requireOption(opts, "verify", kVerifyUsage, "--key-hex") ||
        !requireOption(opts, "verify", kVerifyUsage, "--file") ||
        !requireOption(opts, "verify", kVerifyUsage, "--tag-hex")) {
        return 2;
    }
    const std::string& keyHex = opts["--key-hex"];
    const std::string& filePath = opts["--file"];
    const std::string& tagHex = opts["--tag-hex"];

    // All input-format checks happen before the file is opened, so a
    // malformed key or tag is reported as a parameter error (exit 2) even
    // when the message file does not exist.
    std::vector<unsigned char> key;
    if (!parseKey("verify", kVerifyUsage, keyHex, key)) {
        return 2;
    }

    // The supplied tag must decode to exactly 32 bytes (64 hex characters);
    // decodeHex already rejects empty input, odd length, non-hex characters
    // and whitespace, which also rules out a 0x prefix. The submitted tag is
    // deliberately not echoed back.
    std::vector<unsigned char> expected;
    if (!decodeHex(tagHex, expected) || expected.size() != kTagBytes) {
        std::cerr << "messagetag verify: error: invalid --tag-hex: expected "
                     "exactly 64 hexadecimal characters denoting 32 bytes "
                     "(0-9, a-f, A-F); empty, truncated or over-long values, "
                     "embedded whitespace and a 0x prefix are not accepted\n"
                  << kVerifyUsage;
        return 2;
    }

    std::array<unsigned char, EVP_MAX_MD_SIZE> mac{};
    std::size_t macLength = 0;
    switch (hmacSha256File(key, filePath, mac, macLength)) {
        case HmacStatus::kReadError:
            // The partially read prefix must never be authenticated as if it
            // were the whole message.
            std::cerr << "messagetag verify: error: failed to read file: "
                      << filePath << "\n";
            return 1;
        case HmacStatus::kCryptoError:
            std::cerr << "messagetag verify: error: HMAC-SHA-256 "
                         "computation failed\n";
            return 1;
        case HmacStatus::kSuccess:
            break;
    }

    if (macLength != kTagBytes ||
        !constantTimeEqual(mac.data(), expected.data(), kTagBytes)) {
        // State only that authentication failed; do not assign a cause (the
        // message, the key or the tag could each be the one that differs),
        // and never print the recomputed tag, a matched prefix or the key.
        std::cerr << "messagetag verify: error: authentication tag mismatch: "
                     "the supplied tag does not match the given key and file "
                     "content\n";
        return 3;
    }

    std::cout << "OK\n";
    return 0;
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc == 2 && std::string_view(argv[1]) == "--version") {
        std::cout << "messagetag 0.1.0\n";
        return 0;
    }
    if (argc >= 2 && std::string_view(argv[1]) == "tag") {
        return runTag(argc, argv);
    }
    if (argc >= 2 && std::string_view(argv[1]) == "verify") {
        return runVerify(argc, argv);
    }
    std::cerr << "Usage: messagetag --version\n"
              << "       messagetag tag --key-hex <hex-key> "
                 "--file <message-file>\n"
              << "       messagetag verify --key-hex <hex-key> "
                 "--file <message-file> --tag-hex <hex-tag>\n";
    return 2;
}
