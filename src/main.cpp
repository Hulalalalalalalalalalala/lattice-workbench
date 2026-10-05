// The low-level HMAC functions (HMAC_CTX_new/HMAC_Init_ex/HMAC_Update/
// HMAC_Final) are available in both OpenSSL 1.1.1 and OpenSSL 3.x.
// OpenSSL 3.x marks them deprecated in favour of the EVP_MAC interface
// (which 1.1.1 does not have); suppress those deprecation warnings so the
// portable interface builds cleanly on 3.x. The streaming Init/Update/
// Final form lets the message file be digested in fixed-size chunks
// instead of being held in memory all at once.
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <fstream>
#include <iostream>
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

// HMAC-SHA-256 tags are 32 bytes, written as exactly 64 hex characters.
constexpr std::size_t kTagLength = 32;

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

// Decode a tag for verification: it must be exactly 64 hexadecimal
// characters denoting the 32 tag bytes. Upper and lower case are both
// accepted; empty, truncated or over-long tags, non-hex characters,
// whitespace and a 0x prefix are all rejected (decodeHex already refuses
// anything that is not an even-length run of hex digits).
bool decodeTagHex(std::string_view hex,
                  std::array<unsigned char, kTagLength>& tag) {
    if (hex.size() != kTagLength * 2) {
        return false;
    }
    std::vector<unsigned char> bytes;
    if (!decodeHex(hex, bytes)) {
        return false;
    }
    std::copy(bytes.begin(), bytes.end(), tag.begin());
    return true;
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

// Command-line options shared by the subcommands. tagHex is only accepted
// when the command declares it (verify); for tag it is an unknown argument.
struct ParsedOptions {
    std::string keyHex;
    std::string filePath;
    std::string tagHex;
    bool haveKeyHex = false;
    bool haveFile = false;
    bool haveTagHex = false;
};

// Parse argv[2..] into opts. Returns 0 on success; otherwise the error has
// already been reported and the return value is the process exit code.
int parseOptions(int argc, char* argv[], std::string_view command,
                 std::string_view usage, bool tagHexAllowed,
                 ParsedOptions& opts) {
    // argv[1] is the subcommand name; option parsing starts at argv[2].
    for (int i = 2; i < argc; ++i) {
        std::string arg(argv[i]);
        bool isTagHex = tagHexAllowed && arg == "--tag-hex";
        if (arg == "--key-hex" || arg == "--file" || isTagHex) {
            if (i + 1 >= argc) {
                std::cerr << "messagetag " << command << ": error: option '"
                          << arg << "' requires a value\n"
                          << usage;
                return 2;
            }
            std::string value = argv[++i];
            if (arg == "--key-hex") {
                opts.keyHex = value;
                opts.haveKeyHex = true;
            } else if (arg == "--file") {
                opts.filePath = value;
                opts.haveFile = true;
            } else {
                opts.tagHex = value;
                opts.haveTagHex = true;
            }
        } else {
            std::cerr << "messagetag " << command << ": error: unknown argument '"
                      << arg << "'\n"
                      << usage;
            return 2;
        }
    }

    if (!opts.haveKeyHex) {
        std::cerr << "messagetag " << command
                  << ": error: missing required option '--key-hex'\n"
                  << usage;
        return 2;
    }
    if (!opts.haveFile) {
        std::cerr << "messagetag " << command
                  << ": error: missing required option '--file'\n"
                  << usage;
        return 2;
    }
    if (tagHexAllowed && !opts.haveTagHex) {
        std::cerr << "messagetag " << command
                  << ": error: missing required option '--tag-hex'\n"
                  << usage;
        return 2;
    }
    return 0;
}

// Decode the --key-hex value. Returns 0 on success; otherwise the error has
// already been reported (without echoing the key) and the return value is
// the process exit code.
int decodeKeyOrReport(std::string_view command, std::string_view usage,
                      const std::string& keyHex,
                      std::vector<unsigned char>& key) {
    if (!decodeHex(keyHex, key)) {
        std::cerr << "messagetag " << command
                  << ": error: invalid --key-hex: expected a non-empty, "
                     "even-length string of hexadecimal characters (0-9, a-f, "
                     "A-F); every two characters denote one key byte and "
                     "leading zeros must be kept; a 0x prefix and whitespace "
                     "are not accepted\n"
                  << usage;
        return 2;
    }
    return 0;
}

// Compute the HMAC-SHA-256 of the whole file. Returns 0 on success (mac and
// macLength filled); otherwise the failure has already been reported and the
// return value is the process exit code. A read failure partway through is
// never turned into a partial-message result.
int computeFileMac(std::string_view command,
                   const std::vector<unsigned char>& key,
                   const std::string& filePath,
                   std::array<unsigned char, EVP_MAX_MD_SIZE>& mac,
                   std::size_t& macLength) {
    switch (hmacSha256File(key, filePath, mac, macLength)) {
        case HmacStatus::kReadError:
            std::cerr << "messagetag " << command
                      << ": error: failed to read file: " << filePath << "\n";
            return 1;
        case HmacStatus::kCryptoError:
            std::cerr << "messagetag " << command
                      << ": error: HMAC-SHA-256 computation failed\n";
            return 1;
        case HmacStatus::kSuccess:
            return 0;
    }
    return 1;  // unreachable; keeps compilers from warning
}

int runTag(int argc, char* argv[]) {
    ParsedOptions opts;
    if (int rc = parseOptions(argc, argv, "tag", kTagUsage,
                              /*tagHexAllowed=*/false, opts)) {
        return rc;
    }

    std::vector<unsigned char> key;
    if (int rc = decodeKeyOrReport("tag", kTagUsage, opts.keyHex, key)) {
        return rc;
    }

    std::array<unsigned char, EVP_MAX_MD_SIZE> mac{};
    std::size_t macLength = 0;
    if (int rc = computeFileMac("tag", key, opts.filePath, mac, macLength)) {
        return rc;
    }

    std::cout << hexEncode(mac.data(), macLength) << '\n';
    return 0;
}

int runVerify(int argc, char* argv[]) {
    ParsedOptions opts;
    if (int rc = parseOptions(argc, argv, "verify", kVerifyUsage,
                              /*tagHexAllowed=*/true, opts)) {
        return rc;
    }

    std::vector<unsigned char> key;
    if (int rc = decodeKeyOrReport("verify", kVerifyUsage, opts.keyHex, key)) {
        return rc;
    }

    // The tag's format is validated before the file is touched: a malformed
    // tag is a usage error (exit 2) even when the message file does not
    // exist, never a mismatch (exit 3).
    std::array<unsigned char, kTagLength> expectedTag{};
    if (!decodeTagHex(opts.tagHex, expectedTag)) {
        std::cerr << "messagetag verify: error: invalid --tag-hex: expected "
                     "exactly 64 hexadecimal characters (0-9, a-f, A-F) "
                     "denoting the 32 tag bytes; a 0x prefix and whitespace "
                     "are not accepted\n"
                  << kVerifyUsage;
        return 2;
    }

    std::array<unsigned char, EVP_MAX_MD_SIZE> mac{};
    std::size_t macLength = 0;
    if (int rc = computeFileMac("verify", key, opts.filePath, mac, macLength)) {
        return rc;
    }

    // Constant-time comparison over the whole tag: whether the tags match
    // must not leak how many leading bytes happen to agree. The mismatch
    // report states only that authentication failed -- it does not claim the
    // message was altered or the key is wrong, and it never prints the
    // recomputed tag, any matching prefix, or the key.
    if (macLength == expectedTag.size() &&
        CRYPTO_memcmp(mac.data(), expectedTag.data(), expectedTag.size()) == 0) {
        std::cout << "OK\n";
        return 0;
    }
    std::cerr << "messagetag verify: error: authentication tag does not match\n";
    return 3;
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
              << "       messagetag tag --key-hex <hex-key> --file <message-file>\n"
              << "       messagetag verify --key-hex <hex-key> --file <message-file> "
                 "--tag-hex <hex-tag>\n";
    return 2;
}
