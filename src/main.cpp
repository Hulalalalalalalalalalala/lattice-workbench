// The incremental HMAC_CTX interface (HMAC_Init_ex/HMAC_Update/HMAC_Final)
// from <openssl/hmac.h> is available in both OpenSSL 1.1.1 and OpenSSL 3.x.
// OpenSSL 3.x marks it deprecated in favour of the EVP_MAC interface (which
// 1.1.1 does not have); suppress those deprecation warnings so the portable
// interface builds cleanly on 3.x.
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/evp.h>
#include <openssl/hmac.h>

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

// Outcome of streaming a message file through the HMAC computation. The
// caller reports read failures and computation failures differently, so the
// two are kept distinct instead of collapsing them into a single bool.
enum class TagFileResult {
    kOk,
    kReadError,
    kHmacError,
};

// Compute the HMAC-SHA-256 tag of a file's complete raw byte content without
// ever holding the whole message in memory: the file is read in fixed-size
// chunks and each chunk is fed to the incremental HMAC interface, so the
// extra memory needed stays bounded no matter how large the file grows.
//
// The bytes are not interpreted as text: trailing newlines are kept, line
// endings are not converted and zero bytes are preserved. An empty file
// yields the tag of the empty message (the update loop simply runs zero
// times before HMAC_Final).
//
// The HMAC_CTX interface exists in both OpenSSL 1.1.1 and OpenSSL 3.x and
// implements the same standard HMAC construction (RFC 2104) as the one-shot
// HMAC() function, so keys longer than the SHA-256 block size are hashed
// exactly as the standard requires and both environments produce tags
// identical to the previous one-shot implementation.
TagFileResult hmacSha256File(const std::vector<unsigned char>& key,
                             const std::string& path,
                             std::array<unsigned char, EVP_MAX_MD_SIZE>& mac,
                             std::size_t& macLength) {
    std::ifstream in(path, std::ios::binary | std::ios::in);
    if (!in) {
        return TagFileResult::kReadError;
    }

    // HMAC_CTX_new never fails in practice but is checked anyway; a null
    // context is a computation failure, not a read failure.
    HMAC_CTX* rawCtx = HMAC_CTX_new();
    if (rawCtx == nullptr) {
        return TagFileResult::kHmacError;
    }
    const std::unique_ptr<HMAC_CTX, decltype(&HMAC_CTX_free)> ctx(rawCtx,
                                                                  &HMAC_CTX_free);

    // The key is validated to be non-empty before this is called, so
    // key.data() is always valid.
    if (HMAC_Init_ex(ctx.get(), key.data(), static_cast<int>(key.size()),
                     EVP_sha256(), nullptr) != 1) {
        return TagFileResult::kHmacError;
    }

    std::array<char, 65536> buffer{};
    while (in.read(buffer.data(), static_cast<std::streamsize>(buffer.size()))) {
        if (HMAC_Update(ctx.get(),
                        reinterpret_cast<const unsigned char*>(buffer.data()),
                        buffer.size()) != 1) {
            return TagFileResult::kHmacError;
        }
    }
    if (in.bad()) {
        // The read failed partway through the message; a tag computed from
        // the partial content would be meaningless, so nothing is emitted.
        return TagFileResult::kReadError;
    }
    // Feed the final partial chunk (zero bytes for an empty file or an exact
    // multiple of the buffer size); the last bytes of a large file are
    // authenticated just like any other.
    const std::streamsize tail = in.gcount();
    if (tail > 0 &&
        HMAC_Update(ctx.get(),
                    reinterpret_cast<const unsigned char*>(buffer.data()),
                    static_cast<std::size_t>(tail)) != 1) {
        return TagFileResult::kHmacError;
    }

    unsigned int outLength = 0;
    if (HMAC_Final(ctx.get(), mac.data(), &outLength) != 1) {
        return TagFileResult::kHmacError;
    }
    macLength = outLength;
    return TagFileResult::kOk;
}

int runTag(int argc, char* argv[]) {
    // argv[1] is the "tag" subcommand name; option parsing starts at argv[2].
    std::string keyHex;
    std::string filePath;
    bool haveKeyHex = false;
    bool haveFile = false;

    for (int i = 2; i < argc; ++i) {
        std::string arg(argv[i]);
        if (arg == "--key-hex" || arg == "--file") {
            if (i + 1 >= argc) {
                std::cerr << "messagetag tag: error: option '" << arg
                          << "' requires a value\n"
                          << kTagUsage;
                return 2;
            }
            std::string value = argv[++i];
            if (arg == "--key-hex") {
                keyHex = value;
                haveKeyHex = true;
            } else {
                filePath = value;
                haveFile = true;
            }
        } else {
            std::cerr << "messagetag tag: error: unknown argument '" << arg << "'\n"
                      << kTagUsage;
            return 2;
        }
    }

    if (!haveKeyHex) {
        std::cerr << "messagetag tag: error: missing required option '--key-hex'\n"
                  << kTagUsage;
        return 2;
    }
    if (!haveFile) {
        std::cerr << "messagetag tag: error: missing required option '--file'\n"
                  << kTagUsage;
        return 2;
    }

    std::vector<unsigned char> key;
    if (!decodeHex(keyHex, key)) {
        std::cerr << "messagetag tag: error: invalid --key-hex: expected a non-empty, "
                     "even-length string of hexadecimal characters (0-9, a-f, A-F); "
                     "every two characters denote one key byte and leading zeros must "
                     "be kept; a 0x prefix and whitespace are not accepted\n"
                  << kTagUsage;
        return 2;
    }

    std::array<unsigned char, EVP_MAX_MD_SIZE> mac{};
    std::size_t macLength = 0;
    const TagFileResult result = hmacSha256File(key, filePath, mac, macLength);
    if (result == TagFileResult::kReadError) {
        std::cerr << "messagetag tag: error: failed to read file: " << filePath << "\n";
        return 1;
    }
    if (result != TagFileResult::kOk) {
        std::cerr << "messagetag tag: error: HMAC-SHA-256 computation failed\n";
        return 1;
    }

    std::cout << hexEncode(mac.data(), macLength) << '\n';
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
    std::cerr << "Usage: messagetag --version\n"
              << "       messagetag tag --key-hex <hex-key> --file <message-file>\n";
    return 2;
}
