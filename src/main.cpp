#include <openssl/evp.h>
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
// The EVP_MAC API only exists in OpenSSL 3.x.
#include <openssl/core_names.h>
#include <openssl/params.h>
#else
// OpenSSL 1.1.1 provides the one-shot HMAC() interface instead.
#include <openssl/hmac.h>
#endif

#include <array>
#include <cstddef>
#include <fstream>
#include <iostream>
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

// Read every raw byte of the file. The bytes are not interpreted as text:
// trailing newlines are kept, line endings are not converted and zero bytes
// are preserved. An empty file yields an empty message.
bool readFileBytes(const std::string& path, std::vector<unsigned char>& out) {
    std::ifstream in(path, std::ios::binary | std::ios::in);
    if (!in) {
        return false;
    }
    std::array<char, 65536> buffer{};
    while (in.read(buffer.data(), static_cast<std::streamsize>(buffer.size()))) {
        out.insert(out.end(), buffer.begin(),
                   buffer.begin() + in.gcount());
    }
    if (in.bad()) {
        return false;
    }
    out.insert(out.end(), buffer.begin(),
               buffer.begin() + in.gcount());
    return true;
}

// Compute a standard HMAC-SHA-256 tag with OpenSSL. OpenSSL 3.x uses the
// EVP_MAC API; OpenSSL 1.1.1 does not have it, so there the one-shot HMAC()
// function is used. Both implement the same standard HMAC construction
// (keys longer than the SHA-256 block size are hashed first), so identical
// key and message bytes yield identical tags on either version.
bool hmacSha256(const std::vector<unsigned char>& key,
                const std::vector<unsigned char>& message,
                std::array<unsigned char, EVP_MAX_MD_SIZE>& mac,
                std::size_t& macLength) {
    const unsigned char* msg =
        message.empty() ? reinterpret_cast<const unsigned char*>("")
                        : message.data();
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    bool ok = false;
    EVP_MAC* algo = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    EVP_MAC_CTX* ctx = algo ? EVP_MAC_CTX_new(algo) : nullptr;
    if (ctx) {
        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_utf8_string(
            OSSL_MAC_PARAM_DIGEST, const_cast<char*>("SHA256"), 0);
        params[1] = OSSL_PARAM_construct_end();
        size_t outLength = 0;
        ok = EVP_MAC_init(ctx, key.data(), key.size(), params) == 1 &&
             EVP_MAC_update(ctx, msg, message.size()) == 1 &&
             EVP_MAC_final(ctx, mac.data(), &outLength, mac.size()) == 1;
        if (ok) {
            macLength = outLength;
        }
    }
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(algo);
    return ok;
#else
    unsigned int outLength = 0;
    if (HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), msg,
             message.size(), mac.data(), &outLength) == nullptr) {
        return false;
    }
    macLength = outLength;
    return true;
#endif
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

    std::vector<unsigned char> message;
    if (!readFileBytes(filePath, message)) {
        std::cerr << "messagetag tag: error: failed to read file: " << filePath << "\n";
        return 1;
    }

    std::array<unsigned char, EVP_MAX_MD_SIZE> mac{};
    std::size_t macLength = 0;
    if (!hmacSha256(key, message, mac, macLength)) {
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
