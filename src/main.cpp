#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>

namespace {

void printUsage(std::ostream& os) {
    os << "Usage:\n"
       << "  messagetag tag --key-hex <hex-key> --file <path>\n"
       << "  messagetag --version\n";
}

int hexDigitValue(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Parses a hex string into raw key bytes. The key must be non-empty, have an
// even number of digits, and contain only [0-9a-fA-F]. Never logs the input.
bool parseKeyHex(std::string_view text, std::vector<unsigned char>& key) {
    if (text.empty() || text.size() % 2 != 0) return false;
    key.clear();
    key.reserve(text.size() / 2);
    for (std::size_t i = 0; i < text.size(); i += 2) {
        int hi = hexDigitValue(text[i]);
        int lo = hexDigitValue(text[i + 1]);
        if (hi < 0 || lo < 0) return false;
        key.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }
    return true;
}

int tagCommand(int argc, char* argv[]) {
    std::string_view keyHex;
    std::string_view filePath;
    bool haveKey = false;
    bool haveFile = false;

    for (int i = 2; i < argc; ++i) {
        std::string_view arg(argv[i]);
        if (arg == "--key-hex" || arg == "--file") {
            if (i + 1 >= argc) {
                std::cerr << "messagetag: option '" << arg << "' requires a value\n";
                printUsage(std::cerr);
                return 2;
            }
            if (arg == "--key-hex") {
                keyHex = argv[++i];
                haveKey = true;
            } else {
                filePath = argv[++i];
                haveFile = true;
            }
        } else {
            std::cerr << "messagetag: unrecognized argument '" << arg << "'\n";
            printUsage(std::cerr);
            return 2;
        }
    }

    if (!haveKey) {
        std::cerr << "messagetag: missing required option --key-hex\n";
        printUsage(std::cerr);
        return 2;
    }
    if (!haveFile) {
        std::cerr << "messagetag: missing required option --file\n";
        printUsage(std::cerr);
        return 2;
    }

    std::vector<unsigned char> key;
    if (!parseKeyHex(keyHex, key)) {
        std::cerr << "messagetag: invalid key: --key-hex must be a non-empty, "
                     "even-length string of hexadecimal digits (0-9, a-f)\n";
        printUsage(std::cerr);
        return 2;
    }

    // The message is the file's raw bytes, exactly as stored.
    std::vector<unsigned char> message;
    try {
        std::ifstream in(std::string(filePath), std::ios::binary);
        if (!in) {
            std::cerr << "messagetag: failed to read file '" << filePath << "'\n";
            return 1;
        }
        message.assign(std::istreambuf_iterator<char>(in),
                       std::istreambuf_iterator<char>());
        if (in.bad()) {
            std::cerr << "messagetag: failed to read file '" << filePath << "'\n";
            return 1;
        }
    } catch (const std::ios_base::failure&) {
        // libstdc++'s filebuf throws on low-level read errors (e.g. EISDIR).
        std::cerr << "messagetag: failed to read file '" << filePath << "'\n";
        return 1;
    }

    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int macLen = 0;
    const unsigned char* messagePtr = message.empty() ? nullptr : message.data();
    if (HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), messagePtr,
             message.size(), mac, &macLen) == nullptr) {
        std::cerr << "messagetag: failed to compute authentication tag\n";
        return 1;
    }

    static constexpr char kHexDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(macLen * 2 + 1);
    for (unsigned int i = 0; i < macLen; ++i) {
        out.push_back(kHexDigits[mac[i] >> 4]);
        out.push_back(kHexDigits[mac[i] & 0x0f]);
    }
    out.push_back('\n');
    std::cout << out;
    return 0;
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc == 2 && std::string_view(argv[1]) == "--version") {
        std::cout << "messagetag 0.1.0\n";
        return 0;
    }
    if (argc >= 2 && std::string_view(argv[1]) == "tag") {
        return tagCommand(argc, argv);
    }
    std::cerr << "messagetag: unrecognized arguments\n";
    printUsage(std::cerr);
    return 2;
}
