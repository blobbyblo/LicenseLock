#include "Util.h"
#include "CryptoUtils.h"
#include "HWID.h"
#include <nlohmann/json.hpp>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstring>

static void usage(const char* prog) {
    std::cerr << "Usage: " << prog
        << " --hwid <HWID>"
        << " --expires <RFC3339-timestamp>"
        << " --privkey <priv.pem>"
        << " --out <license.json>"
        << "\n\n"
        << "Hint, your HWID is " << HWID::get_machine_id()
        << "\n\n";
    std::exit(1);
}

int main(int argc, char** argv) {
    std::string hwid;
    std::string expires;
    std::string privkey_path;
    std::string out_path;

    // --- simple argv parsing ---
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--hwid") == 0 && i + 1 < argc) {
            hwid = argv[++i];
        }
        else if (std::strcmp(argv[i], "--expires") == 0 && i + 1 < argc) {
            expires = argv[++i];
        }
        else if (std::strcmp(argv[i], "--privkey") == 0 && i + 1 < argc) {
            privkey_path = argv[++i];
        }
        else if (std::strcmp(argv[i], "--out") == 0 && i + 1 < argc) {
            out_path = argv[++i];
        }
        else {
            usage(argv[0]);
        }
    }

    // --- validate ---
    if (hwid.empty() || expires.empty() ||
        privkey_path.empty() || out_path.empty()) {
        usage(argv[0]);
    }

    // 1) build payload JSON
    nlohmann::json payload = {
        {"hwid",    hwid},
        {"issued",  Util::current_utc_rfc3339()},
        {"expires", expires}
    };
    std::string canon = payload.dump();  // canonical UTF-8 bytes to sign

    // 2) load private key
    std::string priv_pem = Util::slurp_file(privkey_path);

    // 3) sign with RSA-PSS
    auto sig = CryptoUtils::rsa_pss_sign(
        priv_pem,
        reinterpret_cast<const uint8_t*>(canon.data()),
        canon.size());

    // 4) base64-encode signature
    std::string b64sig = Util::to_base64(sig.data(), sig.size());

    // 5) assemble final JSON
    nlohmann::json license = {
        {"payload",   payload},
        {"signature", b64sig}
    };

    // 6) write to disk
    std::ofstream out(out_path, std::ios::out | std::ios::trunc);
    if (!out) {
        std::cerr << "Error: cannot open output file: " << out_path << "\n";
        return 2;
    }
    out << license.dump(2) << "\n";

    std::cout << "License written to " << out_path << "\n";
    return 0;
}
