#include "ServerApp.h"
#include "HandshakeServer.h"
#include "Protocol.h"
#include "Util.h"
#include "ServerKeys.h"
#include "CryptoUtils.h"
#include <nlohmann/json.hpp>

#include <winsock2.h>

#include <filesystem>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <limits.h>
#endif

static std::filesystem::path get_executable_path() {
#ifdef _WIN32
    char buf[MAX_PATH];
    DWORD len = GetModuleFileNameA(NULL, buf, MAX_PATH);
    if (len == 0 || len == MAX_PATH) {
        throw std::runtime_error("GetModuleFileName failed");
    }
    std::filesystem::path exePath(buf);
#else
    char buf[PATH_MAX];
    ssize_t len = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len < 0) throw std::runtime_error("readlink failed");
    buf[len] = '\\0';
    std::filesystem::path exePath(buf);
#endif
    return exePath.parent_path();
}

using json = nlohmann::json;

ServerApp::ServerApp(uint16_t port)
    : m_server(), m_port(port)
{
}

bool ServerApp::run()
{
    if (!m_server.bind("0.0.0.0", m_port)) {
        Util::log("ServerApp: listen failed");
        return false;
    }

    Util::log("ServerApp: listening on port %u", m_port);
    intptr_t client = m_server.accept_client();
    if (client == INVALID_SOCKET) {
        Util::log("ServerApp: accept failed");
        return false;
    }
    Util::log("ServerApp: client connected");

    if (!perform_handshake(client)) return false;
    m_crypto = new SessionCrypto(m_session_key);

    if (!serve_auth(client)) return false;

    Util::log("ServerApp: client authenticated");
    return true;
}

bool ServerApp::perform_handshake(intptr_t client_sock)
{
    HandshakeServer hs(m_server);
    if (!hs.perform_handshake(client_sock)) {
        Util::log("ServerApp: handshake failed");
        return false;
    }
    m_session_key = hs.get_session_key();
    return true;
}

bool ServerApp::serve_auth(intptr_t client_sock)
{
    // 1) receive & decrypt the client’s HWID frame
    Protocol::FrameType ft;
    std::vector<uint8_t> in_frame;
    if (!m_server.receive_message(client_sock, ft, in_frame)) {
        Util::log("ServerApp: recv challenge request failed");
        return false;
    }
    std::vector<uint8_t> body;
    if (!m_crypto->decrypt_frame(in_frame, ft, body)) {
        Util::log("ServerApp: decrypt challenge request failed");
        return false;
    }
    auto req = json::parse(body);
    std::string mid = req["mid"].get<std::string>();

    // 2) issue one-time challenge
    m_challenge = Util::to_hex(Util::generate_random_bytes(16));
    json resp1 = { {"challenge", m_challenge} };
    auto pt1 = resp1.dump();
    std::vector<uint8_t> frame1;
    m_crypto->encrypt_frame(
        Protocol::FrameType::Data,
        std::vector<uint8_t>(pt1.begin(), pt1.end()),
        frame1);
    m_server.send_message(client_sock,
        Protocol::FrameType::Data,
        frame1.data(), frame1.size());

    // 3) receive & decrypt the echoed challenge
    if (!m_server.receive_message(client_sock, ft, in_frame)) {
        Util::log("ServerApp: recv auth request failed");
        return false;
    }
    if (!m_crypto->decrypt_frame(in_frame, ft, body)) {
        Util::log("ServerApp: decrypt auth request failed");
        return false;
    }
    auto req2 = json::parse(body);
    std::string challenge = req2["challenge"].get<std::string>();

    // 4) verify challenge match & send status
    bool challenge_ok = (challenge == m_challenge);
    json resp2 = { {"status", challenge_ok ? "OK" : "FAIL"} };
    auto pt2 = resp2.dump();
    std::vector<uint8_t> frame2;
    m_crypto->encrypt_frame(
        Protocol::FrameType::Data,
        std::vector<uint8_t>(pt2.begin(), pt2.end()),
        frame2);
    m_server.send_message(client_sock,
        Protocol::FrameType::Data,
        frame2.data(), frame2.size());
    if (!challenge_ok) {
        Util::log("ServerApp: challenge mismatch");
        return false;
    }

    // 5) scan for any *_license.json in CWD and validate
    {
        namespace fs = std::filesystem;
        std::string cwd = get_executable_path().string();
        Util::log("ServerApp: scanning directory: %s", cwd.c_str());

        bool license_ok = false;
        const std::string client_hwid = mid;
        const std::string now = Util::current_utc_rfc3339();

        for (auto& entry : fs::directory_iterator(cwd)) {
            auto fn = entry.path().filename().string();
            Util::log("ServerApp: saw file %s", fn.c_str());

            if (fn.size() >= 13 && fn.substr(fn.size() - 13) == "_license.json") {
                Util::log("ServerApp:   testing license file %s", fn.c_str());
                try {
                    // load & parse
                    std::string txt = Util::slurp_file(entry.path().string());
                    auto doc = json::parse(txt);
                    auto payload = doc.at("payload");
                    std::string hwid = payload.at("hwid").get<std::string>();
                    std::string expires = payload.at("expires").get<std::string>();

                    // decode & verify signature
                    auto b64sig = doc.at("signature").get<std::string>();
                    auto sig = Util::from_base64(b64sig);
                    std::string canon = payload.dump();
                    bool sig_ok = CryptoUtils::rsa_pss_verify(
                        SERVER_PUB_PEM,
                        (uint8_t*)canon.data(), canon.size(),
                        sig.data(), sig.size());
                    Util::log("ServerApp:     signature %s",
                        sig_ok ? "OK" : "FAIL");

                    // check HWID and expiry
                    Util::log("ServerApp:     payload.hwid = %s", hwid.c_str());
                    Util::log("ServerApp:     client_hwid = %s", client_hwid.c_str());
                    bool hwid_ok = (hwid == client_hwid);
                    Util::log("ServerApp:     hwid match %s",
                        hwid_ok ? "YES" : "NO");

                    bool time_ok = (now <= expires);
                    Util::log("ServerApp:     now = %s", now.c_str());
                    Util::log("ServerApp:     expires = %s", expires.c_str());
                    Util::log("ServerApp:     not expired %s",
                        time_ok ? "YES" : "NO");

                    if (sig_ok && hwid_ok && time_ok) {
                        Util::log("ServerApp: license %s passes all checks", fn.c_str());
                        license_ok = true;
                        break;
                    }
                }
                catch (const std::exception& e) {
                    Util::log("ServerApp: error validating %s: %s",
                        fn.c_str(), e.what());
                }
            }
        }

        if (!license_ok) {
            Util::log("ServerApp: no valid license found for HWID %s",
                client_hwid.c_str());

            // send FAIL here:
            json resp_fail = { {"status", "FAIL: no valid license"} };
            auto ptf = resp_fail.dump();
            std::vector<uint8_t> fframe;
            m_crypto->encrypt_frame(
                Protocol::FrameType::Data,
                std::vector<uint8_t>(ptf.begin(), ptf.end()),
                fframe);
            m_server.send_message(
                client_sock,
                Protocol::FrameType::Data,
                fframe.data(), fframe.size());

            return false;
        }

        // 6) everything passed
        Util::log("ServerApp: client fully authenticated and licensed");

        // send final OK (optional—client will already have seen "OK" from step 4)
        json resp_ok = { {"status", "OK"} };
        auto pto = resp_ok.dump();
        std::vector<uint8_t> oframe;
        m_crypto->encrypt_frame(
            Protocol::FrameType::Data,
            std::vector<uint8_t>(pto.begin(), pto.end()),
            oframe);
        m_server.send_message(
            client_sock,
            Protocol::FrameType::Data,
            oframe.data(), oframe.size());

        return true;
    }

} // namespace ServerApp