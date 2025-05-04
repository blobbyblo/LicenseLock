#include "ServerApp.h"
#include "HandshakeServer.h"
#include "Protocol.h"
#include "Util.h"
#include "ServerKeys.h"
#include <nlohmann/json.hpp>

#include <winsock2.h>

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
    // 1) receive challenge request
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

    // Replace with your machine's HWID
    static constexpr char EXPECTED_HWID[] = "7ada8c099269283a6e93dc4357285c340a32d3ed77ba1552ce622f39580fcb9f";
    if (mid != EXPECTED_HWID) {
        Util::log("ServerApp: HWID mismatch (got %s, expected %s)",
            mid.c_str(), EXPECTED_HWID);
        return false;    // authentication fails immediately
    }

    // 2) issue one-time challenge
    m_challenge = Util::to_hex(Util::generate_random_bytes(16));
    json resp1 = { {"challenge", m_challenge} };
    auto pt1 = resp1.dump();

    std::vector<uint8_t> frame1;
    m_crypto->encrypt_frame(
        Protocol::FrameType::Data,
        std::vector<uint8_t>(pt1.begin(), pt1.end()),
        frame1);
    m_server.send_message(
        client_sock,
        Protocol::FrameType::Data,
        frame1.data(), frame1.size());

    // 3) receive auth request
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

    // 4) verify challenge matches
    json resp2;
    if (challenge == m_challenge) {
        resp2 = { {"status", "OK"} };
    }
    else {
        resp2 = { {"status", "FAIL"} };
    }
    auto pt2 = resp2.dump();

    std::vector<uint8_t> frame2;
    m_crypto->encrypt_frame(
        Protocol::FrameType::Data,
        std::vector<uint8_t>(pt2.begin(), pt2.end()),
        frame2);
    m_server.send_message(
        client_sock,
        Protocol::FrameType::Data,
        frame2.data(), frame2.size());

    return (challenge == m_challenge);
}
