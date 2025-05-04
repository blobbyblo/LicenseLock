#include "ClientApp.h"
#include "HandshakeClient.h"
#include "Protocol.h"
#include "Util.h"
#include "HWID.h"
#include "ClientKeys.h"
#include <nlohmann/json.hpp>

using json = nlohmann::json;

ClientApp::ClientApp(const char* host, uint16_t port)
    : m_client()
{
    if (!m_client.connect(host, port)) {
        Util::log("ClientApp: connect failed");
    }
}

bool ClientApp::run()
{
    if (!perform_handshake()) return false;
    m_crypto = new SessionCrypto(m_session_key);

    if (!perform_challenge()) return false;
    if (!perform_auth())      return false;

    Util::log("ClientApp: authentication succeeded");
    return true;
}

bool ClientApp::perform_handshake()
{
    HandshakeClient hs(m_client);
    if (!hs.perform_handshake()) {
        Util::log("ClientApp: handshake failed");
        return false;
    }
    m_session_key = hs.get_session_key();
    return true;
}

bool ClientApp::perform_challenge()
{
    // build { "mid": "<hwid>" }
    json req = { {"mid", HWID::get_machine_id()} };
    auto pt = req.dump();

    std::vector<uint8_t> frame;
    m_crypto->encrypt_frame(
        Protocol::FrameType::Data,
        std::vector<uint8_t>(pt.begin(), pt.end()),
        frame);

    if (!m_client.send_message(
        Protocol::FrameType::Data,
        frame.data(), frame.size()))
    {
        Util::log("ClientApp: send challenge failed");
        return false;
    }

    // receive response
    Protocol::FrameType ft;
    std::vector<uint8_t> in_frame, body;
    if (!m_client.receive_message(ft, in_frame)) {
        Util::log("ClientApp: recv challenge response failed");
        return false;
    }
    if (!m_crypto->decrypt_frame(in_frame, ft, body)) {
        Util::log("ClientApp: decrypt challenge response failed");
        return false;
    }

    auto resp = json::parse(body);
    m_challenge = resp["challenge"].get<std::string>();
    return true;
}

bool ClientApp::perform_auth()
{
    // build { "mid":..., "challenge":... }
    json req = {
        {"mid", HWID::get_machine_id()},
        {"challenge", m_challenge}
    };
    auto pt = req.dump();

    std::vector<uint8_t> frame;
    m_crypto->encrypt_frame(
        Protocol::FrameType::Data,
        std::vector<uint8_t>(pt.begin(), pt.end()),
        frame);

    if (!m_client.send_message(
        Protocol::FrameType::Data,
        frame.data(), frame.size()))
    {
        Util::log("ClientApp: send auth failed");
        return false;
    }

    // receive auth response
    Protocol::FrameType ft;
    std::vector<uint8_t> in_frame, body;
    if (!m_client.receive_message(ft, in_frame)) {
        Util::log("ClientApp: recv auth response failed");
        return false;
    }
    if (!m_crypto->decrypt_frame(in_frame, ft, body)) {
        Util::log("ClientApp: decrypt auth response failed");
        return false;
    }

    auto resp = json::parse(body);
    if (resp["status"] != "OK") {
        Util::log("ClientApp: authentication rejected");
        return false;
    }
    return true;
}
