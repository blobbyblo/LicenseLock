#pragma once

#include <vector>
#include <string>
#include "NetworkServer.h"
#include "SessionCrypto.h"

class ServerApp {
public:
    // ctor takes listen port
    explicit ServerApp(uint16_t port);

    // Runs: bind -> accept -> handshake -> serve auth -> exit
    bool run();

private:
    NetworkServer        m_server;
    uint16_t             m_port;
    std::vector<uint8_t> m_session_key;
    SessionCrypto* m_crypto = nullptr;

    std::string          m_challenge;

    bool perform_handshake(intptr_t client_sock);
    bool serve_auth(intptr_t client_sock);
};
