#pragma once

#include <string>
#include <vector>
#include "NetworkClient.h"
#include "SessionCrypto.h"

class ClientApp {
public:
    // ctor takes server host and port
    ClientApp(const char* host, uint16_t port);

    // Runs: handshake -> challenge -> auth
    bool run();

private:
    NetworkClient        m_client;
    std::vector<uint8_t> m_session_key;
    SessionCrypto* m_crypto = nullptr;

    std::string          m_challenge;

    bool perform_handshake();
    bool perform_challenge();
    bool perform_auth();
};
