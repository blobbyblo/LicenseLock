#include "Util.h"
#include "Protocol.h"
#include "NetworkServer.h"
#include "HandshakeServer.h"

#include <winsock2.h>

int main() {
    const uint16_t kPort = 28199;
    Util::log("LLServer starting, listening on port %u...", kPort);

    NetworkServer server;
    if (!server.bind("0.0.0.0", kPort)) {
        Util::log("ERROR: listen failed");
        return 1;
    }

    Util::log("Waiting for client...");
    intptr_t clientSock = server.accept_client();
    if (clientSock == INVALID_SOCKET) {
        Util::log("ERROR: accept_client failed");
        return 1;
    }
    Util::log("Client connected on sock %lld", (long long)clientSock);

    HandshakeServer hs(server);
    if (!hs.perform_handshake(clientSock)) {
        Util::log("ERROR: handshake failed");
        return 1;
    }

    // Now we have the session key:
    auto key = hs.get_session_key();
    Util::log("Server session key:");
    for (auto b : key) Util::log("%02x", b);

    system("pause");

    return 0;
}
