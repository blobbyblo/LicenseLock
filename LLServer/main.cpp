#include "Util.h"
#include "Protocol.h"
#include "NetworkServer.h"

#include <vector>
#include <string>
#include <winsock2.h>

int main() {
    const uint16_t kPort = 28199;

    Util::log("LLServer starting up, listening on port %u...", kPort);

    NetworkServer server;
    if (!server.bind("0.0.0.0", kPort)) {
        Util::log("ERROR: Failed to bind/listen on port %u", kPort);
        return 1;
    }

    Util::log("Waiting for client connection...");
    intptr_t clientSock = server.accept_client();
    if (clientSock == INVALID_SOCKET) {
        Util::log("ERROR: accept_client() failed");
        return 1;
    }
    Util::log("Client connected (sock=%lld)", (long long)clientSock);

    // Receive exactly one frame
    Protocol::FrameType frameType;
    std::vector<uint8_t> payload;
    if (!server.receive_message(clientSock, frameType, payload)) {
        Util::log("ERROR: receive_message() failed");
        return 1;
    }

    if (frameType == Protocol::FrameType::Handshake) {
        std::string msg(payload.begin(), payload.end());
        Util::log("Received Handshake payload: \"%s\"", msg.c_str());
    }
    else {
        Util::log("Received unexpected frame type: 0x%02X",
            uint8_t(frameType));
    }

    Util::log("Shutting down.");
	system("pause");

    return 0;
}
