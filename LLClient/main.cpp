#include "Util.h"
#include "Protocol.h"
#include "NetworkClient.h"
#include "HandshakeClient.h"

int main() {
    const char* host = "127.0.0.1";
    const uint16_t port = 28199;
    Util::log("LLClient connecting to %s:%u...", host, port);

    NetworkClient net;
    if (!net.connect(host, port)) {
        Util::log("ERROR: connect failed");
        return 1;
    }

    HandshakeClient hs(net);
    if (!hs.perform_handshake()) {
        Util::log("ERROR: handshake failed");
        return 1;
    }

    auto key = hs.get_session_key();
    Util::log("Client session key:");
    for (auto b : key) Util::log("%02x", b);

    system("pause");

    return 0;
}
