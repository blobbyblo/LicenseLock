#pragma once

#include <vector>
#include <cstdint>

#include "NetworkServer.h" // from LLServer
#include "Protocol.h" // from LLSharedLib

class HandshakeServer {

public:
	// Construct with an already-connected NetworkServer
	explicit HandshakeServer(NetworkServer& server);

	// Performs the RSA-OAEP handshake. Returns false on failure
	bool perform_handshake(intptr_t client_socket);

	// After handshake, returns the 32 byte session key
	const std::vector<uint8_t>& get_session_key() const;

private:
	NetworkServer& m_server;
	std::vector<uint8_t> m_session_key; // 32-byte session key

}; // class HandshakeServer
