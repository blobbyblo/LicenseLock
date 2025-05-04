#pragma once

#include <vector>
#include <cstdint>

#include "NetworkClient.h" // from LLClient
#include "Protocol.h" // from LLSharedLib

class HandshakeClient {

public:
	// Construct with an already-connected NetworkClient
	explicit HandshakeClient(NetworkClient& client);

	// Performs the RSA-OAEP handshake. Returns false on failure
	bool perform_handshake();

	// After handshake, returns the 32 byte session key
	const std::vector<uint8_t>& get_session_key() const;

private:
	NetworkClient& m_client;
	std::vector<uint8_t> m_session_key; // 32-byte session key

}; // class HandshakeClient
