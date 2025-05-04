#pragma once

#include <cstdint>
#include <vector>

#include "Protocol.h" // from LLSharedLib

class NetworkClient {

public:
	NetworkClient();
	~NetworkClient();

	// Connect to server at host:port, returns false on error
	bool connect(const char* host, uint16_t port);

	// Send a framed message [Type|Length|Payload]
	bool send_message(Protocol::FrameType type, const uint8_t* payload, size_t payload_len);

	// Receive a framed message (blocking until frame received)
	bool receive_message(Protocol::FrameType& type, std::vector<uint8_t>& payload);

private:
	intptr_t m_socket; // Socket handle

}; // class NetworkClient
