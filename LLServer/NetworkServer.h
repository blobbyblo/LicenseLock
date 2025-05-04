#pragma once

#include <cstdint>
#include <vector>

#include "Protocol.h" // from LLSharedLib

class NetworkServer {

public:
	NetworkServer();
	~NetworkServer();

	// Bind to host:port and start listening
	bool bind(const char* host, uint16_t port);

	// Block until a client connects, returns INVALID_SOCKET on error
	intptr_t accept_client();

	// Send a framed message [Type|Length|Payload] to the client
	bool send_message(intptr_t client_socket, Protocol::FrameType type, const uint8_t* payload, size_t payload_len);

	// Receive a framed message from the client (blocking until frame received)
	bool receive_message(intptr_t client_socket, Protocol::FrameType& type, std::vector<uint8_t>& payload);

private:
	intptr_t m_listen_socket; // Listening socket handle

}; // class NetworkServer
