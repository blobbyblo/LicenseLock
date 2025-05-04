#include "NetworkClient.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include "Util.h"

#pragma comment(lib, "ws2_32.lib") // Link with ws2_32.lib

NetworkClient::NetworkClient()
	: m_socket(INVALID_SOCKET)
{
	// Initialize Winsock
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		Util::log("WSAStartup failed\n");
	}
}

NetworkClient::~NetworkClient()
{
	if (m_socket != INVALID_SOCKET) {
		closesocket(m_socket);
		WSACleanup();
	}
}

bool NetworkClient::connect(const char* host, uint16_t port)
{
	// Create socket
	m_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (m_socket == INVALID_SOCKET) {
		Util::log("Socket creation failed\n");
		return false;
	}
	// Resolve server address
	struct sockaddr_in server_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	inet_pton(AF_INET, host, &server_addr.sin_addr);
	// Connect to server
	if (::connect(m_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
		Util::log("Connection failed\n");
		closesocket(m_socket);
		m_socket = INVALID_SOCKET;
		return false;
	}
	return true;
}

bool NetworkClient::send_message(Protocol::FrameType type, const uint8_t* payload, size_t payload_len)
{
	if (payload_len > Protocol::MAX_PAYLOAD_SIZE) {
		Util::log("Payload size exceeds maximum\n");
		return false;
	}
	// Prepare the message
	size_t total_size = Protocol::HEADER_SIZE + payload_len;
	std::vector<uint8_t> message(total_size);
	message[0] = static_cast<uint8_t>(type);
	Protocol::write_be_length(message.data() + 1, static_cast<uint16_t>(payload_len));
	if (payload && payload_len > 0) {
		std::copy(payload, payload + payload_len, message.data() + Protocol::HEADER_SIZE);
	}
	// Send the message
	int bytes_sent = send(m_socket, reinterpret_cast<const char*>(message.data()), static_cast<int>(total_size), 0);
	if (bytes_sent == SOCKET_ERROR) {
		Util::log("Send failed\n");
		return false;
	}
	return true;
}

bool NetworkClient::receive_message(Protocol::FrameType& type, std::vector<uint8_t>& payload)
{
	// Read the header
	uint8_t header[Protocol::HEADER_SIZE];
	int bytes_received = recv(m_socket, reinterpret_cast<char*>(header), Protocol::HEADER_SIZE, 0);
	if (bytes_received <= 0) {
		Util::log("Receive failed\n");
		return false;
	}
	type = static_cast<Protocol::FrameType>(header[0]);
	size_t payload_len = Protocol::read_be_length(header + 1);
	if (payload_len > Protocol::MAX_PAYLOAD_SIZE) {
		Util::log("Payload size exceeds maximum\n");
		return false;
	}
	// Read the payload
	payload.resize(payload_len);
	bytes_received = recv(m_socket, reinterpret_cast<char*>(payload.data()), static_cast<int>(payload_len), 0);
	if (bytes_received <= 0) {
		Util::log("Receive failed\n");
		return false;
	}
	return true;
}
