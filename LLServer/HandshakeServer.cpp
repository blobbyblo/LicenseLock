#include "HandshakeServer.h"
#include "CryptoUtils.h"
#include "Util.h"
#include "ServerKeys.h"

HandshakeServer::HandshakeServer(NetworkServer& server)
	: m_server(server)
{
}

bool HandshakeServer::perform_handshake(intptr_t client_socket)
{
	// Receive the encrypted session key from the client
	std::vector<uint8_t> encrypted_key;
	Protocol::FrameType frame_type;
	if (!m_server.receive_message(client_socket, frame_type, encrypted_key)) {
		Util::log("ERROR: Failed to receive handshake message");
		return false;
	}
	if (frame_type != Protocol::FrameType::Handshake) {
		Util::log("ERROR: Unexpected frame type received");
		return false;
	}
	// Decrypt the session key using RSA-OAEP
	m_session_key = CryptoUtils::rsa_decrypt(encrypted_key, SERVER_PRIV_PEM);
	if (m_session_key.empty()) {
		Util::log("ERROR: RSA decryption failed");
		return false;
	}
	return true;
}

const std::vector<uint8_t>& HandshakeServer::get_session_key() const
{
	return m_session_key;
}
