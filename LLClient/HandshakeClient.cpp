#include "HandshakeClient.h"

#include "CryptoUtils.h" // from LLSharedLib
#include "Util.h" // from LLSharedLib
#include "ClientKeys.h" // from LLClient

HandshakeClient::HandshakeClient(NetworkClient& client)
	: m_client(client)
{
	// Generate a random 32-byte session key
	m_session_key = Util::generate_random_bytes(32);
}

bool HandshakeClient::perform_handshake()
{
	// Encrypt the session key using RSA-OAEP
	std::vector<uint8_t> encrypted_key = CryptoUtils::rsa_encrypt(m_session_key, SERVER_PUB_PEM);
	if (encrypted_key.empty()) {
		Util::log("ERROR: RSA encryption failed");
		return false;
	}
	// Send the encrypted session key to the server
	if (!m_client.send_message(Protocol::FrameType::Handshake, encrypted_key.data(), encrypted_key.size())) {
		Util::log("ERROR: Failed to send handshake message");
		return false;
	}
	return true;
}

const std::vector<uint8_t>& HandshakeClient::get_session_key() const
{
	return m_session_key;
}
