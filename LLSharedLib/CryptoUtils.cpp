#include "CryptoUtils.h"
#include "Util.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdexcept>

namespace CryptoUtils {

    // Helpers
    static void throwSSLError(const char* where) {
        unsigned long err = ERR_get_error();
        char buf[256];
        ERR_error_string_n(err, buf, sizeof buf);
        throw std::runtime_error(std::string(where) + ": " + buf);
    }

    // Encrypt with RSA-OAEP via EVP_PKEY
    std::vector<uint8_t> rsa_encrypt(const std::vector<uint8_t>& data,
        const std::string& keyPem)
    {
        // 1) Load public key
        BIO* bio = BIO_new_mem_buf(keyPem.data(), (int)keyPem.size());
        if (!bio) throw std::runtime_error("BIO_new_mem_buf failed");
        EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        BIO_free(bio);
        if (!pkey) throwSSLError("PEM_read_bio_PUBKEY");

        // 2) Create context & init
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
        EVP_PKEY_free(pkey);
        if (!ctx) throwSSLError("EVP_PKEY_CTX_new");
        if (EVP_PKEY_encrypt_init(ctx) <= 0) throwSSLError("EVP_PKEY_encrypt_init");
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
            throwSSLError("EVP_PKEY_CTX_set_rsa_padding");

        // 3) Determine buffer length
        size_t outlen = 0;
        if (EVP_PKEY_encrypt(ctx, NULL, &outlen, data.data(), data.size()) <= 0)
            throwSSLError("EVP_PKEY_encrypt (determine length)");

        std::vector<uint8_t> out(outlen);

        // 4) Perform encryption
        if (EVP_PKEY_encrypt(ctx, out.data(), &outlen, data.data(), data.size()) <= 0)
            throwSSLError("EVP_PKEY_encrypt");
        out.resize(outlen);

        EVP_PKEY_CTX_free(ctx);
        return out;
    }

    // Decrypt with RSA-OAEP via EVP_PKEY
    std::vector<uint8_t> rsa_decrypt(const std::vector<uint8_t>& data,
        const std::string& keyPem)
    {
        // 1) Load private key
        BIO* bio = BIO_new_mem_buf(keyPem.data(), (int)keyPem.size());
        if (!bio) throw std::runtime_error("BIO_new_mem_buf failed");
        EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        BIO_free(bio);
        if (!pkey) throwSSLError("PEM_read_bio_PrivateKey");

        // 2) Create context & init
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
        EVP_PKEY_free(pkey);
        if (!ctx) throwSSLError("EVP_PKEY_CTX_new");
        if (EVP_PKEY_decrypt_init(ctx) <= 0) throwSSLError("EVP_PKEY_decrypt_init");
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
            throwSSLError("EVP_PKEY_CTX_set_rsa_padding");

        // 3) Determine buffer length
        size_t outlen = 0;
        if (EVP_PKEY_decrypt(ctx, NULL, &outlen, data.data(), data.size()) <= 0)
            throwSSLError("EVP_PKEY_decrypt (determine length)");

        std::vector<uint8_t> out(outlen);

        // 4) Perform decryption
        if (EVP_PKEY_decrypt(ctx, out.data(), &outlen, data.data(), data.size()) <= 0)
            throwSSLError("EVP_PKEY_decrypt");
        out.resize(outlen);

        EVP_PKEY_CTX_free(ctx);
        return out;
    }

    // AES-GCM stays the same (calls through EVP), so no changes here…

} // namespace CryptoUtils
