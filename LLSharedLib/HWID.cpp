#include "HWID.h"
#include <windows.h>
#include <iphlpapi.h>
#include <intrin.h>
#include <vector>
#include <string>
#include <algorithm>
#include <wincrypt.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "crypt32.lib")

namespace {

    // Compute SHA-256 hash of data and return as lowercase hex string
    std::string sha256_hex(const std::vector<uint8_t>& data) {
        HCRYPTPROV hProv = 0;
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            return std::string();
        }
        HCRYPTHASH hHash = 0;
        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            CryptReleaseContext(hProv, 0);
            return std::string();
        }
        if (!CryptHashData(hHash, data.data(), (DWORD)data.size(), 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return std::string();
        }
        DWORD hashLen = 0;
        DWORD cbHashLen = sizeof(hashLen);
        if (!CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&hashLen, &cbHashLen, 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return std::string();
        }
        std::vector<uint8_t> hash(hashLen);
        if (!CryptGetHashParam(hHash, HP_HASHVAL, hash.data(), &hashLen, 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return std::string();
        }
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);

        static const char hexmap[] = "0123456789abcdef";
        std::string hex;
        hex.reserve(hashLen * 2);
        for (uint8_t b : hash) {
            hex.push_back(hexmap[b >> 4]);
            hex.push_back(hexmap[b & 0xF]);
        }
        return hex;
    }

    // Get CPU vendor string via __cpuid
    std::string get_cpu_vendor() {
        int cpuInfo[4] = { 0 };
        __cpuid(cpuInfo, 0);
        char vendor[13] = { 0 };
        *(int*)&vendor[0] = cpuInfo[1]; // EBX
        *(int*)&vendor[4] = cpuInfo[3]; // EDX
        *(int*)&vendor[8] = cpuInfo[2]; // ECX
        return std::string(vendor);
    }

    // Get first non-loopback MAC address in hex string
    std::string get_mac_address() {
        DWORD bufLen = 0;
        if (GetAdaptersInfo(NULL, &bufLen) != ERROR_BUFFER_OVERFLOW) {
            return std::string();
        }
        std::vector<uint8_t> buffer(bufLen);
        PIP_ADAPTER_INFO pInfo = (PIP_ADAPTER_INFO)buffer.data();
        if (GetAdaptersInfo(pInfo, &bufLen) != NO_ERROR) {
            return std::string();
        }
        for (PIP_ADAPTER_INFO p = pInfo; p; p = p->Next) {
            if (p->AddressLength == 6) {
                char mac[13] = { 0 };
                for (UINT i = 0; i < p->AddressLength; ++i) {
                    sprintf_s(mac + i * 2, 3, "%02x", p->Address[i]);
                }
                return std::string(mac);
            }
        }
        return std::string();
    }

    // Get volume serial number of C:\ as decimal string
    std::string get_volume_serial() {
        DWORD serial = 0;
        if (GetVolumeInformationA("C:\\", NULL, 0, &serial, NULL, NULL, NULL, 0)) {
            return std::to_string(serial);
        }
        return std::string();
    }

} // unnamed namespace

namespace HWID {

    std::string get_machine_id() {
        std::vector<std::string> parts;
        auto cpu = get_cpu_vendor();
        if (!cpu.empty()) parts.push_back(cpu);
        auto mac = get_mac_address();
        if (!mac.empty()) parts.push_back(mac);
        auto vol = get_volume_serial();
        if (!vol.empty()) parts.push_back(vol);

        if (parts.empty()) {
            return std::string();
        }
        std::sort(parts.begin(), parts.end());
        std::string concat;
        for (auto& s : parts) concat += s;
        std::vector<uint8_t> bytes(concat.begin(), concat.end());
        return sha256_hex(bytes);
    }

} // namespace HWID
