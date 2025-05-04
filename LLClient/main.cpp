#include <iostream>

#include "NetworkClient.h"

#include "Protocol.h"    // from LLSharedLib

int main()
{
    std::cout << "LicenseLock LLClient starting up..." << std::endl;

    NetworkClient net;
    if (!net.connect("127.0.0.1", 28199)) return 1;
    std::vector<uint8_t> msg = { 'H','I' };
    net.send_message(Protocol::FrameType::Handshake, msg.data(), msg.size());

    system("pause");

    return 0;
}
