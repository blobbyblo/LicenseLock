#include "Util.h"
#include "ClientApp.h"

int main()
{
    const char* host = "127.0.0.1";
    const uint16_t port = 28199;

    Util::log("LLClient: starting up");
    ClientApp app(host, port);
    if (!app.run()) {
        Util::log("LLClient: run failed");
        return 1;
    }
    Util::log("LLClient: exiting");

	system("pause");

    return 0;
}
