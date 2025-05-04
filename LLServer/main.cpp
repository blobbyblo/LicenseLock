#include "Util.h"
#include "ServerApp.h"

int main()
{
    const uint16_t port = 28199;

    Util::log("LLServer: starting up");
    ServerApp app(port);
    if (!app.run()) {
        Util::log("LLServer: run failed");
        return 1;
    }
    Util::log("LLServer: exiting");

    system("pause");

    return 0;
}
