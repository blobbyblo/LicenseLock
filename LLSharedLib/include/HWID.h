#pragma once

#include <string>

// HWID - hardware identifier
namespace HWID {

    // Gather hardware identifiers (CPU serial, primary NIC MAC, BIOS UUID)
    std::string get_machine_id();

}
