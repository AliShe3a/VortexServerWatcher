#include "LoginServer.h"
#include <iostream>
#include <fstream>
#include <string>
#include <algorithm>

std::string Trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    if (std::string::npos == first) return str;
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, (last - first + 1));
}

std::string GetConfigValue(const std::string& section, const std::string& key, const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) return "";

    std::string line;
    std::string currentSection;

    while (std::getline(file, line)) {
        line = Trim(line);
        if (line.empty() || line[0] == ';') continue; 

        if (line.front() == '[' && line.back() == ']') {
            currentSection = line.substr(1, line.size() - 2);
            continue;
        }

        if (currentSection == section) {
            size_t delimiterPos = line.find('=');
            if (delimiterPos != std::string::npos) {
                std::string currentKey = Trim(line.substr(0, delimiterPos));
                if (currentKey == key) {
                    return Trim(line.substr(delimiterPos + 1));
                }
            }
        }
    }
    return ""; 
}

int main()
{
    const std::string configFile = "./config.ini";
    const std::string sectionName = "VORTEX_PROTECTION_BY_SHE3A";

    std::cout << "Loading configuration from " << configFile << "..." << std::endl;

    std::string ipStr = GetConfigValue(sectionName, "IP", configFile);
    std::string lPortStr = GetConfigValue(sectionName, "LPORT", configFile);
    std::string exLPortStr = GetConfigValue(sectionName, "EXLPORT", configFile);

    if (ipStr.empty()) {
        std::cout << "Warning: IP not found in config, using default 127.0.0.1" << std::endl;
        ipStr = "127.0.0.1";
    }

    int srvPort = lPortStr.empty() ? 28888 : std::stoi(lPortStr);
    int exSrvPort = exLPortStr.empty() ? 18889 : std::stoi(exLPortStr);

    std::cout << "Server Config -> IP: " << ipStr << " | LPort: " << srvPort << " | ExPort: " << exSrvPort << std::endl;

    ProxyServer proxyServer(ipStr.c_str(), srvPort, ipStr.c_str(), exSrvPort);
    proxyServer.Start();

    return 0;
}