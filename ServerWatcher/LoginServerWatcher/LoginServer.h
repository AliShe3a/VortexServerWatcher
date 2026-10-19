#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <fstream>
#include <winsock2.h>
#include <windows.h> 
#include <vector>
#include <string>
#include <map>
#include <set>
#include "maxminddb.h"



#pragma comment(lib, "ws2_32.lib")

int GLOBAL_DEBUG_MODE = 0;
 int MAX_PPS = 500;
 int MAX_BPS = 2 * 1024 * 1024;
 int GLOBAL_MAX_CONNECTIONS = 500;
 int MAX_CONNS_PER_IP = 10;
 int CONN_RATE_MS = 200;
 int PRE_AUTH_TIMEOUT_MS = 30000;
int ENABLE_BLACKLIST = 0;

std::string ADMIN_IP_1 = "127.0.0.1";
std::string ADMIN_IP_2 = "127.0.0.1";

void LoadBlacklistFromFile();

void UpdateIntConfig(const char* name, int& currentVal, int newVal) {
    if (currentVal != newVal) {
        std::cout << "[Config] " << name << " updated: " << currentVal << " -> " << newVal << std::endl;
        currentVal = newVal;
    }
}

void LoadConfiguration(bool silent = false) {
    const char* iniFile = ".\\config.ini";

    int new_debug = GetPrivateProfileIntA("LOGIN_CONFIG", "GLOBAL_DEBUG_MODE", 0, iniFile);
    int new_pps = GetPrivateProfileIntA("LOGIN_CONFIG", "MAX_PPS", 1500, iniFile);
    int new_bps = GetPrivateProfileIntA("LOGIN_CONFIG", "MAX_BPS", 5242880, iniFile);
    int new_g_max = GetPrivateProfileIntA("LOGIN_CONFIG", "GLOBAL_MAX_CONNECTIONS", 700, iniFile);
    int new_ip_max = GetPrivateProfileIntA("LOGIN_CONFIG", "MAX_CONNS_PER_IP", 30, iniFile);
    int new_rate = GetPrivateProfileIntA("LOGIN_CONFIG", "CONN_RATE_MS", 250, iniFile);
    int new_timeout = GetPrivateProfileIntA("LOGIN_CONFIG", "PRE_AUTH_TIMEOUT_MS", 35000, iniFile);
    int new_blacklist = GetPrivateProfileIntA("LOGIN_CONFIG", "ENABLE_BLACKLIST", 1, iniFile);

    UpdateIntConfig("GLOBAL_DEBUG_MODE", GLOBAL_DEBUG_MODE, new_debug);
    UpdateIntConfig("MAX_PPS", MAX_PPS, new_pps);
    UpdateIntConfig("MAX_BPS", MAX_BPS, new_bps);
    UpdateIntConfig("GLOBAL_MAX_CONNECTIONS", GLOBAL_MAX_CONNECTIONS, new_g_max);
    UpdateIntConfig("MAX_CONNS_PER_IP", MAX_CONNS_PER_IP, new_ip_max);
    UpdateIntConfig("CONN_RATE_MS", CONN_RATE_MS, new_rate);
    UpdateIntConfig("PRE_AUTH_TIMEOUT_MS", PRE_AUTH_TIMEOUT_MS, new_timeout);

    if (ENABLE_BLACKLIST != new_blacklist) {
        ENABLE_BLACKLIST = new_blacklist;
        std::cout << "[Config] ENABLE_BLACKLIST updated: " << new_blacklist << std::endl;
        if (ENABLE_BLACKLIST) LoadBlacklistFromFile();
    }

    char buffer[64];
    GetPrivateProfileStringA("LOGIN_CONFIG", "ADMIN_IP_1", "127.0.0.1", buffer, 64, iniFile);
    std::string new_admin1 = buffer;
    if (ADMIN_IP_1 != new_admin1) { ADMIN_IP_1 = new_admin1; std::cout << "[Config] ADMIN_IP_1 Updated.\n"; }

    GetPrivateProfileStringA("LOGIN_CONFIG", "ADMIN_IP_2", "127.0.0.1", buffer, 64, iniFile);
    std::string new_admin2 = buffer;
    if (ADMIN_IP_2 != new_admin2) { ADMIN_IP_2 = new_admin2; std::cout << "[Config] ADMIN_IP_2 Updated.\n"; }

    if (!silent) {
        std::cout << "[System] Configuration Initialized." << std::endl;
    }
}

DWORD WINAPI ConfigWatcherThread(LPVOID lpParam) {
    while (true) {
        Sleep(3000);
        LoadConfiguration(true);
    }
    return 0;
}

class FastMutex {
public:
    FastMutex() { InitializeCriticalSection(&m_cs); }
    ~FastMutex() { DeleteCriticalSection(&m_cs); }
    void lock() { EnterCriticalSection(&m_cs); }
    void unlock() { LeaveCriticalSection(&m_cs); }
private:
    CRITICAL_SECTION m_cs;
    FastMutex(const FastMutex&);
    FastMutex& operator=(const FastMutex&);
};

class FastGuard {
public:
    explicit FastGuard(FastMutex& m) : m_mutex(m) { m_mutex.lock(); }
    ~FastGuard() { m_mutex.unlock(); }
private:
    FastMutex& m_mutex;
    FastGuard(const FastGuard&);
    FastGuard& operator=(const FastGuard&);
};

FastMutex& GetIpMutex() { static FastMutex m; return m; }
std::map<std::string, int>& GetIpConnections() { static std::map<std::string, int> m; return m; }
std::map<std::string, DWORD>& GetLastConnTime() { static std::map<std::string, DWORD> m; return m; }
FastMutex& GetBlacklistMutex() { static FastMutex m; return m; }
std::set<std::string>& GetBlacklist() { static std::set<std::string> m; return m; }

volatile long g_activeConnections = 0;

void LoadBlacklistFromFile() {
    FastGuard lock(GetBlacklistMutex());
    std::ifstream file("blacklist.txt");
    if (!file.is_open()) return;

    std::string line;
    int count = 0;
    while (std::getline(file, line)) {
        size_t first = line.find_first_not_of(" \t\r\n");
        if (std::string::npos == first) continue;
        size_t last = line.find_last_not_of(" \t\r\n");
        std::string ip = line.substr(first, (last - first + 1));

        if (!ip.empty()) {
            GetBlacklist().insert(ip);
            count++;
        }
    }
    if (GLOBAL_DEBUG_MODE && count > 0) {
        std::cout << "[System] Loaded " << count << " IPs from blacklist.txt" << std::endl;
    }
}

class GeoGuard {
public:
    static GeoGuard& Instance() { static GeoGuard instance; return instance; }
    bool Initialize(const std::string& dbPath) {
        int status = MMDB_open(dbPath.c_str(), MMDB_MODE_MMAP, &m_mmdb);
        if (status != MMDB_SUCCESS) {
            std::cerr << "[GeoIP] Error opening database: " << MMDB_strerror(status) << std::endl;
            m_initialized = false;
            return false;
        }
        m_initialized = true;
        std::cout << "[GeoIP] Database loaded successfully." << std::endl;
        return true;
    }
    bool IsAllowedCountry(const std::string& ipStr) {
        if (!m_initialized) return true;
        if (ipStr == "127.0.0.1" || ipStr == ADMIN_IP_1) return true;
        int gai_error, mmdb_error;
        MMDB_lookup_result_s result = MMDB_lookup_string(&m_mmdb, ipStr.c_str(), &gai_error, &mmdb_error);
        if (gai_error != 0 || mmdb_error != MMDB_SUCCESS) return true;
        if (!result.found_entry) return true;
        MMDB_entry_data_s entry_data;
        int status = MMDB_get_value(&result.entry, &entry_data, "country", "iso_code", NULL);
        if (status == MMDB_SUCCESS && entry_data.has_data) {
            std::string countryCode(entry_data.utf8_string, entry_data.data_size);
            if (countryCode == "VN") return true;
            if (GLOBAL_DEBUG_MODE) std::cout << "[DEBUG][GeoIP] Blocking IP: " << ipStr << " Country: " << countryCode << std::endl;
        }
        else return true;
        return false;
    }
    ~GeoGuard() { if (m_initialized) MMDB_close(&m_mmdb); }
private:
    GeoGuard() : m_initialized(false) {}
    MMDB_s m_mmdb;
    bool m_initialized;
};

struct ProtoData { byte aDummy[17399]; };
#pragma pack(push, 1)
struct T_PACKET {
    uint8_t tStartByte; uint16_t wSize;
    uint8_t firstClass; uint8_t secondClass; uint8_t thirdClass;
    uint8_t extensionPacketCount; uint8_t extensionPacketCurCount;
    ProtoData userData;
};
#pragma pack(pop)

class CPacket {
public:
    CPacket(const uint8_t* buffer, size_t size) {
        m_nRecordedSize = (size > 17408) ? 17408 : (uint16_t)size;
        memcpy(m_staticBuffer, buffer, m_nRecordedSize);
    }
    uint8_t GetStartByte() const { if (m_nRecordedSize < 1) return 0; return ((T_PACKET*)m_staticBuffer)->tStartByte; }
    uint16_t GetSize() const { if (m_nRecordedSize < 3) return 0; return ((T_PACKET*)m_staticBuffer)->wSize; }
    uint8_t GetExtensionPacketCount() const { if (m_nRecordedSize < 7) return 0; return ((T_PACKET*)m_staticBuffer)->extensionPacketCount; }
    uint8_t GetExtensionPacketCurCount() const { if (m_nRecordedSize < 8) return 0; return ((T_PACKET*)m_staticBuffer)->extensionPacketCurCount; }
private:
    uint8_t m_staticBuffer[17408];
    uint16_t m_nRecordedSize;
};

class ProxyClient {
public:
    ProxyClient(SOCKET client, const char* targetIp, int targetPort, std::string clientIp)
        : clientSocket(client), tIp(targetIp), tPort(targetPort), clientIp(clientIp), targetSocket(INVALID_SOCKET) 
    {

        m_totalExtensionSize = 0;
        m_expectedExtensionIndex = 1;
        m_isReassembling = false;
        m_targetExtensionCount = 0;

        isAdmin = (clientIp == ADMIN_IP_1 || clientIp == ADMIN_IP_2);
        HANDLE hThread = CreateThread(NULL, 0, ThreadEntry, this, 0, NULL);
        if (hThread) CloseHandle(hThread); else CleanUpAndSelfDelete();
    }
    static DWORD WINAPI ThreadEntry(LPVOID lpParam) {
        ProxyClient* pClient = (ProxyClient*)lpParam;
        if (pClient) {
            try { pClient->Run(); }
            catch (...) {}
            pClient->CleanUpAndSelfDelete();
        }
        return 0;
    }
    void CleanUpAndSelfDelete() {
        {
            FastGuard lock(GetIpMutex());
            std::map<std::string, int>& conns = GetIpConnections();
            if (conns[this->clientIp] > 0) conns[this->clientIp]--;
        }
        InterlockedDecrement(&g_activeConnections);
        if (GLOBAL_DEBUG_MODE) std::cout << "[DEBUG] Client disconnected: " << this->clientIp << std::endl;
        delete this;
    }
private:
    SOCKET clientSocket, targetSocket;
    std::string tIp; int tPort;
    std::string clientIp; bool isAdmin;
    int m_totalExtensionSize;
    int m_expectedExtensionIndex;  
    int m_currentExtensionID;      
    bool m_isReassembling;         
    int m_targetExtensionCount;   

    void SetSocketOptions(SOCKET s) {
        int nodelay = 1; setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char*)&nodelay, sizeof(int));
        linger solinger; solinger.l_onoff = 1; solinger.l_linger = 0;
        setsockopt(s, SOL_SOCKET, SO_LINGER, (const char*)&solinger, sizeof(solinger));
    }

    void BanIP(const std::string& reason)
    {

        if (!ENABLE_BLACKLIST)
            return;

        FastGuard lock(GetBlacklistMutex());

        if (GetBlacklist().count(clientIp)) return;

        GetBlacklist().insert(clientIp);

        std::ofstream file("blacklist.txt", std::ios::app);
        if (file.is_open()) {
            file << clientIp << std::endl;
            file.close();
        }

        if (GLOBAL_DEBUG_MODE) std::cout << "[BLOCK] IP: " << clientIp << " Reason: " << reason << " (Saved to blacklist.txt)" << std::endl;
        CloseSockets();
    }

    void Run() {
        m_totalExtensionSize = 0;
        if (GLOBAL_DEBUG_MODE) std::cout << "[DEBUG] New Client Thread Started: " << clientIp << std::endl;
        {

            if (ENABLE_BLACKLIST) {
                FastGuard lock(GetBlacklistMutex());
                if (GetBlacklist().count(clientIp)) {
                    if (GLOBAL_DEBUG_MODE) std::cout << "[DEBUG] IP is in Blacklist, dropping." << std::endl;
                    CloseSockets(); return;
                }
            }
        }
        DWORD timeout = PRE_AUTH_TIMEOUT_MS;
        setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
        char firstBuffer[4096];
        int bytesReceived = recv(clientSocket, firstBuffer, sizeof(firstBuffer), 0);
        if (bytesReceived < 8) { CloseSockets(); return; }
        CPacket checkPacket((uint8_t*)firstBuffer, bytesReceived);
        if (checkPacket.GetStartByte() != 241) {
            BanIP("Invalid StartByte (Not 241)"); return;
        }
        if (ConnectToTarget()) {
            SetSocketOptions(clientSocket); SetSocketOptions(targetSocket);
            DWORD noTimeout = 0; setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&noTimeout, sizeof(noTimeout));
            send(targetSocket, firstBuffer, bytesReceived, 0);
            HANDLE hS2C = CreateThread(NULL, 0, StaticForwardServerToClient, this, 0, NULL);
            ForwardClientToServer();
            if (hS2C) { WaitForSingleObject(hS2C, INFINITE); CloseHandle(hS2C); }
        }
        CloseSockets();
    }
    bool ConnectToTarget() {
        for (int i = 0; i < 2; i++) {
            targetSocket = socket(AF_INET, SOCK_STREAM, 0);
            if (targetSocket == INVALID_SOCKET) return false;
            sockaddr_in addr; addr.sin_family = AF_INET; addr.sin_port = htons(tPort);
            inet_pton(AF_INET, tIp.c_str(), &(addr.sin_addr));
            if (connect(targetSocket, (struct sockaddr*)&addr, sizeof(addr)) != SOCKET_ERROR) return true;
            closesocket(targetSocket);
        }
        return false;
    }
    static DWORD WINAPI StaticForwardServerToClient(LPVOID lpParam) {
        ProxyClient* p = (ProxyClient*)lpParam; if (p) p->ForwardServerToClient(); return 0;
    }
    void ForwardClientToServer() {

        char buffer[16384]; int bytesRead;

        DWORD lastReset = GetTickCount64(); int ppsCount = 0; int bpsCount = 0;

        while (true) {

            {
                if (ENABLE_BLACKLIST) {
                    FastGuard lock(GetBlacklistMutex());

                    if (GetBlacklist().count(clientIp)) break;
                }
            }

            bytesRead = recv(clientSocket, buffer, sizeof(buffer), 0);

            if (bytesRead <= 0) break;

            DWORD now = GetTickCount64();

            if ((now - lastReset) >= 1000) { ppsCount = 0; bpsCount = 0; lastReset = now; }

            ppsCount++; bpsCount += bytesRead;

            if (!isAdmin && (ppsCount > MAX_PPS || bpsCount > MAX_BPS)) {

                if (ppsCount > MAX_PPS * 1.5) { BanIP("Extreme Rate Limit Exceeded"); break; }

            }

            if (bytesRead >= 8) {

                CPacket cpacket((uint8_t*)buffer, bytesRead);

                if (cpacket.GetExtensionPacketCount() > 0) {

                    if (cpacket.GetExtensionPacketCurCount() == 1) m_totalExtensionSize = bytesRead;

                    else m_totalExtensionSize += bytesRead;

                    if (m_totalExtensionSize > 17408) { BanIP("Buffer Overflow Attempt"); break; }

                }

                else m_totalExtensionSize = 0;

            }

            if (send(targetSocket, buffer, bytesRead, 0) <= 0) break;

        }

        shutdown(clientSocket, SD_BOTH);

    }
    void ForwardServerToClient() {
        char buffer[16384]; int bytesRead;
        while (true) {
            if (targetSocket == INVALID_SOCKET) break;
            bytesRead = recv(targetSocket, buffer, sizeof(buffer), 0);
            if (bytesRead <= 0) break;
            if (send(clientSocket, buffer, bytesRead, 0) <= 0) break;
        }
        shutdown(clientSocket, SD_BOTH);
    }
    void CloseSockets() {
        if (clientSocket != INVALID_SOCKET) { closesocket(clientSocket); clientSocket = INVALID_SOCKET; }
        if (targetSocket != INVALID_SOCKET) { closesocket(targetSocket); targetSocket = INVALID_SOCKET; }
    }
};

class ProxyServer {
public:
    ProxyServer(const char* bIp, int bPort, const char* tIp, int tPort)
        : bindIp(bIp), bindPort(bPort), targetIp(tIp), targetPort(tPort) {
    }

    void Start() {
        WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);

        LoadConfiguration(false);

        HANDLE hConfigThread = CreateThread(NULL, 0, ConfigWatcherThread, NULL, 0, NULL);
        if (hConfigThread) CloseHandle(hConfigThread);

        if (ENABLE_BLACKLIST)
            LoadBlacklistFromFile();

        if (!GeoGuard::Instance().Initialize("GeoLite2-Country.mmdb")) {
            std::cout << "Warning: GeoIP DB not found. Geo blocking disabled!" << std::endl;
        }
        SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
        int opt = 1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
        sockaddr_in addr; addr.sin_family = AF_INET; addr.sin_port = htons(bindPort);
        inet_pton(AF_INET, bindIp, &(addr.sin_addr));
        if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
            std::cerr << "Bind failed: " << WSAGetLastError() << std::endl; return;
        }
        listen(s, SOMAXCONN);
        std::cout << ">> Login Shield v2 (By She3a) Online on " << bindPort << std::endl;
        while (true) {
            sockaddr_in cAddr; int cLen = sizeof(cAddr);
            SOCKET client = accept(s, (struct sockaddr*)&cAddr, &cLen);
            if (client == INVALID_SOCKET) continue;
            if (g_activeConnections >= GLOBAL_MAX_CONNECTIONS) {
                closesocket(client); Sleep(10); continue;
            }
            char ip[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &cAddr.sin_addr, ip, INET_ADDRSTRLEN);
            std::string clientIp(ip);
            bool isAdmin = (clientIp == ADMIN_IP_1 || clientIp == ADMIN_IP_2);
            {

                if (ENABLE_BLACKLIST) {
                    FastGuard lock(GetBlacklistMutex());
                    if (GetBlacklist().count(clientIp)) {
                        if (GLOBAL_DEBUG_MODE) std::cout << "[DEBUG] Rejected: IP " << clientIp << " is in blacklist." << std::endl;
                        closesocket(client); continue;
                    }
                }
            }
            if (!isAdmin && !GeoGuard::Instance().IsAllowedCountry(clientIp)) {
                closesocket(client); continue;
            }
            DWORD nowTs = GetTickCount64();
            {
                FastGuard lock(GetIpMutex());
                std::map<std::string, DWORD>& lastConn = GetLastConnTime();
                std::map<std::string, int>& ipConns = GetIpConnections();
                if (lastConn.size() > 5000) lastConn.clear();
                if (!isAdmin) {
                    if ((nowTs - lastConn[clientIp]) < CONN_RATE_MS) { closesocket(client); continue; }
                    if (ipConns[clientIp] >= MAX_CONNS_PER_IP) { closesocket(client); continue; }
                }
                ipConns[clientIp]++; lastConn[clientIp] = nowTs;
            }
            InterlockedIncrement(&g_activeConnections);
            new ProxyClient(client, targetIp, targetPort, clientIp);
        }
    }
private:
    const char* bindIp, * targetIp; int bindPort, targetPort;
};
