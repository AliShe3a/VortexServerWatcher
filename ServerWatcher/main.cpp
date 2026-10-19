#include <cstdlib>
#include <iostream>
#include <TlHelp32.h>
#include <string>
#include <Windows.h>
#include <DbgHelp.h>

//int main() {
//    const char* serviceExecutablePath = "C:\\pmang\\crossfire\\cf_loginsrv\\cf_loginsrv.exe";// Replace with the actual path to your service executable
//
//    // Launch the service executable, creating a console window
//    int result = std::system(serviceExecutablePath);
//
//    if (result == 0) {
//        std::cout << "Service started with a console window." << std::endl;
//    }
//    else {
//        std::cerr << "Failed to start the service with a console window." << std::endl;
//    }
//
//    return 0;
//}

DWORD FindProcessIdByExeName(const std::wstring& exeName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32W processEntry = { sizeof(PROCESSENTRY32W) };

    if (Process32FirstW(snapshot, &processEntry)) {
        do {
            if (std::wstring(processEntry.szExeFile) == exeName) {
                CloseHandle(snapshot);
                return processEntry.th32ProcessID;
            }
        } while (Process32NextW(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    return 0;
}

int main() {
    const std::wstring targetExeName = L"cf_loginsrv.exe"; // Replace with the name of your service executable
    DWORD servicePID = FindProcessIdByExeName(targetExeName);

    if (servicePID != 0) {
        if (AttachConsole(servicePID)) {
            std::wcout << L"Attached to the service's console." << std::endl;
        }
        else {
            if (GetLastError() == ERROR_ACCESS_DENIED) {
                std::wcerr << L"Failed to attach due to access denied. Please run this program as administrator." << std::endl;
            }
            else {
                std::wcerr << L"Failed to attach to the service's console." << std::endl;
            }
        }
    }
    else {
        std::wcerr << L"Service process not found." << std::endl;
    }

    return 0;
}

