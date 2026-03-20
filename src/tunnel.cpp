#include "tunnel.h"
#include <string>
#include <vector>
#include <windows.h>
#include <winhttp.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "winhttp.lib")

#define VERCEL_HOST "sentinelnet-v2.vercel.app"
#define REPORT_PATH "/api/report"

static void httpsPost(const std::string &host, const std::string &path,
                      const std::string &body) {
  HINTERNET hSession =
      WinHttpOpen(L"SentinelNet/2.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                  WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  if (!hSession)
    return;

  WinHttpSetTimeouts(hSession, 5000, 5000, 5000, 5000);

  HINTERNET hConnect =
      WinHttpConnect(hSession, std::wstring(host.begin(), host.end()).c_str(),
                     INTERNET_DEFAULT_HTTPS_PORT, 0);
  if (!hConnect) {
    WinHttpCloseHandle(hSession);
    return;
  }

  std::wstring wPath(path.begin(), path.end());
  HINTERNET hRequest = WinHttpOpenRequest(
      hConnect, L"POST", wPath.c_str(), nullptr, WINHTTP_NO_REFERER,
      WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);

  if (hRequest) {
    std::wstring wHeaders(L"Content-Type: application/json\r\n");
    WinHttpAddRequestHeaders(hRequest, wHeaders.c_str(), -1L,
                             WINHTTP_ADDREQ_FLAG_ADD);

    WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                       (LPVOID)body.c_str(), body.size(), body.size(), 0);

    WinHttpReceiveResponse(hRequest, nullptr);
    WinHttpCloseHandle(hRequest);
  }

  WinHttpCloseHandle(hConnect);
  WinHttpCloseHandle(hSession);
}

void TunnelManager::start() {
  // Commit 1: Pure Beacon Mode (Removes all Cloudflare dependencies)
  // Its ONLY job is to tell Vercel that PC2 is online every 10 seconds.
  while (true) {
    std::string body = "{\"url\":\"online\"}";
    httpsPost(VERCEL_HOST, REPORT_PATH, body);

    // Wait 10s before the next heartbeat
    Sleep(10000);
  }
}