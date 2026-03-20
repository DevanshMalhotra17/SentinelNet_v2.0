#include "server.h"
#include "scanner.h"
#include <algorithm>
#include <ctime>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#endif

// Store scan results
struct ScanData {
  std::string ip;
  std::vector<int> ports;
  std::string timestamp;
};

struct NetworkConfig {
  std::string gateway;
  std::string subnet;
};

std::vector<ScanData> scanResults;
std::mutex dataMutex;
NetworkConfig networkConfig;

std::string jsonResponse(const std::string &json) {
  std::string response = "HTTP/1.1 200 OK\r\n";
  response += "Content-Type: application/json\r\n";
  response += "Access-Control-Allow-Origin: *\r\n";
  response += "Content-Length: " + std::to_string(json.length()) + "\r\n";
  response += "\r\n";
  response += json;
  return response;
}

std::string detectNetworkConfig() {
  NetworkScanner scanner;
  auto interfaces = scanner.getInterfaces();

  std::string gateway = "192.168.1.1";
  std::string subnet = "192.168.1.0/24";
  std::string bestIP = "";
  int bestScore = -1;

  std::cout << "Detecting network configuration..." << std::endl;

  // Score each interface to find the most likely "real" network
  for (const auto &iface : interfaces) {
    int score = 0;

    // Skip loopback
    if (iface.ip.find("127.0.0.1") == 0)
      continue;

    // Skip link-local addresses (169.254.x.x)
    if (iface.ip.find("169.254.") == 0)
      continue;

    // Skip common virtual network ranges
    if (iface.ip.find("192.168.56.") == 0)
      continue; // VirtualBox
    if (iface.ip.find("192.168.57.") == 0)
      continue; // VirtualBox
    if (iface.ip.find("192.168.99.") == 0)
      continue; // Docker

    // Prefer 10.0.0.x (common home/office network)
    if (iface.ip.find("10.0.0.") == 0) {
      score = 100;
    }
    // Then 192.168.1.x (most common home router)
    else if (iface.ip.find("192.168.1.") == 0) {
      score = 90;
    }
    // Then other 192.168.x.x
    else if (iface.ip.find("192.168.") == 0) {
      score = 80;
    }
    // Then other 10.x.x.x
    else if (iface.ip.find("10.") == 0) {
      score = 70;
    }

    if (score > bestScore) {
      bestScore = score;
      bestIP = iface.ip;
    }
  }

  // If we found a valid IP, derive gateway and subnet
  if (!bestIP.empty()) {
    size_t lastDot = bestIP.rfind('.');
    if (lastDot != std::string::npos) {
      std::string base = bestIP.substr(0, lastDot);
      gateway = base + ".1";
      subnet = base + ".0/24";
      std::cout << "  Detected IP: " << bestIP << std::endl;
      std::cout << "  Router: " << gateway << std::endl;
      std::cout << "  Network: " << subnet << std::endl;
    }
  } else {
    std::cout << "  No suitable network found, using defaults" << std::endl;
    std::cout << "  Router: " << gateway << std::endl;
    std::cout << "  Network: " << subnet << std::endl;
  }

  networkConfig.gateway = gateway;
  networkConfig.subnet = subnet;

  return "{\"gateway\":\"" + gateway + "\",\"network\":\"" + subnet + "\"}";
}

APIServer::APIServer(int port) : serverPort(port), isRunning(false) {}

APIServer::~APIServer() { stop(); }

#include <filesystem>
namespace fs = std::filesystem;

std::string readFile(const std::string &filepath) {
  std::ifstream file(filepath, std::ios::binary);
  if (!file.is_open()) {
    return "";
  }
  std::stringstream buffer;
  buffer << file.rdbuf();
  return buffer.str();
}

std::string getCurrentTime() {
  time_t now = time(nullptr);
  char buf[64];
  strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&now));
  return std::string(buf);
}

std::string buildScansJSON() {
  std::lock_guard<std::mutex> lock(dataMutex);

  std::string json = "{\"scans\":[";
  for (size_t i = 0; i < scanResults.size(); i++) {
    json += "{";
    json += "\"ip\":\"" + scanResults[i].ip + "\",";
    json += "\"timestamp\":\"" + scanResults[i].timestamp + "\",";
    json += "\"ports\":[";
    for (size_t j = 0; j < scanResults[i].ports.size(); j++) {
      json += std::to_string(scanResults[i].ports[j]);
      if (j < scanResults[i].ports.size() - 1)
        json += ",";
    }
    json += "]}";
    if (i < scanResults.size() - 1)
      json += ",";
  }
  json += "]}";

  return json;
}

void APIServer::start() {
  // Detect network configuration on startup
  std::string networkInfo = detectNetworkConfig();

  // Log initial state
  std::cout << "Initial scan results: " << scanResults.size() << std::endl;

  WSADATA wsa;
  WSAStartup(MAKEWORD(2, 2), &wsa);

  SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, 0);
  if (serverSocket == INVALID_SOCKET) {
    std::cerr << "Failed to create socket" << std::endl;
    return;
  }

  sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(serverPort);

  if (bind(serverSocket, (sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
    std::cerr << "Bind failed. Port " << serverPort << " may be in use."
              << std::endl;
    closesocket(serverSocket);
    return;
  }

  if (listen(serverSocket, 5) == SOCKET_ERROR) {
    std::cerr << "Listen failed" << std::endl;
    closesocket(serverSocket);
    return;
  }

  std::cout << "Server listening on port " << serverPort << "..." << std::endl;

  isRunning = true;

  while (isRunning) {
    SOCKET clientSocket = accept(serverSocket, nullptr, nullptr);
    if (clientSocket == INVALID_SOCKET)
      continue;

    std::string request;
    char buffer[4096];
    bool requestComplete = false;

    // Read until we find the end of the HTTP headers (\r\n\r\n)
    while (!requestComplete) {
      int bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
      if (bytesRead <= 0)
        break;
      buffer[bytesRead] = '\0';
      request.append(buffer, bytesRead);

      if (request.find("\r\n\r\n") != std::string::npos) {
        requestComplete = true;
      }

      // Safety break for extremely large requests
      if (request.length() > 65536)
        break;
    }

    if (request.empty()) {
      closesocket(clientSocket);
      continue;
    }

    std::string response;
    // Capture the request line for logging
    size_t lineEnd = request.find("\r\n");
    std::string requestLine =
        (lineEnd != std::string::npos) ? request.substr(0, lineEnd) : "INVALID";
    std::cout << "[REQUEST] " << requestLine << std::endl;

    if (request.find("GET /hack.js") != std::string::npos ||
        request.find("GET /web/hack.js") != std::string::npos) {
      std::string js = readFile("hack.js");
      if (js.empty())
        js = readFile("web/hack.js");
      if (js.empty())
        js = readFile("../web/hack.js");
      if (js.empty()) {
        response = "HTTP/1.1 404 Not Found\r\n\r\n404 - hack.js not found";
      } else {
        response =
            "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n" +
            js;
      }
    } else if (request.find("GET /hack") != std::string::npos ||
               request.find("GET /web/hack") != std::string::npos) {
      std::string html = readFile("hack.html");
      if (html.empty())
        html = readFile("web/hack.html");
      if (html.empty())
        html = readFile("../web/hack.html");
      if (html.empty()) {
        response = "HTTP/1.1 404 Not Found\r\n\r\n404 - Hack page not found";
      } else {
        response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + html;
      }
    } else if (request.find("GET /connect.html") != std::string::npos ||
               request.find("GET /web/connect.html") != std::string::npos) {
      std::string html = readFile("connect.html");
      if (html.empty())
        html = readFile("web/connect.html");
      if (html.empty())
        html = readFile("../web/connect.html");

      if (html.empty()) {
        response = "HTTP/1.1 404 Not Found\r\n\r\n404 - connect.html not found";
      } else {
        response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + html;
      }
    } else if (request.find("GET / ") != std::string::npos ||
               request.find("GET /dashboard.html") != std::string::npos ||
               request.find("GET /web/dashboard.html") != std::string::npos ||
               request.find("GET /index.html") != std::string::npos) {
      std::string html = readFile("dashboard.html");
      if (html.empty())
        html = readFile("web/dashboard.html");
      if (html.empty())
        html = readFile("index.html");
      if (html.empty())
        html = readFile("web/index.html");
      if (html.empty())
        html = readFile("../web/dashboard.html");

      if (html.empty()) {
        std::cerr << "  [ERROR] UI files not found!" << std::endl;
        response = "HTTP/1.1 404 Not Found\r\n\r\n404 - UI file not found";
      } else {
        response = "HTTP/1.1 200 OK\r\n"
                   "Content-Type: text/html\r\n"
                   "Content-Length: " +
                   std::to_string(html.length()) +
                   "\r\n"
                   "Connection: close\r\n\r\n" +
                   html;
      }
    } else if (request.find("GET /style.css") != std::string::npos ||
               request.find("GET /web/style.css") != std::string::npos) {
      std::string css = readFile("style.css");
      if (css.empty())
        css = readFile("web/style.css");
      if (css.empty())
        css = readFile("../web/style.css");

      if (css.empty()) {
        response = "HTTP/1.1 404 Not Found\r\n\r\n";
      } else {
        response = "HTTP/1.1 200 OK\r\n"
                   "Content-Type: text/css\r\n"
                   "Content-Length: " +
                   std::to_string(css.length()) +
                   "\r\n"
                   "Connection: close\r\n\r\n" +
                   css;
      }
    } else if (request.find("GET /script.js") != std::string::npos ||
               request.find("GET /web/script.js") != std::string::npos) {
      std::string js = readFile("script.js");
      if (js.empty())
        js = readFile("web/script.js");
      if (js.empty())
        js = readFile("../web/script.js");

      if (js.empty()) {
        response = "HTTP/1.1 404 Not Found\r\n\r\n";
      } else {
        response = "HTTP/1.1 200 OK\r\n"
                   "Content-Type: application/javascript\r\n"
                   "Content-Length: " +
                   std::to_string(js.length()) +
                   "\r\n"
                   "Connection: close\r\n\r\n" +
                   js;
      }
    } else if (request.find("GET /hack1.js") != std::string::npos ||
               request.find("GET /web/hack1.js") != std::string::npos) {
      std::string js = readFile("hack1.js");
      if (js.empty())
        js = readFile("../web/hack1.js");
      if (js.empty()) {
        response = "HTTP/1.1 404 Not Found\r\n\r\n404 - hack1.js not found";
      } else {
        response =
            "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n" +
            js;
      }
    } else if (request.find("GET /api/scans") != std::string::npos) {
      std::string json = buildScansJSON();
      response = "HTTP/1.1 200 OK\r\nContent-Type: "
                 "application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n" +
                 json;
    } else if (request.find("GET /api/alerts") != std::string::npos) {
      response = "HTTP/1.1 200 OK\r\nContent-Type: "
                 "application/json\r\nAccess-Control-Allow-Origin: "
                 "*\r\n\r\n{\"alerts\":[]}";
    } else if (request.find("GET /api/discover") != std::string::npos) {
      std::cout
          << "[API] Network discovery requested (using fast parallel scan)"
          << std::endl;

      NetworkScanner scanner;
      std::vector<std::string> hosts =
          scanner.discoverActiveHosts(networkConfig.subnet);

      std::string json = "{\"hosts\":[";
      for (size_t i = 0; i < hosts.size(); i++) {
        json += "\"" + hosts[i] + "\"";
        if (i < hosts.size() - 1)
          json += ",";
      }
      json += "]}";

      std::cout << "[API] Discovery complete. Found " << hosts.size()
                << " hosts" << std::endl;
      response = "HTTP/1.1 200 OK\r\nContent-Type: "
                 "application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n" +
                 json;
    } else if (request.find("GET /api/network-info") != std::string::npos) {
      std::string json = "{\"gateway\":\"" + networkConfig.gateway +
                         "\",\"network\":\"" + networkConfig.subnet + "\"}";
      response = "HTTP/1.1 200 OK\r\nContent-Type: "
                 "application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n" +
                 json;
    } else if (request.find("POST /api/scan/trigger") != std::string::npos) {
      std::cout << "[API] Scan trigger received" << std::endl;

      // Parse body for target IP
      size_t bodyStart = request.find("\r\n\r\n");
      std::string target = "127.0.0.1";

      if (bodyStart != std::string::npos) {
        std::string body = request.substr(bodyStart + 4);
        std::cout << "[DEBUG] Body: " << body << std::endl;

        // Simple JSON parsing for target
        size_t targetPos = body.find("\"target\"");
        if (targetPos != std::string::npos) {
          size_t start = body.find("\"", targetPos + 8);
          size_t end = body.find("\"", start + 1);
          if (start != std::string::npos && end != std::string::npos) {
            target = body.substr(start + 1, end - start - 1);
          }
        }
      }

      std::cout << "[SCAN] Starting scan of " << target << std::endl;

      std::vector<int> openPorts;

      try {
        // Check if host is alive first
        NetworkScanner scanner;

        std::cout << "[PING] Checking if " << target << " is reachable..."
                  << std::endl;
        bool isAlive = scanner.isHostAlive(target, 1000);

        if (!isAlive) {
          std::cout << "[PING] Host " << target << " is not responding to ping"
                    << std::endl;
        }

        // Scan ports anyway (some hosts block ping but have open ports)
        std::vector<int> commonPorts = {21,  22,  23,  25,   80,   135,
                                        139, 443, 445, 3306, 3389, 8080};
        openPorts = scanner.scanPorts(target, commonPorts);

        std::cout << "[SCAN] Scan completed successfully" << std::endl;
      } catch (const std::exception &e) {
        std::cerr << "[ERROR] Scan exception: " << e.what() << std::endl;
      } catch (...) {
        std::cerr << "[ERROR] Unknown scan error occurred" << std::endl;
      }

      // Store results even if no ports found
      {
        std::lock_guard<std::mutex> lock(dataMutex);
        ScanData data;
        data.ip = target;
        data.ports = openPorts;
        data.timestamp = getCurrentTime();
        scanResults.push_back(data);

        std::cout << "[DATA] Added scan result: " << target << " ("
                  << openPorts.size() << " ports)" << std::endl;
      }

      std::cout << "[SCAN] Completed scan of " << target << " - "
                << openPorts.size() << " ports open" << std::endl;

      response = "HTTP/1.1 200 OK\r\nContent-Type: "
                 "application/json\r\nAccess-Control-Allow-Origin: "
                 "*\r\n\r\n{\"status\":\"success\"}";
    } else if (request.find("POST /api/audit/fingerprint") !=
               std::string::npos) {
      std::cout << "[API] Fingerprint request received" << std::endl;

      // Parse body
      size_t bodyStart = request.find("\r\n\r\n");
      if (bodyStart == std::string::npos) {
        response = jsonResponse("{\"error\":\"No body\"}");
      } else {
        std::string body = request.substr(bodyStart + 4);

        // Parse target IP
        std::string target = "";
        int port = 0;

        size_t targetPos = body.find("\"target\"");
        if (targetPos != std::string::npos) {
          size_t start = body.find("\"", targetPos + 8);
          size_t end = body.find("\"", start + 1);
          if (start != std::string::npos && end != std::string::npos) {
            target = body.substr(start + 1, end - start - 1);
          }
        }

        size_t portPos = body.find("\"port\"");
        if (portPos != std::string::npos) {
          size_t colonPos = body.find(":", portPos);
          if (colonPos != std::string::npos) {
            size_t numStart = colonPos + 1;
            while (numStart < body.length() &&
                   (body[numStart] == ' ' || body[numStart] == '\t')) {
              numStart++;
            }
            std::string portStr = "";
            while (numStart < body.length() && isdigit(body[numStart])) {
              portStr += body[numStart++];
            }
            if (!portStr.empty()) {
              port = std::stoi(portStr);
            }
          }
        }

        if (target.empty() || port == 0) {
          response = jsonResponse("{\"error\":\"Invalid request\"}");
        } else {
          std::cout << "[FINGERPRINT] Grabbing banner from " << target << ":"
                    << port << std::endl;

          try {
            NetworkScanner scanner;
            AuditResult result = scanner.grabBanner(target, port);

            std::string json = "{";
            json += "\"port\":" + std::to_string(result.port) + ",";
            json += "\"service\":\"" + result.service + "\",";

            // Escape banner string for JSON
            std::string escapedBanner = result.banner;
            size_t pos = 0;
            while ((pos = escapedBanner.find("\"", pos)) != std::string::npos) {
              escapedBanner.replace(pos, 1, "\\\"");
              pos += 2;
            }
            pos = 0;
            while ((pos = escapedBanner.find("\n", pos)) != std::string::npos) {
              escapedBanner.replace(pos, 1, "\\n");
              pos += 2;
            }
            pos = 0;
            while ((pos = escapedBanner.find("\r", pos)) != std::string::npos) {
              escapedBanner.replace(pos, 1, "\\r");
              pos += 2;
            }

            json += "\"banner\":\"" + escapedBanner + "\"";
            json += "}";

            std::cout << "[FINGERPRINT] Service: " << result.service
                      << std::endl;
            response =
                "HTTP/1.1 200 OK\r\nContent-Type: "
                "application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n" +
                json;
          } catch (...) {
            response = jsonResponse("{\"error\":\"Fingerprint failed\"}");
          }
        }
      }
    } else if (request.find("POST /api/clear") != std::string::npos) {
      std::lock_guard<std::mutex> lock(dataMutex);
      scanResults.clear();
      std::cout << "[DATA] Cleared all scan results" << std::endl;
      response = "HTTP/1.1 200 OK\r\nContent-Type: "
                 "application/json\r\nAccess-Control-Allow-Origin: "
                 "*\r\n\r\n{\"status\":\"success\"}";
    } else {
      response = "HTTP/1.1 404 Not Found\r\n\r\n404 Not Found";
    }

    send(clientSocket, response.c_str(), response.length(), 0);
    closesocket(clientSocket);
  }

  closesocket(serverSocket);
  WSACleanup();
}

void APIServer::stop() { isRunning = false; }