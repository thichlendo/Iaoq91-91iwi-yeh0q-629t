#include <unistd.h>
#include <dirent.h>
#include <fstream>
#include <string>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "../engine/string_obfs.h"

namespace shield::security {

bool scanMapsForHooks() {
    std::ifstream maps(OBFS_STR("/proc/self/maps"));
    if (!maps.is_open()) return false;

    std::string line;
    std::string sFrida = OBFS_STR("frida");
    std::string sGadget = OBFS_STR("gadget");
    std::string sXposed = OBFS_STR("xposed");
    std::string sSubstrate = OBFS_STR("substrate");

    while (std::getline(maps, line)) {
        if (line.find(sFrida) != std::string::npos ||
            line.find(sGadget) != std::string::npos ||
            line.find(sXposed) != std::string::npos ||
            line.find(sSubstrate) != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool scanTaskThreads() {
    std::string taskDirStr = OBFS_STR("/proc/self/task");
    DIR* dir = opendir(taskDirStr.c_str());
    if (!dir) return false;

    std::string sGum = OBFS_STR("gum-js-loop");
    std::string sGmain = OBFS_STR("gmain");
    std::string sPoolFrida = OBFS_STR("pool-frida");

    struct dirent* entry;
    bool found = false;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_name[0] == '.') continue;
        std::string commPath = taskDirStr + "/" + entry->d_name + OBFS_STR("/comm");
        std::ifstream commFile(commPath);
        if (commFile.is_open()) {
            std::string threadName;
            std::getline(commFile, threadName);
            if (threadName.find(sGum) != std::string::npos ||
                threadName.find(sGmain) != std::string::npos ||
                threadName.find(sPoolFrida) != std::string::npos) {
                found = true;
                break;
            }
        }
    }
    closedir(dir);
    return found;
}

bool checkFridaDefaultPort() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    struct sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(27042);
    inet_pton(AF_INET, OBFS_STR("127.0.0.1").c_str(), &sa.sin_addr);

    struct timeval tv{0, 100000}; // Timeout 100ms
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));

    bool open = (connect(sock, reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa)) == 0);
    close(sock);
    return open;
}

bool isHookingDetected() {
    return scanMapsForHooks() || scanTaskThreads() || checkFridaDefaultPort();
}

} // namespace shield::security
