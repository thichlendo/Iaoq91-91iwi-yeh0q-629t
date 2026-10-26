#include <unistd.h>
#include <fstream>
#include <string>
#include <ctime>
#include <cstdlib>
#include <sys/ptrace.h>
#include "../engine/string_obfs.h"

namespace shield::security {

bool checkTracerPid() {
    std::ifstream statusFile(OBFS_STR("/proc/self/status"));
    if (!statusFile.is_open()) return false;

    std::string line;
    std::string target = OBFS_STR("TracerPid:");
    while (std::getline(statusFile, line)) {
        if (line.compare(0, target.length(), target) == 0) {
            int tracerPid = std::atoi(line.substr(target.length()).c_str());
            if (tracerPid != 0) {
                return true;
            }
            break;
        }
    }
    return false;
}

bool checkDebuggerTiming() {
    struct timespec start{}, end{};
    clock_gettime(CLOCK_MONOTONIC, &start);

    volatile int acc = 0;
    for (int i = 0; i < 10000; ++i) {
        acc += (i ^ 0x3F);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    long elapsedMs = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_nsec - start.tv_nsec) / 1000000;
    // Nếu vòng lặp nhỏ bị dừng quá 250ms -> Đang bị treo tại Breakpoint
    return elapsedMs > 250;
}

bool isDebuggerDetected() {
    return checkTracerPid() || checkDebuggerTiming();
}

} // namespace shield::security
