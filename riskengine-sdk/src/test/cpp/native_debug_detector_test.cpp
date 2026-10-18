#include "../../main/cpp/detector/native_debug_detector.h"
#include <cassert>
#include <cstring>
#include <string>

static std::string status;
extern "C" int read_file_content(const char *, char *buf, size_t size) {
    if (status.empty()) return -1;
    const auto count = status.copy(buf, size - 1);
    buf[count] = '\0';
    return static_cast<int>(count);
}

int main() {
    status = "Name:\tverifier\nTracerPid:\t0\n";
    assert(!check_ptrace());
    assert(!check_ptrace());
    status = "Name:\tverifier\nTracerPid:\t1234\n";
    assert(check_ptrace());
    status.clear();
    assert(!check_ptrace()); // Unavailable evidence must not become a positive detection.
}
