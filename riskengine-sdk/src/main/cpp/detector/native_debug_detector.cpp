#include "native_debug_detector.h"
#include "../util/syscall_wrapper.h"
#include <string>
#include <cstring>
#include <cstdlib>
#include <fcntl.h>

int get_tracer_pid() {
    char buf[1024] = {0};
    int n = read_file_content("/proc/self/status", buf, sizeof(buf));
    if (n <= 0) return 0;

    char *line = strstr(buf, "TracerPid:");
    if (line) {
        return atoi(line + 10);
    }
    return 0;
}

bool check_ptrace() {
    // TRACEME can fail under policy restrictions and changes the caller's tracing state.
    // Only a positive TracerPid is evidence of an attached tracer.
    return get_tracer_pid() > 0;
}
