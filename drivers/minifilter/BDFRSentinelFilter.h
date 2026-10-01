#pragma once

#include <fltKernel.h>

#define BDFR_PROTOCOL_VERSION 1
#define BDFR_MAX_PATH_CHARS 1024

typedef enum _BDFR_POLICY_VERDICT {
    BdfrVerdictAllow = 0,
    BdfrVerdictBlock = 1
} BDFR_POLICY_VERDICT;

typedef struct _BDFR_SCAN_REQUEST {
    ULONG Version;
    ULONG ProcessId;
    ULONG DesiredAccess;
    WCHAR Path[BDFR_MAX_PATH_CHARS];
} BDFR_SCAN_REQUEST, *PBDFR_SCAN_REQUEST;

typedef struct _BDFR_SCAN_REPLY {
    ULONG Version;
    ULONG Verdict;
} BDFR_SCAN_REPLY, *PBDFR_SCAN_REPLY;
