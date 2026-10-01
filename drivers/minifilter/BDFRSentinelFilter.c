#include "BDFRSentinelFilter.h"

PFLT_FILTER gBdfrFilter = NULL;
PFLT_PORT gBdfrServerPort = NULL;
PFLT_PORT gBdfrClientPort = NULL;

DRIVER_INITIALIZE DriverEntry;

NTSTATUS
BdfrUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
BdfrPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

NTSTATUS
BdfrConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionPortCookie
);

VOID
BdfrDisconnect(
    _In_opt_ PVOID ConnectionCookie
);

CONST FLT_OPERATION_REGISTRATION gBdfrCallbacks[] = {
    {
        IRP_MJ_CREATE,
        0,
        BdfrPreCreate,
        NULL
    },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION gBdfrRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    gBdfrCallbacks,
    BdfrUnload,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;
    PSECURITY_DESCRIPTOR securityDescriptor = NULL;
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING portName;

    UNREFERENCED_PARAMETER(RegistryPath);

    status = FltRegisterFilter(
        DriverObject,
        &gBdfrRegistration,
        &gBdfrFilter
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = FltBuildDefaultSecurityDescriptor(
        &securityDescriptor,
        FLT_PORT_ALL_ACCESS
    );

    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gBdfrFilter);
        gBdfrFilter = NULL;
        return status;
    }

    RtlInitUnicodeString(&portName, L"\BDFRSentinelPort");

    InitializeObjectAttributes(
        &objectAttributes,
        &portName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        securityDescriptor
    );

    status = FltCreateCommunicationPort(
        gBdfrFilter,
        &gBdfrServerPort,
        &objectAttributes,
        NULL,
        BdfrConnect,
        BdfrDisconnect,
        NULL,
        1
    );

    FltFreeSecurityDescriptor(securityDescriptor);

    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gBdfrFilter);
        gBdfrFilter = NULL;
        return status;
    }

    status = FltStartFiltering(gBdfrFilter);

    if (!NT_SUCCESS(status)) {
        FltCloseCommunicationPort(gBdfrServerPort);
        gBdfrServerPort = NULL;
        FltUnregisterFilter(gBdfrFilter);
        gBdfrFilter = NULL;
    }

    return status;
}

NTSTATUS
BdfrUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Flags);

    if (gBdfrServerPort != NULL) {
        FltCloseCommunicationPort(gBdfrServerPort);
        gBdfrServerPort = NULL;
    }

    if (gBdfrClientPort != NULL) {
        FltCloseClientPort(gBdfrFilter, &gBdfrClientPort);
    }

    if (gBdfrFilter != NULL) {
        FltUnregisterFilter(gBdfrFilter);
        gBdfrFilter = NULL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
BdfrConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionPortCookie
)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    if (InterlockedCompareExchangePointer(
            (PVOID volatile *)&gBdfrClientPort,
            ClientPort,
            NULL) != NULL) {
        return STATUS_DEVICE_BUSY;
    }

    *ConnectionPortCookie = NULL;
    return STATUS_SUCCESS;
}

VOID
BdfrDisconnect(
    _In_opt_ PVOID ConnectionCookie
)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);

    if (gBdfrClientPort != NULL) {
        FltCloseClientPort(gBdfrFilter, &gBdfrClientPort);
    }
}

FLT_PREOP_CALLBACK_STATUS
BdfrPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
    ACCESS_MASK desiredAccess;
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    BDFR_SCAN_REQUEST request;
    BDFR_SCAN_REPLY reply;
    ULONG replySize = sizeof(reply);
    LARGE_INTEGER timeout;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (gBdfrClientPort == NULL ||
        Data->RequestorMode == KernelMode ||
        Data->Iopb->Parameters.Create.SecurityContext == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    desiredAccess =
        Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;

    if ((desiredAccess & FILE_EXECUTE) == 0) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo
    );

    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    RtlZeroMemory(&request, sizeof(request));
    RtlZeroMemory(&reply, sizeof(reply));

    request.Version = BDFR_PROTOCOL_VERSION;
    request.ProcessId = HandleToULong(PsGetCurrentProcessId());
    request.DesiredAccess = desiredAccess;

    if (nameInfo->Name.Buffer != NULL && nameInfo->Name.Length > 0) {
        ULONG chars = nameInfo->Name.Length / sizeof(WCHAR);
        chars = min(chars, BDFR_MAX_PATH_CHARS - 1);

        RtlCopyMemory(
            request.Path,
            nameInfo->Name.Buffer,
            chars * sizeof(WCHAR)
        );

        request.Path[chars] = L'\0';
    }

    FltReleaseFileNameInformation(nameInfo);

    //
    // Two-second relative timeout. Failure/timeouts are intentionally
    // fail-open so the filter cannot brick the endpoint if the service
    // is unavailable.
    //
    timeout.QuadPart = -(2LL * 10LL * 1000LL * 1000LL);

    status = FltSendMessage(
        gBdfrFilter,
        &gBdfrClientPort,
        &request,
        sizeof(request),
        &reply,
        &replySize,
        &timeout
    );

    if (!NT_SUCCESS(status) ||
        replySize < sizeof(reply) ||
        reply.Version != BDFR_PROTOCOL_VERSION) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (reply.Verdict == BdfrVerdictBlock) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
