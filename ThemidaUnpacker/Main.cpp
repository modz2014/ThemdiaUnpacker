#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <iostream>
#include <string>
#include <shlwapi.h> // for PathFileExists

/*bool SuspendThreadsByProcessID(DWORD processId) {
    HANDLE threadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (threadSnapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    THREADENTRY32 threadEntry;
    threadEntry.dwSize = sizeof(THREADENTRY32);
    if (!Thread32First(threadSnapshot, &threadEntry)) {
        CloseHandle(threadSnapshot);
        return false;
    }

    do {
        if (threadEntry.th32OwnerProcessID == processId) {
            HANDLE threadHandle = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadEntry.th32ThreadID);
            if (threadHandle != NULL) {
                SuspendThread(threadHandle);
                CloseHandle(threadHandle);
            }
        }
    } while (Thread32Next(threadSnapshot, &threadEntry));

    CloseHandle(threadSnapshot);
    return true;
}

bool ResumeThreadsByProcessID(DWORD processId) {
    HANDLE threadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (threadSnapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    THREADENTRY32 threadEntry;
    threadEntry.dwSize = sizeof(THREADENTRY32);
    if (!Thread32First(threadSnapshot, &threadEntry)) {
        CloseHandle(threadSnapshot);
        return false;
    }

    do {
        if (threadEntry.th32OwnerProcessID == processId) {
            HANDLE threadHandle = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadEntry.th32ThreadID);
            if (threadHandle != NULL) {
                while (ResumeThread(threadHandle) > 0) {}
                CloseHandle(threadHandle);
            }
        }
    } while (Thread32Next(threadSnapshot, &threadEntry));

    CloseHandle(threadSnapshot);
    return true;
}
*/


bool ModifyThreadsByProcessID(DWORD processId, bool suspend) {
    DWORD desiredAccess = suspend ? THREAD_SUSPEND_RESUME : THREAD_RESUME;

    HANDLE threadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (threadSnapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    THREADENTRY32 threadEntry;
    threadEntry.dwSize = sizeof(THREADENTRY32);
    if (!Thread32First(threadSnapshot, &threadEntry)) {
        CloseHandle(threadSnapshot);
        return false;
    }

    do {
        if (threadEntry.th32OwnerProcessID == processId) {
            HANDLE threadHandle = OpenThread(desiredAccess, FALSE, threadEntry.th32ThreadID);
            if (threadHandle != NULL) {
                if (suspend) {
                    SuspendThread(threadHandle);
                }
                else {
                    while (ResumeThread(threadHandle) > 0) {}
                }
                CloseHandle(threadHandle);
            }
        }
    } while (Thread32Next(threadSnapshot, &threadEntry));

    CloseHandle(threadSnapshot);
    return true;
}

bool IsClrjitDLLLoaded(DWORD processId) {
    HANDLE moduleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processId);
    if (moduleSnapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    MODULEENTRY32 moduleEntry;
    moduleEntry.dwSize = sizeof(MODULEENTRY32);
    if (Module32First(moduleSnapshot, &moduleEntry)) {
        do {
            if (_tcsicmp(moduleEntry.szModule, _T("clrjit.dll")) == 0) {
                CloseHandle(moduleSnapshot);
                return true;
            }
        } while (Module32Next(moduleSnapshot, &moduleEntry));
    }

    CloseHandle(moduleSnapshot);
    return false;
}

int main(int argc, char* argv[]) {
    MessageBox(nullptr, _T("Themida Unpacker"), _T("Info"), MB_OK);

    if (argc < 2) {
        MessageBox(nullptr, _T("Usage: Drag and drop the target file onto the executable."), _T("Error"), MB_OK);
        return 1;
    }

    bool suspendThreads = true; // Define the variable here

    // The first command-line argument (argv[1]) contains the path to the target file.
    _TCHAR targetPath[MAX_PATH];
    _stprintf_s(targetPath, _T("%S"), argv[1]);

    _TCHAR pdPath[MAX_PATH] = _T("");

    OPENFILENAME ofn;
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.lpstrFilter = _T("PD File (pd.exe)\0pd.exe\0");
    ofn.lpstrFile = pdPath;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = _T("Select pd.exe");
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

    if (GetOpenFileName(&ofn) == 0) {
        MessageBox(nullptr, _T("Please select the PD file."), _T("Error"), MB_OK);
        return 1;
    }

    int processId;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));

    if (CreateProcess(targetPath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        processId = pi.dwProcessId;
        std::wcout << L"WAIT..." << std::endl;
        while (true) {
            if (IsClrjitDLLLoaded(processId)) {
                ModifyThreadsByProcessID(processId, suspendThreads);
                std::wcout << L"Found clrjit.dll -> LOADED .NET" << std::endl;
                if (true) {
                    _TCHAR cmdLine[MAX_PATH];
                    _stprintf_s(cmdLine, _T("\"%s\" -pid %d"), pdPath, processId);

                    _TCHAR dumpDir[MAX_PATH] = _T("DUMP");

                    if (!PathFileExists(dumpDir)) {
                        // If the directory doesn't exist, create it
                        if (!CreateDirectory(dumpDir, NULL)) {
                            // If CreateDirectory fails, show an error message and return
                            MessageBox(nullptr, _T("Failed to create dump directory."), _T("Error"), MB_OK);
                            return 1;
                        }


                        if (CreateProcess(pdPath, cmdLine, NULL, NULL, FALSE, 0, NULL, dumpDir, &si, &pi));
                        {
                            MessageBox(nullptr, _T("DUMPED! If an error occurs, please dump it manually"), _T("Info"), MB_OK);
                            TerminateProcess(pi.hProcess, 0);
                            CloseHandle(pi.hProcess);
                            CloseHandle(pi.hThread);
                            return 0;
                        }
                    }
                    else {
                        // MessageBox(nullptr, _T("DUMP IT with SCYLLA! ") + _T(PathFindFileName(targetPath)) + _T(" PID: ") + std::to_wstring(processId) + _T("\nCheck Option:\nUse OriginalFirstThunk\nScan for Direct Imports\nFix Direct Imports UNIVERSAL\nUpdate header checksum\nCreate backup\nEnable debug privileges\nUse advanced IAT search\nRead APIs always from disk"), _T("Info"), MB_OK);
                        TerminateProcess(pi.hProcess, 0);
                        CloseHandle(pi.hProcess);
                        CloseHandle(pi.hThread);
                        return 0;
                    }
                }
            }
        }
    }
    else {
        MessageBox(nullptr, _T("Unknown Error: Run as Administrator and 32-bit for _32, 64-bit for _64"), _T("Error"), MB_OK);
        return 1;
    }
}
