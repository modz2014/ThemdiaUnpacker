#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <iostream>
#include <string>

bool SuspendProcess(DWORD dwProcessId) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    if (!Thread32First(hSnapshot, &te32)) {
        CloseHandle(hSnapshot);
        return false;
    }

    do {
        if (te32.th32OwnerProcessID == dwProcessId) {
            HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
            if (hThread != NULL) {
                SuspendThread(hThread);
                CloseHandle(hThread);
            }
        }
    } while (Thread32Next(hSnapshot, &te32));

    CloseHandle(hSnapshot);
    return true;
}

bool ResumeProcess(DWORD dwProcessId) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    if (!Thread32First(hSnapshot, &te32)) {
        CloseHandle(hSnapshot);
        return false;
    }

    do {
        if (te32.th32OwnerProcessID == dwProcessId) {
            HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
            if (hThread != NULL) {
                while (ResumeThread(hThread) > 0) {}
                CloseHandle(hThread);
            }
        }
    } while (Thread32Next(hSnapshot, &te32));

    CloseHandle(hSnapshot);
    return true;
}

bool HasLoadedClrjitDLL(DWORD dwProcessId) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    MODULEENTRY32 me32;
    me32.dwSize = sizeof(MODULEENTRY32);
    if (Module32First(hSnapshot, &me32)) {
        do {
            if (_tcsicmp(me32.szModule, _T("clrjit.dll")) == 0) {
                CloseHandle(hSnapshot);
                return true;
            }
        } while (Module32Next(hSnapshot, &me32));
    }

    CloseHandle(hSnapshot);
    return false;
}

int main(int argc, char* argv[]) {
    MessageBox(nullptr, _T("Themida Unpacker"), _T("Info"), MB_OK);

    if (argc < 2) {
        MessageBox(nullptr, _T("Usage: Drag and drop the target file onto the executable."), _T("Error"), MB_OK);
        return 1;
    }

    // The first command-line argument (argv[1]) contains the path to the target file.
    _TCHAR path[MAX_PATH];
    _stprintf_s(path, _T("%S"), argv[1]);

    _TCHAR pd_path[MAX_PATH] = _T("");

    OPENFILENAME ofn;
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.lpstrFilter = _T("PD File (pd.exe)\0pd.exe\0");
    ofn.lpstrFile = pd_path;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = _T("Select pd.exe");
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

    if (GetOpenFileName(&ofn) == 0) {
        MessageBox(nullptr, _T("Please select the PD file."), _T("Error"), MB_OK);
        return 1;
    }

    int pid;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));

    if (CreateProcess(path, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        pid = pi.dwProcessId;
        std::wcout << L"WAIT..." << std::endl;
        while (true) {
            if (HasLoadedClrjitDLL(pid)) {
                SuspendProcess(pid);
                std::wcout << L"Found clrjit.dll -> LOADED .NET" << std::endl;
                if (MessageBox(nullptr, _T("May I AutoDump?"), _T("Question"), MB_YESNO) == IDYES) {
                    _TCHAR cmdLine[MAX_PATH];
                    _stprintf_s(cmdLine, _T("\"%s\" -pid %d"), pd_path, pid);
                    CreateProcess(pd_path, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
                    MessageBox(nullptr, _T("DUMPED! If an error occurs, please dump it manually"), _T("Info"), MB_OK);
                    TerminateProcess(pi.hProcess, 0);
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                    return 0;
                }
                else {
                    //MessageBox(nullptr, _T("DUMP IT with SCYLLA! ") + _T(PathFindFileName(path)) + _T(" PID: ") + std::to_wstring(pid) + _T("\nCheck Option:\nUse OriginalFirstThunk\nScan for Direct Imports\nFix Direct Imports UNIVERSAL\nUpdate header checksum\nCreate backup\nEnable debug privileges\nUse advanced IAT search\nRead APIs always from disk"), _T("Info"), MB_OK);
                    TerminateProcess(pi.hProcess, 0);
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                    return 0;
                }
            }
        }
    }
    else {
        MessageBox(nullptr, _T("Unknown Error: Run as Administrator and 32-bit for _32, 64-bit for _64"), _T("Error"), MB_OK);
        return 1;
    }
}