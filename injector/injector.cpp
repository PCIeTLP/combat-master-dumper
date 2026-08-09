#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <string>

static DWORD PidByName(const char* exe) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe{}; pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    if (Process32First(snap, &pe))
        do { if (_stricmp(pe.szExeFile, exe) == 0) { pid = pe.th32ProcessID; break; } }
        while (Process32Next(snap, &pe));
    CloseHandle(snap);
    return pid;
}

static bool EnableDebugPrivilege() {
    HANDLE tok;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) return false;
    LUID luid;
    bool ok = false;
    if (LookupPrivilegeValueA(nullptr, SE_DEBUG_NAME, &luid)) {
        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        ok = AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), nullptr, nullptr) &&
             GetLastError() == ERROR_SUCCESS;
    }
    CloseHandle(tok);
    return ok;
}

static HMODULE RemoteModule(DWORD pid, const char* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return nullptr;
    MODULEENTRY32 me{}; me.dwSize = sizeof(me);
    HMODULE h = nullptr;
    if (Module32First(snap, &me))
        do { if (_stricmp(me.szModule, name) == 0) { h = me.hModule; break; } }
        while (Module32Next(snap, &me));
    CloseHandle(snap);
    return h;
}

static int Unload(DWORD pid, const char* moduleName) {
    HMODULE rem = RemoteModule(pid, moduleName);
    if (!rem) { printf("[*] %s is not loaded in pid %lu\n", moduleName, pid); return 0; }
    HANDLE p = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                           PROCESS_VM_OPERATION | PROCESS_VM_READ, FALSE, pid);
    if (!p) { printf("[!] OpenProcess failed (%lu)\n", GetLastError()); return 1; }
    auto freeLib = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "FreeLibrary");
    int rc = 1;

    for (int i = 0; i < 8; i++) {
        if (!RemoteModule(pid, moduleName)) { rc = 0; break; }
        HANDLE th = CreateRemoteThread(p, nullptr, 0, freeLib, rem, 0, nullptr);
        if (!th) { printf("[!] CreateRemoteThread failed (%lu)\n", GetLastError()); break; }
        WaitForSingleObject(th, 10000);
        CloseHandle(th);
    }
    if (rc == 0) printf("[+] %s unloaded from pid %lu\n", moduleName, pid);
    else printf("[!] %s still loaded\n", moduleName);
    CloseHandle(p);
    return rc;
}

int main(int argc, char** argv) {
    std::string dll, procName = "CombatMaster.exe";
    DWORD pid = 0;
    bool unload = false;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--dll" && i + 1 < argc) dll = argv[++i];
        else if (a == "--process" && i + 1 < argc) procName = argv[++i];
        else if (a == "--pid" && i + 1 < argc) pid = (DWORD)strtoul(argv[++i], nullptr, 10);
        else if (a == "--unload") unload = true;
        else if (a == "--help" || a == "-h") {
            printf("usage: injector.exe [--dll path] [--process name.exe | --pid N] [--unload]\n"
                   "  --unload  force-unload an already-injected combat_master_dumper.dll\n");
            return 0;
        }
    }
    if (unload) {
        EnableDebugPrivilege();
        if (!pid) pid = PidByName(procName.c_str());
        if (!pid) { printf("[!] process not running: %s\n", procName.c_str()); return 2; }
        return Unload(pid, "combat_master_dumper.dll");
    }
    if (dll.empty()) {
        char self[MAX_PATH]{};
        GetModuleFileNameA(nullptr, self, MAX_PATH);
        std::string d(self);
        d = d.substr(0, d.find_last_of("\\/") + 1);
        dll = d + "combat_master_dumper.dll";
    }
    char full[MAX_PATH]{};
    if (!GetFullPathNameA(dll.c_str(), MAX_PATH, full, nullptr) || GetFileAttributesA(full) == INVALID_FILE_ATTRIBUTES) {
        printf("[!] dll not found: %s\n", dll.c_str());
        return 1;
    }
    EnableDebugPrivilege();

    if (!pid) pid = PidByName(procName.c_str());
    if (!pid) { printf("[!] process not running: %s\n", procName.c_str()); return 2; }
    printf("[*] target pid %lu\n[*] injecting %s\n", pid, full);

    HANDLE p = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                           PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
    if (!p) { printf("[!] OpenProcess failed (%lu)\n", GetLastError()); return 3; }

    size_t n = strlen(full) + 1;
    LPVOID rem = VirtualAllocEx(p, nullptr, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!rem) { printf("[!] VirtualAllocEx failed (%lu)\n", GetLastError()); CloseHandle(p); return 4; }
    if (!WriteProcessMemory(p, rem, full, n, nullptr)) {
        printf("[!] WriteProcessMemory failed (%lu)\n", GetLastError());
        VirtualFreeEx(p, rem, 0, MEM_RELEASE); CloseHandle(p); return 5;
    }
    auto loadLib = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    HANDLE th = CreateRemoteThread(p, nullptr, 0, loadLib, rem, 0, nullptr);
    if (!th) {
        printf("[!] CreateRemoteThread failed (%lu)\n", GetLastError());
        VirtualFreeEx(p, rem, 0, MEM_RELEASE); CloseHandle(p); return 6;
    }
    WaitForSingleObject(th, 30000);
    DWORD ec = 0; GetExitCodeThread(th, &ec);
    printf(ec ? "[+] LoadLibraryA returned 0x%lX - dumping in background\n"
              : "[!] LoadLibraryA returned NULL - injection failed\n", ec);
    CloseHandle(th);
    VirtualFreeEx(p, rem, 0, MEM_RELEASE);
    CloseHandle(p);
    return ec ? 0 : 7;
}
