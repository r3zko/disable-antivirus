#include <windows.h>
#include <iostream>
#include <string>

// Registry Keys
const wchar_t* defenderKey = L"SOFTWARE\\Policies\\Microsoft\\Windows Defender";
const wchar_t* realtimeKey = L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection";

// Disable Defender via Registry
void DisableDefenderRegistry() {
    HKEY hKey;
    DWORD disable = 1;

    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, defenderKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, L"DisableAntiSpyware", 0, REG_DWORD, (BYTE*)&disable, sizeof(disable));
        RegCloseKey(hKey);
    }

    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, realtimeKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, L"DisableRealtimeMonitoring", 0, REG_DWORD, (BYTE*)&disable, sizeof(disable));
        RegSetValueExW(hKey, L"DisableBehaviorMonitoring", 0, REG_DWORD, (BYTE*)&disable, sizeof(disable));
        RegSetValueExW(hKey, L"DisableOnAccessProtection", 0, REG_DWORD, (BYTE*)&disable, sizeof(disable));
        RegCloseKey(hKey);
    }
}

// Re-enable Defender via Registry
void EnableDefenderRegistry() {
    HKEY hKey;
    DWORD enable = 0;

    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, defenderKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, L"DisableAntiSpyware", 0, REG_DWORD, (BYTE*)&enable, sizeof(enable));
        RegCloseKey(hKey);
    }

    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, realtimeKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegDeleteValueW(hKey, L"DisableRealtimeMonitoring");
        RegDeleteValueW(hKey, L"DisableBehaviorMonitoring");
        RegDeleteValueW(hKey, L"DisableOnAccessProtection");
        RegCloseKey(hKey);
    }
}

// Control the WinDefend service
void ToggleDefenderService(bool enable) {
    SC_HANDLE scManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scManager) {
        SC_HANDLE service = OpenServiceW(scManager, L"WinDefend", SERVICE_ALL_ACCESS);
        if (service) {
            SERVICE_STATUS status;
            if (!enable) {
                ControlService(service, SERVICE_CONTROL_STOP, &status);
                ChangeServiceConfigW(service, SERVICE_NO_CHANGE, SERVICE_DISABLED, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
            }
            else {
                ChangeServiceConfigW(service, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
                StartService(service, 0, NULL);
            }
            CloseServiceHandle(service);
        }
        CloseServiceHandle(scManager);
    }
}

// Toggle Tamper Protection
void SetTamperProtection(bool enable) {
    std::string command = "powershell -command \"Set-MpPreference -DisableTamperProtection " + std::string(enable ? "false" : "true") + "\" >nul 2>&1";
    system(command.c_str());
}

// Check if running as Admin
bool IsAdmin() {
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdminGroup;
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdminGroup)) {
        if (!CheckTokenMembership(NULL, AdminGroup, &isAdmin)) {
            isAdmin = FALSE;
        }
        FreeSid(AdminGroup);
    }
    return isAdmin;
}

int main() {
    // Check for Admin rights
    if (!IsAdmin()) {
        std::cout << "[!] Error: Run as Administrator!" << std::endl;
        system("pause");
        return 1;
    }

    // Ask for action
    std::string input;
    std::cout << "[?] Disable (D) or Re-enable (R) Windows Defender? [D/R]: ";
    std::getline(std::cin, input);

    bool disableMode = (input == "D" || input == "d");

    // Confirmation
    std::cout << "[?] Are you sure you want to " << (disableMode ? "DISABLE" : "RE-ENABLE") << " Windows Defender? (Y/N): ";
    std::getline(std::cin, input);

    if (input != "Y" && input != "y") {
        std::cout << "[!] Operation cancelled." << std::endl;
        system("pause");
        return 0;
    }

    // Execute
    if (disableMode) {
        std::cout << "[+] Disabling Windows Defender..." << std::endl;
        DisableDefenderRegistry();
        ToggleDefenderService(false);
        SetTamperProtection(false);
        std::cout << "[+] Defender disabled. Reboot recommended." << std::endl;
    }
    else {
        std::cout << "[+] Re-enabling Windows Defender..." << std::endl;
        EnableDefenderRegistry();
        ToggleDefenderService(true);
        SetTamperProtection(true);
        std::cout << "[+] Defender re-enabled. Reboot recommended." << std::endl;
    }

    system("pause");
    return 0;
}