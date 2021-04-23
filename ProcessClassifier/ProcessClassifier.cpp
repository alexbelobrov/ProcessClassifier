#include "stdafx.h"
#include "ProcessClassifier.h"
#include "ServiceHandleKeeper.h"
#include "Utils.h"

namespace classifier
{
    ProcessClassifier::ProcessClassifier()
    {
        InitSystemRootPath();
        InitInstallFolders();
        InitInstalledServicesPaths();
        InitInstalledModulesPaths();
    }

    std::vector<SuspiciousProcessInfo> ProcessClassifier::GetSuspiciousProcesses() const
    {
        std::vector<SuspiciousProcessInfo> suspiciousProcesses;
        for (const auto pid : utils::GetProcessList())
        {
            auto processPath = utils::GetPathToProcess(pid);
            if (processPath.empty())
            {
                continue;
            }
            auto suspiciousModules = GetSuspiciousModules(pid);
            const auto isProcessSuspicious = IsProcessSuspicious(pid, processPath);
            const auto isProcessHasSuspiciousModules = !suspiciousModules.empty();
            if (isProcessSuspicious || isProcessHasSuspiciousModules)
            {
                const auto reason = [isProcessSuspicious, isProcessHasSuspiciousModules]() -> SuspiciousProcessInfo::Reason
                {
                    if (!isProcessSuspicious)
                    {
                        return SuspiciousProcessInfo::Reason::ModuleNotInstalled;
                    }
                    if (!isProcessHasSuspiciousModules)
                    {
                        return SuspiciousProcessInfo::Reason::ProcessNotInstalled;
                    }
                    return SuspiciousProcessInfo::Reason::ProcessAndModuleNotInstalled;
                }();
                SuspiciousProcessInfo info{pid, std::move(processPath), reason, std::move(suspiciousModules)};
                suspiciousProcesses.push_back(std::move(info));
            }
        }
        return suspiciousProcesses;
    }

    void ProcessClassifier::InitSystemRootPath()
    {
        TCHAR buffer[MAX_PATH] = {0};
        if (0 != ExpandEnvironmentStrings(L"%SYSTEMROOT%", buffer, MAX_PATH))
        {
            m_systemRootPath = buffer;
        }
    }

    void ProcessClassifier::InitInstallFolders()
    {
        const std::wstring arpKey(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
        const auto arpCallback = [this, &arpKey](HKEY parent, bool wow6432 = false)
        {
            return [this, &arpKey, parent, wow6432](const std::wstring& subkey) -> bool
            {
                auto oInstallLocation = utils::RegistryReadString(parent, arpKey + L'\\' + subkey, L"InstallLocation", wow6432);
                if (!oInstallLocation.has_value())
                {
                    return false;
                }
                auto& installLocation = oInstallLocation.value();
                utils::RemoveQuotes(installLocation);
                if (!installLocation.empty())
                {
                    m_installFolders.emplace(installLocation);
                }
                return false;
            };
        };
        utils::RegistryEnumKeys(HKEY_CURRENT_USER, arpKey, arpCallback(HKEY_CURRENT_USER));
        utils::RegistryEnumKeys(HKEY_LOCAL_MACHINE, arpKey, arpCallback(HKEY_LOCAL_MACHINE));
        utils::RegistryEnumKeys(HKEY_LOCAL_MACHINE, arpKey, arpCallback(HKEY_LOCAL_MACHINE, true), true);

        const std::wstring appPathsKey(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths");
        const auto appPathsCallback = [this, &appPathsKey](HKEY parent, bool wow6432 = false)
        {
            return [this, &appPathsKey, parent, wow6432](const std::wstring& subkey) -> bool
            {
                auto oExePath = utils::RegistryReadString(parent, appPathsKey + L'\\' + subkey, L"", wow6432);
                if (!oExePath.has_value())
                {
                    return false;
                }
                auto& exePath = oExePath.value();
                utils::RemoveQuotes(exePath);
                TCHAR buffer[MAX_PATH] = {0};
                if (0 != ExpandEnvironmentStrings(exePath.c_str(), buffer, MAX_PATH))
                {
                    const std::wstring p(buffer);
                    if (!p.empty())
                    {
                        m_installFolders.emplace(p.substr(0, p.find_last_of(L"/\\")));
                    }
                }
                return false;
            };
        };
        utils::RegistryEnumKeys(HKEY_CURRENT_USER, appPathsKey, appPathsCallback(HKEY_CURRENT_USER));
        utils::RegistryEnumKeys(HKEY_LOCAL_MACHINE, appPathsKey, appPathsCallback(HKEY_LOCAL_MACHINE));
    }

    void ProcessClassifier::InitInstalledServicesPaths()
    {
        utils::ServiceHandleKeeper scManager = OpenSCManager(
            0,
            SERVICES_ACTIVE_DATABASE,
            SC_MANAGER_ENUMERATE_SERVICE
        );
        if (scManager.IsValid())
        {
            DWORD required = 0;
            DWORD resumeHandle = 0;
            DWORD servicesCount = 0;

            EnumServicesStatusEx(
                scManager,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_ACTIVE,
                0,
                0,
                &required,
                &servicesCount,
                &resumeHandle,
                0
            );

            std::vector<BYTE> servicesBuffer(required);
            if (FALSE == EnumServicesStatusEx(
                scManager,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_ACTIVE,
                servicesBuffer.data(),
                static_cast<DWORD>(servicesBuffer.size()),
                &required,
                &servicesCount,
                &resumeHandle,
                0
            ))
            {
                return;
            }

            auto services = reinterpret_cast<const ENUM_SERVICE_STATUS_PROCESS*>(servicesBuffer.data());
            for (DWORD i = 0; i < servicesCount; ++i)
            {
                m_installedServicesPids.emplace(services[i].ServiceStatusProcess.dwProcessId);
            }
        }
    }

    void ProcessClassifier::InitInstalledModulesPaths()
    {
        const std::wstring clsidKey(L"CLSID");
        const auto callback = [this, &clsidKey](bool wow6432 = false)
        {
            return [this, &clsidKey, wow6432](const std::wstring& guidKey) -> bool
            {
                auto oInstallLocation = utils::RegistryReadString(HKEY_CLASSES_ROOT, clsidKey + L'\\' + guidKey + L'\\' + L"InprocServer32", L"", wow6432);
                if (!oInstallLocation.has_value())
                {
                    return false;
                }
                auto& installLocation = oInstallLocation.value();
                utils::RemoveQuotes(installLocation);
                TCHAR buffer[MAX_PATH] = {0};
                if (0 != ExpandEnvironmentStrings(installLocation.c_str(), buffer, MAX_PATH))
                {
                    if (!IsSystemModule(buffer))
                    {
                        m_registeredObjectsPaths.emplace(buffer);
                    }
                }
                return false;
            };
        };
        utils::RegistryEnumKeys(HKEY_CLASSES_ROOT, clsidKey, callback());
        utils::RegistryEnumKeys(HKEY_CLASSES_ROOT, clsidKey, callback(true), true);
    }

    bool ProcessClassifier::IsProcessSuspicious(const DWORD pid, const std::wstring& path) const
    {
        return
            !IsSystemModule(path) &&
            !IsInstalledService(pid) &&
            !IsPresentInKnownFolders(path);
    }

    std::vector<std::wstring> ProcessClassifier::GetSuspiciousModules(const DWORD pid) const
    {
        std::vector<std::wstring> suspiciousModules;
        for (const auto& modulePath : utils::GetProcessModules(pid))
        {
            if (!IsSystemModule(modulePath) && !IsInstalledModule(modulePath) && !IsPresentInKnownFolders(modulePath))
            {
                suspiciousModules.push_back(modulePath);
            }
        }
        return suspiciousModules;
    }

    bool ProcessClassifier::IsSystemModule(std::wstring_view path) const
    {
        if (path.empty())
        {
            return false;
        }
        return
            path.size() >= m_systemRootPath.size() &&
            0 == _wcsnicmp(path.data(), m_systemRootPath.c_str(), m_systemRootPath.size());
    }

    bool ProcessClassifier::IsInstalledService(const DWORD pid) const
    {
        return m_installedServicesPids.cend() != m_installedServicesPids.find(pid);
    }

    bool ProcessClassifier::IsInstalledModule(const std::wstring& path) const
    {
        if (path.empty())
        {
            return false;
        }
        return HasRegisteredComObject(path) || IsPresentInKnownFolders(path);
    }

    bool ProcessClassifier::HasRegisteredComObject(const std::wstring& path) const
    {
        return std::any_of(m_registeredObjectsPaths.cbegin(), m_registeredObjectsPaths.cend(), [this, &path](const auto& registeredObject)
        {
            return
                path.size() >= registeredObject.size() &&
                0 == _wcsnicmp(path.c_str(), registeredObject.c_str(), registeredObject.size());
        });
    }

    bool ProcessClassifier::IsPresentInKnownFolders(const std::wstring& path) const
    {
        return std::any_of(m_installFolders.cbegin(), m_installFolders.cend(), [this, &path](const auto& installFolder)
        {
            return
                path.size() >= installFolder.size() &&
                0 == _wcsnicmp(path.c_str(), installFolder.c_str(), installFolder.size());
        });
    }
}
