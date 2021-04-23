#pragma once
#include "SuspiciousProcessInfo.h"

namespace classifier
{
    class ProcessClassifier
    {
    public:
        ProcessClassifier();
        std::vector<SuspiciousProcessInfo> GetSuspiciousProcesses() const;

    private:
        void InitSystemRootPath();
        void InitInstallFolders();
        void InitInstalledServicesPaths();
        void InitInstalledModulesPaths();

        bool IsProcessSuspicious(DWORD pid, const std::wstring& path) const;
        std::vector<std::wstring> GetSuspiciousModules(DWORD pid) const;

        bool IsSystemModule(std::wstring_view path) const;
        bool IsInstalledService(DWORD pid) const;
        bool IsInstalledModule(const std::wstring& path) const;
        bool HasRegisteredComObject(const std::wstring& path) const;
        bool IsPresentInKnownFolders(const std::wstring& path) const;

    private:
        std::wstring m_systemRootPath;
        std::set<std::wstring> m_installFolders;
        std::set<std::wstring> m_registeredObjectsPaths;
        std::set<DWORD> m_installedServicesPids;
    };
}
