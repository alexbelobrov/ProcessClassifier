#pragma once

namespace classifier
{
    struct SuspiciousProcessInfo
    {
        enum class Reason
        {
            ProcessNotInstalled,
            ModuleNotInstalled,
            ProcessAndModuleNotInstalled
        };

        DWORD pid = 0;
        std::wstring path;
        Reason reason = Reason::ProcessNotInstalled;
        std::vector<std::wstring> suspiciousModules;
    };
}
