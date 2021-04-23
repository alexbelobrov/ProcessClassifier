#include "stdafx.h"
#include "ProcessClassifier.h"
#include "Utils.h"

namespace
{
    void PrintModules(const std::vector<std::wstring>& modules)
    {
        std::wcout << L"suspicious modules:" << std::endl;
        for (const auto& module : modules)
        {
            std::wcout << L'\t' << module << std::endl;
        }
    }
}

int main()
{
    try
    {
        const classifier::ProcessClassifier classifier;
        const auto suspiciousProcesses = classifier.GetSuspiciousProcesses();
        if (!suspiciousProcesses.empty())
        {
            std::wcout << L"Suspicious processes:" << std::endl << std::endl;
            for (const auto& process : suspiciousProcesses)
            {
                std::wcout
                    << L"pid: " << process.pid << std::endl
                    << L"path: " << process.path << std::endl;
                switch (process.reason)
                {
                case classifier::SuspiciousProcessInfo::Reason::ProcessNotInstalled:
                    std::wcout << L"reason: process is not system and not installed" << std::endl;
                    break;

                case classifier::SuspiciousProcessInfo::Reason::ModuleNotInstalled:
                    std::wcout << L"reason: process has suspicious modules" << std::endl;
                    PrintModules(process.suspiciousModules);
                    break;

                case classifier::SuspiciousProcessInfo::Reason::ProcessAndModuleNotInstalled:
                    std::wcout << L"reason: process is not system and not installed, also has suspicious modules " << std::endl;
                    PrintModules(process.suspiciousModules);
                    break;

                default:
                    std::wcout << L"reason: unknown" << std::endl;
                }
                std::wcout << std::endl;
            }
        }
        else
        {
            std::wcout << L"Suspicious processes not found!" << std::endl;
        }
    }
    catch (const std::exception& ex)
    {
        std::wcout << L"Exception occurred: " << utils::ToWString(ex.what());
    }
}
