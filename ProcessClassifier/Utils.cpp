#include "stdafx.h"
#include "Utils.h"
#include "HandleKeeper.h"

namespace utils
{
    std::vector<DWORD> GetProcessList()
    {
        std::vector<DWORD> processList(0x200);
        DWORD requiredSize = 0;
        do
        {
            const auto processListSize = static_cast<DWORD>(processList.size() * sizeof(DWORD));
            if (FALSE == EnumProcesses(processList.data(), processListSize, &requiredSize))
            {
                return {};
            }
            if (processListSize == requiredSize)
            {
                processList.resize(processList.size() * 2);
            }
            else
            {
                break;
            }
        }
        while (true);
        processList.resize(requiredSize / sizeof(DWORD));
        return processList;
    }

    std::wstring GetPathToProcess(const DWORD pid)
    {
        HandleKeeper process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (process.IsValid())
        {
            TCHAR path[MAX_PATH] = {0};
            if (0 != GetModuleFileNameEx(process, NULL, path, MAX_PATH))
            {
                return path;
            }
        }
        return {};
    }

    std::vector<std::wstring> GetProcessModules(const DWORD pid)
    {
        HandleKeeper process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (process.IsValid())
        {
            HMODULE modules[0x400] = {0};
            DWORD required = 0;
            if (FALSE != EnumProcessModules(process, modules, sizeof(modules), &required))
            {
                std::vector<std::wstring> result;
                result.reserve(required / sizeof(HMODULE) - 1);
                for (DWORD i = 1; i < required / sizeof(HMODULE); ++i)
                {
                    TCHAR modulePath[MAX_PATH] = {0};
                    if (0 != GetModuleFileNameEx(process, modules[i], modulePath, sizeof(modulePath) / sizeof(TCHAR)))
                    {
                        result.emplace_back(modulePath);
                    }
                }
                return result;
            }
        }
        return {};
    }

    void RegistryEnumKeys(HKEY parent, const std::wstring& subkey, const RegistryEnumCallback& callback, const bool wow6432)
    {
        HKEY key;
        auto status = RegOpenKeyEx(
            parent,
            subkey.c_str(),
            0,
#ifdef _WIN64
            wow6432 ? KEY_READ | KEY_WOW64_32KEY : KEY_READ | KEY_WOW64_64KEY,
#else
            wow6432 ? KEY_READ : KEY_READ | KEY_WOW64_64KEY,
#endif
            &key
        );
        if (ERROR_SUCCESS == status)
        {
            DWORD index = 0;
            const DWORD REGISTRY_NAME_SIZE = 256;
            TCHAR name[REGISTRY_NAME_SIZE] = {0};
            DWORD nameSize = REGISTRY_NAME_SIZE;
            while ((status = RegEnumKeyEx(
                key,
                index++,
                name,
                &nameSize,
                0,
                NULL,
                NULL,
                NULL)) == ERROR_SUCCESS)
            {
                if (callback(name))
                {
                    break;
                }
                nameSize = REGISTRY_NAME_SIZE;
            }
            RegCloseKey(key);
        }
    }

    std::optional<std::wstring> RegistryReadString(HKEY parent, const std::wstring& subkey, const std::wstring& value, const bool wow6432)
    {
        HKEY key;
        auto ret = RegOpenKeyEx(
            parent,
            subkey.c_str(),
            0,
#ifdef _WIN64
            wow6432 ? KEY_READ | KEY_WOW64_32KEY : KEY_READ | KEY_WOW64_64KEY,
#else
            wow6432 ? KEY_READ : KEY_READ | KEY_WOW64_64KEY,
#endif
            &key
        );
        if (ERROR_SUCCESS == ret)
        {
            DWORD readSize = 0;
            ret = RegQueryValueEx(
                key,
                value.c_str(),
                NULL,
                NULL,
                NULL,
                &readSize
            );
            std::vector<BYTE> readData(static_cast<size_t>(readSize), 0);
            if (ERROR_MORE_DATA == ret || ERROR_SUCCESS == ret)
            {
                ret = RegQueryValueEx(
                    key,
                    value.c_str(),
                    NULL,
                    NULL,
                    readData.data(),
                    &readSize
                );
                if (ERROR_SUCCESS != ret)
                {
                    RegCloseKey(key);
                    return std::nullopt;
                }
            }
            RegCloseKey(key);
            if (!readData.empty())
            {
                readData.resize(wcslen(reinterpret_cast<const wchar_t*>(readData.data())) * sizeof(wchar_t));
                return std::wstring(
                    reinterpret_cast<const wchar_t*>(readData.data()),
                    reinterpret_cast<const wchar_t*>(readData.data() + readData.size())
                );
            }
            return std::nullopt;
        }
        return std::nullopt;
    }

    void RemoveQuotes(std::wstring& str)
    {
        str.erase(std::remove(str.begin(), str.end(), L'\"'), str.end());
    }

    std::wstring ToWString(std::string_view str)
    {
        const int sizeRequired = MultiByteToWideChar(
            CP_UTF8,
            0,
            str.data(),
            static_cast<int>(str.size()),
            NULL,
            0
        );
        std::wstring result(static_cast<size_t>(sizeRequired), 0);
        MultiByteToWideChar(
            CP_UTF8,
            0,
            str.data(),
            static_cast<int>(str.size()),
            result.data(),
            static_cast<int>(result.size())
        );
        return result;
    }
}
