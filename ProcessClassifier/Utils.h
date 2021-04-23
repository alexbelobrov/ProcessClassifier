#pragma once

namespace utils
{
    std::vector<DWORD> GetProcessList();
    std::wstring GetPathToProcess(DWORD pid);
    std::vector<std::wstring> GetProcessModules(DWORD pid);

    using RegistryEnumCallback = std::function<bool(const std::wstring&)>;
    void RegistryEnumKeys(HKEY parent, const std::wstring& subkey, const RegistryEnumCallback& callback, bool wow6432 = false);
    std::optional<std::wstring> RegistryReadString(HKEY parent, const std::wstring& subkey, const std::wstring& value, bool wow6432 = false);

    void RemoveQuotes(std::wstring& str);
    std::wstring ToWString(std::string_view str);
}
