#pragma once

namespace utils
{
    class HandleKeeper
    {
    public:
        HandleKeeper() = default;
        HandleKeeper(HANDLE handle);
        HandleKeeper(HandleKeeper&& handleKeeper);
        HandleKeeper(const HandleKeeper&) = delete;
        ~HandleKeeper();

        HandleKeeper& operator=(HandleKeeper&& handleKeeper);
        HandleKeeper& operator=(HANDLE handle);
        HandleKeeper& operator=(const HandleKeeper&) = delete;

        operator HANDLE&();

        bool IsValid() const;

    private:
        void Close();

    private:
        HANDLE m_handle = INVALID_HANDLE_VALUE;
    };
}
