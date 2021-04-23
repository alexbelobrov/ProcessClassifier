#pragma once

namespace utils
{
    class ServiceHandleKeeper
    {
    public:
        ServiceHandleKeeper(SC_HANDLE handle);
        ~ServiceHandleKeeper();
        operator SC_HANDLE&();
        bool IsValid() const;

    private:
        SC_HANDLE m_handle = NULL;
    };
}
