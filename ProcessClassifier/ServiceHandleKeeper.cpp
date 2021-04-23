#include "stdafx.h"
#include "ServiceHandleKeeper.h"

namespace utils
{
    ServiceHandleKeeper::ServiceHandleKeeper(SC_HANDLE handle) :
        m_handle(handle)
    {
    }

    ServiceHandleKeeper::~ServiceHandleKeeper()
    {
        if (IsValid())
        {
            CloseServiceHandle(m_handle);
            m_handle = NULL;
        }
    }

    ServiceHandleKeeper::operator SC_HANDLE&()
    {
        return m_handle;
    }

    bool ServiceHandleKeeper::IsValid() const
    {
        return NULL != m_handle;
    }
}
