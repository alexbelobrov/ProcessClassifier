#include "stdafx.h"
#include "HandleKeeper.h"

namespace utils
{
    HandleKeeper::HandleKeeper(HANDLE handle) :
        m_handle(handle)
    {
    }

    HandleKeeper::HandleKeeper(HandleKeeper&& handleKeeper) :
        m_handle(handleKeeper.m_handle)
    {
        handleKeeper.m_handle = INVALID_HANDLE_VALUE;
    }

    HandleKeeper::~HandleKeeper()
    {
        Close();
    }

    HandleKeeper& HandleKeeper::operator=(HandleKeeper&& handleKeeper)
    {
        if (&handleKeeper != this)
        {
            operator=(handleKeeper.m_handle);
            handleKeeper.m_handle = INVALID_HANDLE_VALUE;;
        }
        return *this;
    }

    HandleKeeper& HandleKeeper::operator=(HANDLE handle)
    {
        if (handle != m_handle)
        {
            Close();
            m_handle = handle;
        }
        return *this;
    }

    HandleKeeper::operator HANDLE&()
    {
        return m_handle;
    }

    bool HandleKeeper::IsValid() const
    {
        return INVALID_HANDLE_VALUE != m_handle && NULL != m_handle;
    }

    void HandleKeeper::Close()
    {
        if (IsValid())
        {
            CloseHandle(m_handle);
            m_handle = INVALID_HANDLE_VALUE;
        }
    }
}
