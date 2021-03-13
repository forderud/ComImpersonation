#include "TestControl.hpp"
#include "../RunInSandbox/ComCreate.hpp"
#include "Socket.hpp"


TestControl::TestControl(){
}

TestControl::~TestControl() {
}

HRESULT STDMETHODCALLTYPE TestControl::Add(int a, int b, int * sum) {
    *sum = a + b;
    return S_OK;
}

HRESULT STDMETHODCALLTYPE TestControl::IsElevated (/*out*/BOOL * is_elevated, /*out*/BOOL * is_high_il) {
    *is_elevated = ImpersonateThread::IsProcessElevated();

    IntegrityLevel proc_integrity = ImpersonateThread::GetProcessLevel();
    *is_high_il = (proc_integrity >= IntegrityLevel::High);

    return S_OK;
}


HRESULT STDMETHODCALLTYPE TestControl::TestNetworkConnection (/*in*/BSTR host, USHORT port, /*out*/BOOL * can_access) {
    *can_access = false; // assume no connectivity by default

    try {
        SocketWrap sock;
        *can_access = sock.TryToConnect(ToAscii(host), port);
    } catch (const std::exception & ) {
        return E_FAIL;
    }

    return S_OK;
}


HRESULT STDMETHODCALLTYPE TestControl::CreateInstance (BOOL elevated, /*in*/CLSID clsid, /*out*/IUnknown ** obj) {
    if (!obj)
        return E_INVALIDARG;

    if (elevated) {
        return CoCreateInstanceElevated<IUnknown>(NULL, clsid, obj);
    } else {
        CComPtr<IUnknown> res;
        HRESULT hr = res.CoCreateInstance(clsid);
        if (FAILED(hr))
            return hr;

        *obj = res.Detach();
        return S_OK;
    }
}

HRESULT STDMETHODCALLTYPE TestControl::TestCallback(IUnknown * obj) {
    if (!obj)
        return E_INVALIDARG;

    // cast callback pointer
    CComPtr<ICallbackTest> tmp;
    HRESULT hr = obj->QueryInterface(&tmp);
    if (FAILED(hr))
        return E_INVALIDARG;

    // invoke callback
    return tmp->Ping();
}

HRESULT STDMETHODCALLTYPE TestControl::MoveMouseCursor(int x_pos, int y_pos, /*out*/DWORD * access) {
    {
        // Based on 
        // https://github.com/nccgroup/WindowsDACLEnumProject/blob/master/WinStationsAndDesktopPerms/WinStationsAndDesktopPerms/WinStationsAndDesktopPerms.cpp
        HWINSTA win_sta = GetProcessWindowStation();

        {
            // query information about the window station
            DWORD buf_len = 0;
            USEROBJECTFLAGS flags = {};
            WIN32_CHECK(GetUserObjectInformation(win_sta, UOI_FLAGS, &flags, sizeof(flags), &buf_len));
            assert(flags.dwFlags == 1);
            assert(flags.fInherit == 0);

            wchar_t name_buf[1024] = {};
            WIN32_CHECK(GetUserObjectInformation(win_sta, UOI_NAME, name_buf, (DWORD)std::size(name_buf), &buf_len));
            assert(std::wstring(name_buf) == L"WinSta0");

            wchar_t type_buf[1024] = {};
            WIN32_CHECK(GetUserObjectInformation(win_sta, UOI_TYPE, type_buf, (DWORD)std::size(type_buf), &buf_len));
            assert(std::wstring(type_buf) == L"WindowStation");

            BOOL ok = GetUserObjectInformation(win_sta, UOI_USER_SID, nullptr, 0, &buf_len);
            std::vector<BYTE> user_sid_buf(buf_len, 0);
            WIN32_CHECK(GetUserObjectInformation(win_sta, UOI_USER_SID, user_sid_buf.data(), (DWORD)user_sid_buf.size(), &buf_len));
            SID* user_sid_ptr = (SID*)user_sid_buf.data();

            assert(win_sta);
        }
        {
            SECURITY_INFORMATION type = DACL_SECURITY_INFORMATION;
            DWORD buf_len = 0;
            BOOL ok = GetUserObjectSecurity(win_sta, &type, nullptr, 0, &buf_len);
            std::vector<BYTE> dacl_buf(buf_len, 0);
            SECURITY_DESCRIPTOR* sd = (SECURITY_DESCRIPTOR*)dacl_buf.data();
            WIN32_CHECK(GetUserObjectSecurity(win_sta, &type, sd, (DWORD)dacl_buf.size(), &buf_len));
            // sd->Sacl & sd->Dacl pointers are not accessible
            assert(win_sta);
        }

        ACL* dacl = nullptr; // weak ptr.
        LocalWrap<PSECURITY_DESCRIPTOR> SD;
        DWORD err = GetSecurityInfo(win_sta, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &dacl, NULL, &SD);
        if (err != ERROR_SUCCESS) {
            DWORD err = GetLastError();
            return HRESULT_FROM_WIN32(err);
        }
        assert(IsValidAcl(dacl));

        UINT writeattr = 0;

        for (DWORD idx = 0; idx < dacl->AceCount; ++idx) {
            ACCESS_ALLOWED_ACE* ace = nullptr;
            BOOL ok = GetAce(dacl, idx, (void**)&ace);
            if (!ok) {
                DWORD err = GetLastError();
                return HRESULT_FROM_WIN32(err);
            }

            if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE)
                continue;

            auto user_domain = Permissions::LookupSID((SID*)&ace->SidStart);

            if (ace->Mask & WINSTA_WRITEATTRIBUTES)
                writeattr++;

        }

        Permissions::Check check;
        ACCESS_MASK mask = check.TryAccess(SD);
        *access = mask;
    }

    // will fail without WINSTA_WRITEATTRIBUTES access
    BOOL ok = SetCursorPos(x_pos, y_pos);
    if (!ok) {
        DWORD err = GetLastError();
        // TODO: Figure out why err==0 here
        return E_ACCESSDENIED;
    }
    return S_OK;
}
