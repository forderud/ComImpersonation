#pragma once
#include "Sandboxing.hpp"
#include "ProcCreate.hpp"
#include <tuple>
#include "../TestControl/ComSupport.hpp"


/** Attempt to create a COM server that runds through a specific user account.
    AppContainer problem:
      Process is created but CoGetClassObject activation gives E_ACCESSDENIED (The machine-default permission settings do not grant Local Activation permission for the COM Server) */
CComPtr<IUnknown> CoCreateAsUser_impersonate (CLSID clsid, IntegrityLevel mode, bool grant_appcontainer_permissions) {
    std::unique_ptr<ImpersonateThread> impersonate;
    bool explicit_process_create = (mode == IntegrityLevel::AppContainer);
    if (explicit_process_create) {
        // launch COM server process manually
        wchar_t clsid_str[39] = {};
        int ok = StringFromGUID2(clsid, const_cast<wchar_t*>(clsid_str), static_cast<int>(std::size(clsid_str)));
        if (!ok)
            abort(); // should never happen

        std::wstring exe_path = RegQuery::GetExePath(clsid_str);
        if (exe_path.empty())
            exe_path = RegQuery::GetExePath(clsid_str, KEY_WOW64_32KEY); // fallback to 32bit part of registry
        if (exe_path.empty()) {
            std::wcerr << L"ERROR: Unable to locate COM server EXE path." << std::endl;
            exit(-2);
        }

        if (grant_appcontainer_permissions) {
            // grant ALL_APPLICATION_PACKAGES permission to the COM EXE & DCOM LaunchPermission
            const wchar_t ac_str_sid[] = L"S-1-15-2-1"; // ALL_APP_PACKAGES
            Permissions::Check access_checker(ac_str_sid);

            DWORD existing_access = access_checker.TryAccessPath(exe_path.c_str());
            if (Permissions::Check::HasReadAccess(existing_access)) {
                std::wcout << "AppContainer already have EXE access.\n";
            } else {
                DWORD err = Permissions::MakePathAppContainer(ac_str_sid, exe_path.c_str(), GENERIC_READ | GENERIC_EXECUTE);
                if (err != ERROR_SUCCESS) {
                    _com_error error(err);
                    std::wcerr << L"ERROR: Failed to grant AppContainer permissions to the EXE, MSG=\"" << error.ErrorMessage() << L"\" (" << err << L")" << std::endl;
                    exit(-2);
                }
            }

            std::wstring app_id = RegQuery::GetAppID(clsid_str);
            if (app_id.empty()) {
                std::wcerr << L"ERROR: Unable to locate COM server AppID." << std::endl;
                exit(-2);
            }

            bool has_launch_perm = false;
            {
                // open registry path
                CComBSTR reg_path(L"AppID\\");
                reg_path.Append(app_id.c_str());

                CRegKey appid_reg;
                if (appid_reg.Open(HKEY_CLASSES_ROOT, reg_path, KEY_READ) != ERROR_SUCCESS) {
                    std::wcerr << L"ERROR: Unable to open server AppID." << std::endl;
                    exit(-2);
                }
                
                ULONG launch_perm_len = 0;
                appid_reg.QueryBinaryValue(L"LaunchPermission", nullptr, &launch_perm_len); // ignore failure
                if (launch_perm_len > 0) {
                    std::vector<BYTE> launch_perm_sd(launch_perm_len, 0);

                    if (appid_reg.QueryBinaryValue(L"LaunchPermission", launch_perm_sd.data(), &launch_perm_len) == ERROR_SUCCESS) {
                        ACCESS_MASK access = access_checker.TryAccess(launch_perm_sd.data());
                        has_launch_perm = Permissions::Check::HasLaunchPermission(access);
                    }
                }
            }

            if (!has_launch_perm) {
                DWORD err = Permissions::EnableLaunchActPermission(ac_str_sid, app_id.c_str());
                if (err != ERROR_SUCCESS) {
                    _com_error error(err);
                    std::wcerr << L"ERROR: Failed to grant AppContainer AppID LaunchPermission, MSG=\"" << error.ErrorMessage() << L"\" (" << err << L")" << std::endl;
                    exit(-2);
                }
            }
        }

        if (mode == IntegrityLevel::AppContainer) {
            AppContainerWrap ac(L"RunInSandbox.AppContainer", L"RunInSandbox.AppContainer");
            HandleWrap proc = CreateAndKillAppContainerProcess(ac, exe_path.c_str());
            // impersonate the process handle
            impersonate.reset(new ImpersonateThread(proc));
        } else {
            StartupInfoWrap si;
            HandleWrap proc = ProcCreate(si, exe_path.c_str(), mode, {L"-Embedding"}); // mimic how svchost passes "-Embedding" argument
            // impersonate the process handle
            impersonate.reset(new ImpersonateThread(proc));
        }
    } else {
        {
            // impersonate desired integrity
            impersonate.reset(new ImpersonateThread(mode, GetCurrentProcess()));
        }
    }

    // create COM object in a separate process
    CComPtr<IUnknown> obj;
    HRESULT hr = obj.CoCreateInstance(clsid, nullptr, CLSCTX_LOCAL_SERVER | CLSCTX_ENABLE_CLOAKING);
    if ((mode == IntegrityLevel::AppContainer) && (hr == E_ACCESSDENIED)) {
        std::wcerr << L"ERROR: CoCreateInstance access denied when trying to create a new COM server instance. Have you remember to grant AppContainer permissions?" << std::endl;
        exit(-3);
    } else {
        CHECK(hr);
    }

    return obj;
}


/** Create a AppID and elevation-enabled COM server in a admin process.
    REF: https://docs.microsoft.com/en-us/windows/win32/com/the-com-elevation-moniker */
template <typename T>
static HRESULT CoCreateInstanceElevated (HWND window, const GUID clsid, T ** result) {
    if (!result)
        return E_INVALIDARG;
    if (*result)
        return E_INVALIDARG;

    wchar_t clsid_str[39] = {};
    int ok = StringFromGUID2(clsid, const_cast<wchar_t*>(clsid_str), static_cast<int>(std::size(clsid_str)));
    if (!ok)
        abort(); // should never happen

    std::wstring obj_name = L"Elevation:Administrator!new:";
    obj_name += clsid_str;

    BIND_OPTS3 options = {};
    options.cbStruct = sizeof(options);
    options.hwnd = window;
    options.dwClassContext = CLSCTX_LOCAL_SERVER;

    //std::wcout << L"CoGetObject: " << obj_name << L'\n';
    return ::CoGetObject(obj_name.c_str(), &options, __uuidof(T), reinterpret_cast<void**>(result));
}


/** Try to set a an attribute on an automation-compatible COM server. */
static bool SetComAttribute(CComPtr<IUnknown> & obj, CComBSTR name, CComVariant value) {
    CComPtr<IDispatch> obj_disp;
    if (FAILED(obj.QueryInterface(&obj_disp)))
        return false;

    // lookup attribute ID
    DISPID dispid = 0;
    if (FAILED(obj_disp->GetIDsOfNames(IID_NULL, &name, 1, LOCALE_USER_DEFAULT, &dispid)))
        return false;

    // prepare arguments
    DISPPARAMS params = {};
    DISPID type = DISPID_PROPERTYPUT;
    {
        params.cArgs = 1;
        params.rgvarg = &value;
        params.cNamedArgs = 1;
        params.rgdispidNamedArgs = &type;
    }

    // invoke call
    HRESULT hr = obj_disp->Invoke(dispid, IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_PROPERTYPUT, &params, NULL, NULL, NULL);
    return SUCCEEDED(hr);
}
