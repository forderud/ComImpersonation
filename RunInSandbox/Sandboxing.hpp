#pragma once
#include <cassert>
#include <tuple>
#include <vector>
#include <Windows.h>
#include <atlbase.h>
#include <comdef.h>
#include <versionhelpers.h>
#include <aclapi.h> // for SE_FILE_OBJECT
#include <sddl.h> // for SDDL_REVISION_1
#include <userenv.h>
#pragma comment(lib, "Userenv.lib")
#include <authz.h>
#pragma comment(lib, "authz.lib")
#include <Winternl.h>
#pragma comment(lib, "onecoreuap.lib") // for DeriveCapabilitySidsFromName


static void WIN32_CHECK(BOOL res) {
    if (res)
        return;

    DWORD code = GetLastError();

    _com_error error(code);
    std::wcout << L"ERROR: " << error.ErrorMessage() << std::endl;
    abort();
}


/** RAII wrapper of Win32 "handle" objects. */
class HandleWrap {
public:
    HandleWrap() {
    }

    HandleWrap(HandleWrap && other) {
        std::swap(handle, other.handle);
    }

    ~HandleWrap() {
        if (handle) {
            CloseHandle(handle);
            handle = nullptr;
        }
    }

    HandleWrap& operator = (HandleWrap && other) {
        this->~HandleWrap();
        new(this) HandleWrap(std::move(other));
        return *this;
    }
    HandleWrap& operator = (HANDLE other) {
        this->~HandleWrap();
        new(this) HandleWrap();
        handle = other;
        return *this;
    }

    operator HANDLE () {
        return handle;
    }
    HANDLE* operator & () {
        return &handle;
    }

private:
    HandleWrap(const HandleWrap &) = delete;

    HANDLE handle = nullptr;
};
static_assert(sizeof(HandleWrap) == sizeof(HANDLE), "HandleWrap size mismatch");


/** RAII wrapper of Win32 API objects allocated with LocalAlloc. */
template <class T>
class LocalWrap {
public:
    LocalWrap() {
    }
    ~LocalWrap() {
        if (obj) {
            LocalFree(obj);
            obj = nullptr;
        }
    }

    operator T () {
        return obj;
    }
    T* operator & () {
        return &obj;
    }

private:
    LocalWrap(const LocalWrap &) = delete;
    LocalWrap& operator = (const LocalWrap &) = delete;

    T obj = nullptr;
};


/** RAII wrapper of Win32 Security IDentifier (SID) handles. */
class SidWrap {
public:
    SidWrap() {
    }
    ~SidWrap() {
        Clear();
    }

    void Clear() {
        if (sid) {
            FreeSid(sid);
            sid = nullptr;
        }
    }

    void Create(WELL_KNOWN_SID_TYPE type) {
        assert(!sid);

        DWORD sid_size = SECURITY_MAX_SID_SIZE;
        sid = LocalAlloc(LPTR, sid_size);
        WIN32_CHECK(CreateWellKnownSid(type, nullptr, sid, &sid_size));
    }

    std::wstring ToString() const {
        LocalWrap<wchar_t*> name_str;
        BOOL ok = ConvertSidToStringSidW(sid, &name_str);
        assert(ok); ok;
        return static_cast<wchar_t*>(name_str);
    }

    operator PSID () {
        return sid;
    }
    PSID* operator & () {
        return &sid;
    }

protected:
    SidWrap (const SidWrap &) = delete;
    SidWrap& operator = (const SidWrap &) = delete;

    PSID sid = nullptr;
};
static_assert(sizeof(SidWrap) == sizeof(PSID), "SidWrap size mismatch");


/** RAII class for encapsulating AppContainer configuration. */
class AppContainerWrap {
public:
    AppContainerWrap(const wchar_t * name, const wchar_t * desc) {
        // https://docs.microsoft.com/en-us/windows/uwp/packaging/app-capability-declarations
        AddCapability(L"internetClient");   // confirmed to enable client sockets (but not ping)
        AddCapability(L"removableStorage"); // have been unable to get this to work (see https://github.com/M2Team/Privexec/issues/31 for more info)

        // delete existing (if present)
        Delete(name);

        Create(name, desc);
    }

    ~AppContainerWrap() {
        for (auto &c : m_capabilities) {
            if (c.Sid) {
                HLOCAL fail = LocalFree(c.Sid);
                assert(!fail); fail;
                c.Sid = nullptr;
            }
        }
    }

    void Create(const wchar_t * name, const wchar_t * desc) {
        assert(!m_sid);

        // try to create new container
        HRESULT hr = CreateAppContainerProfile(name, name, desc, m_capabilities.empty() ? nullptr : m_capabilities.data(), (DWORD)m_capabilities.size(), &m_sid);
        if (HRESULT_CODE(hr) == ERROR_ALREADY_EXISTS) {
            // fallback to opening existing container
            hr = DeriveAppContainerSidFromAppContainerName(name, &m_sid);
        }
        if (FAILED(hr))
            abort();
    }

    void Delete(const wchar_t * name) {
        assert(!m_sid);
        HRESULT hr = DeleteAppContainerProfile(name);
        hr; // ignore error
    }

    /** Returns a non-owning security capability struct. */
    SECURITY_CAPABILITIES SecCap() {
        SECURITY_CAPABILITIES sc = {};
        sc.AppContainerSid = m_sid;
        if (m_capabilities.size() > 0)
            sc.Capabilities = m_capabilities.data();
        sc.CapabilityCount = static_cast<DWORD>(m_capabilities.size());
        return sc;
    }

    void AddCapability(const wchar_t * cap_name) {
        PSID * cap_group_sid = nullptr;
        DWORD cap_group_sid_len = 0;
        PSID * cap_sids = nullptr;
        DWORD cap_sids_len = 0;
        WIN32_CHECK(DeriveCapabilitySidsFromName(cap_name, &cap_group_sid, &cap_group_sid_len, &cap_sids, &cap_sids_len));

        // forward all capability SIDs (only one in practice)
        for (size_t i = 0; i < cap_sids_len; ++i)
            m_capabilities.push_back({cap_sids[i], SE_GROUP_ENABLED});

        // clean up cap_sids array (entries will be cleaned up in the destuctor)
        HLOCAL fail = LocalFree(cap_sids);
        assert(!fail);
        cap_sids = nullptr;

        // clean up cap_group_sid entries & array
        for (size_t i = 0; i < cap_group_sid_len; ++i) {
            fail = LocalFree(cap_group_sid[i]);
            assert(!fail);
        }
        fail = LocalFree(cap_group_sid);
        assert(!fail);
        cap_group_sid = nullptr;
    }

private:
    SidWrap                         m_sid;
    std::vector<SID_AND_ATTRIBUTES> m_capabilities;
};


enum class IntegrityLevel {
    Default = 0,
    AppContainer = 1,                ///< dummy value to ease impl.
    Untrusted = WinUntrustedLabelSid,///< same as ConvertStringSidToSid("S-1-16-0",..)
    Low       = WinLowLabelSid,      ///< same as ConvertStringSidToSid("S-1-16-4096",..)
    Medium    = WinMediumLabelSid,   ///< same as ConvertStringSidToSid("S-1-16-8192",..)
    High      = WinHighLabelSid,     ///< same as ConvertStringSidToSid("S-1-16-12288",..)
};

static std::wstring ToString (IntegrityLevel integrity) {
    switch (integrity) {
    case IntegrityLevel::Default:      return L"default";
    case IntegrityLevel::AppContainer: return L"AppContainer";
    case IntegrityLevel::Low:          return L"low IL";
    case IntegrityLevel::Medium:       return L"medium IL";
    case IntegrityLevel::High:         return L"high IL";
    }

    abort(); // never reached
}

static IntegrityLevel FromString (std::wstring arg) {
    if (arg == L"ac") {
        return IntegrityLevel::AppContainer;
    } else if (arg == L"li") {
        return IntegrityLevel::Low;
    } else if (arg == L"mi") {
        return IntegrityLevel::Medium;
    } else if (arg == L"hi") {
        return IntegrityLevel::High;
    }

    return IntegrityLevel::Default;
}


class Permissions {
public:
    /** Determine the resulting acces mask for a filesystem object when being requested by identity_sid.
        Based on https://docs.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-geteffectiverightsfromacla */
    class Check {
    public:
        Check (const wchar_t * identity_sid) : m_autz_mgr(nullptr, nullptr), m_autz_client_ctx(nullptr, nullptr) {
            Initialize();

            SidWrap identity_sid_bin;
            BOOL ok = ConvertStringSidToSid(identity_sid, &identity_sid_bin);
            if (!ok)
                throw std::runtime_error("ConvertStringSidToSid failure");

            {
                AUTHZ_CLIENT_CONTEXT_HANDLE tmp_ctx = nullptr;
                ok = AuthzInitializeContextFromSid(0, identity_sid_bin, m_autz_mgr.get(), NULL, {}, NULL, &tmp_ctx);
                if (!ok)
                    throw std::runtime_error("AuthzInitializeContextFromSid failure");

                m_autz_client_ctx = {tmp_ctx, AuthzFreeContext};
            }
        }

        ~Check() {
        }

        ACCESS_MASK TryAccessPath(const wchar_t* path) {
            LocalWrap<PSECURITY_DESCRIPTOR> path_sd;
            {
                // Obtain information about the security of a file or directory. The returned info. is filtered by the caller's access rights.
                DWORD length = 0;
                BOOL ok = GetFileSecurity(path, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, NULL, NULL, &length);
                if (ok || (ERROR_INSUFFICIENT_BUFFER != ::GetLastError()))
                    return 0;

                *&path_sd = LocalAlloc(LPTR, length);
                ok = GetFileSecurity(path, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, path_sd, length, &length);
                if (!ok)
                    return 0;
            }

            return TryAccess(path_sd);
        }

        ACCESS_MASK TryAccess(PSECURITY_DESCRIPTOR sd) {
            ACCESS_MASK GrantedAccess = 0;
            DWORD       Error = 0;
            {
                AUTHZ_ACCESS_REQUEST AccessRequest = {};
                AccessRequest.DesiredAccess = MAXIMUM_ALLOWED;
                AccessRequest.PrincipalSelfSid = NULL;
                AccessRequest.ObjectTypeList = NULL;
                AccessRequest.ObjectTypeListLength = 0;
                AccessRequest.OptionalArguments = NULL;

                AUTHZ_ACCESS_REPLY AccessReply = {};
                AccessReply.ResultListLength = 1;
                AccessReply.GrantedAccessMask = &GrantedAccess; // [size_is(ResultListLength)]
                AccessReply.Error             = &Error;         // [size_is(ResultListLength)]

                // perform access check
                BOOL ok = AuthzAccessCheck(0, m_autz_client_ctx.get(), &AccessRequest, NULL, sd, NULL, 0, &AccessReply, NULL);
                if (!ok)
                    return 0;
            }

            return GrantedAccess;
        }

        /** Based on https://docs.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-geteffectiverightsfromacla */
        static bool HasReadAccess (ACCESS_MASK mask) {
            if ((mask & GENERIC_READ) == GENERIC_READ)
                return true;
            if ((mask & FILE_GENERIC_READ) == FILE_GENERIC_READ)
                return true;
            return false;
        }

        /** Special access control checking for COM. Must be kept in sync with EnableLaunchActPermission function below.
            REF: https://docs.microsoft.com/en-us/windows/win32/com/access-control-lists-for-com */
        static bool HasLaunchPermission(ACCESS_MASK mask) {
            return (mask & COM_RIGHTS_EXECUTE) && (mask & COM_RIGHTS_EXECUTE_LOCAL) && (mask & COM_RIGHTS_ACTIVATE_LOCAL);
        }

    private:
        void Initialize() {
            AUTHZ_RESOURCE_MANAGER_HANDLE mgr_tmp = nullptr;
            BOOL ok = AuthzInitializeResourceManager(AUTHZ_RM_FLAG_NO_AUDIT, NULL, NULL, NULL, NULL, &mgr_tmp);
            if (!ok)
                abort(); // should never happen
            m_autz_mgr = { mgr_tmp, AuthzFreeResourceManager };
        }

        std::unique_ptr<std::remove_pointer<AUTHZ_RESOURCE_MANAGER_HANDLE>::type, decltype(&AuthzFreeResourceManager)> m_autz_mgr;
        std::unique_ptr<std::remove_pointer<AUTHZ_CLIENT_CONTEXT_HANDLE>::type, decltype(&AuthzFreeContext)>           m_autz_client_ctx;
    };

    /** Tag a folder path as writable by low integrity level (IL) processes.
        By default, only %USER PROFILE%\AppData\LocalLow is writable.
        Based on "Designing Applications to Run at a Low Integrity Level" https://docs.microsoft.com/en-us/previous-versions/dotnet/articles/bb625960(v%3dmsdn.10)
        Equivalent to "icacls.exe  <path> /setintegritylevel Low"

    Limitations when running under medium IL (e.g. from a non-admin command prompt):
    * Will fail if only the "Administrators" group have full access to the path, even if the current user is a member of that group.
    * Requires either the current user or the "Users" group to be granted full access to the path. */
    static DWORD MakePathLowIntegrity(const wchar_t * path) {
        if (!path || (wcslen(path) == 0))
            return ERROR_BAD_ARGUMENTS;

        ACL * sacl = nullptr; // system access control list (weak ptr.)
        LocalWrap<PSECURITY_DESCRIPTOR> SD; // must outlive SetNamedSecurityInfo to avoid sporadic failures
        {
            // initialize "low IL" System Access Control List (SACL)
            // Security Descriptor String interpretation: (based on sddl.h)
            // SACL:(ace_type=Mandatory integrity Label (ML); ace_flags=; rights=SDDL_NO_WRITE_UP (NW); object_guid=; inherit_object_guid=; account_sid=Low mandatory level (LW))
            WIN32_CHECK(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"S:(ML;;NW;;;LW)", SDDL_REVISION_1, &SD, NULL));
            BOOL sacl_present = FALSE;
            BOOL sacl_defaulted = FALSE;
            WIN32_CHECK(GetSecurityDescriptorSacl(SD, &sacl_present, &sacl, &sacl_defaulted));
        }

        // apply "low IL" SACL
        DWORD ret = SetNamedSecurityInfoW(const_cast<wchar_t*>(path), SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, /*owner*/NULL, /*group*/NULL, /*Dacl*/NULL, sacl);
        return ret; // ERROR_SUCCESS on success
    }


    /** Make file/folder accessible from a given AppContainer.
        Based on https://github.com/zodiacon/RunAppContainer/blob/master/RunAppContainer/RunAppContainerDlg.cpp */
    static DWORD MakePathAppContainer(const wchar_t * ac_str_sid, const wchar_t * path, ACCESS_MASK accessMask) {
        if (!ac_str_sid || (wcslen(ac_str_sid) == 0))
            return ERROR_BAD_ARGUMENTS;
        if (!path || (wcslen(path) == 0))
            return ERROR_BAD_ARGUMENTS;

        // convert string SID to binary
        SidWrap ac_sid;
        WIN32_CHECK(ConvertStringSidToSid(ac_str_sid, &ac_sid));

        EXPLICIT_ACCESSW access = {};
        {
            access.grfAccessPermissions = accessMask;
            access.grfAccessMode = GRANT_ACCESS;
            access.grfInheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
            access.Trustee.pMultipleTrustee = nullptr;
            access.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
            access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
            access.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
            access.Trustee.ptstrName = (wchar_t*)*&ac_sid;
        }

        ACL * prevAcl = nullptr; // weak ptr.
        DWORD status = GetNamedSecurityInfoW(const_cast<wchar_t*>(path), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, /*DACL*/&prevAcl, nullptr, nullptr);
        if (status != ERROR_SUCCESS)
            return status;

        LocalWrap<ACL*> newAcl; // owning ptr.
        status = SetEntriesInAclW(1, &access, prevAcl, &newAcl);
        if (status != ERROR_SUCCESS)
            return status;

        status = SetNamedSecurityInfoW(const_cast<wchar_t*>(path), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, /*DACL*/newAcl, nullptr);
        return status; // ERROR_SUCCESS on success
    }


    /** Enable DCOM launch & activation requests for a given AppContainer SID.
        TODO: Update ACLs instead of replacing it.
        REF: https://docs.microsoft.com/en-us/windows/win32/secauthz/modifying-the-acls-of-an-object-in-c-- */
    static LSTATUS EnableLaunchActPermission (const wchar_t* ac_str_sid, const wchar_t* app_id) {
        if (!ac_str_sid || (wcslen(ac_str_sid) == 0))
            return ERROR_BAD_ARGUMENTS;
        if (!app_id || (wcslen(app_id) == 0))
            return ERROR_BAD_ARGUMENTS;

        // Allow World Local Launch/Activation permissions. Label the SD for LOW IL Execute UP
        // REF: https://docs.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format
        // REF: https://docs.microsoft.com/en-us/windows/win32/com/access-control-lists-for-com
        std::wstring ac_access = L"O:BA";// Owner: Built-in administrators (BA)
        ac_access += L"G:BA";            // Group: Built-in administrators (BA)
        ac_access += L"D:(A;;0xb;;;WD)"; // DACL: (ace_type=Allow (A); ace_flags=; rights=ACTIVATE_LOCAL | EXECUTE_LOCAL | EXECUTE (0xb); object_guid=; inherit_object_guid=; account_sid=Everyone (WD))
        ac_access += L"(A;;0xb;;;";
        ac_access +=             ac_str_sid;
        ac_access +=                     L")"; // (ace_type=Allow (A); ace_flags=; rights=ACTIVATE_LOCAL | EXECUTE_LOCAL | EXECUTE (0xb); object_guid=; inherit_object_guid=; account_sid=ac_str_sid)
        ac_access += L"S:(ML;;NX;;;LW)"; // SACL:(ace_type=Mandatory Label (ML); ace_flags=; rights=No Execute Up (NX); object_guid=; inherit_object_guid=; account_sid=Low mandatory level (LW))
        LocalWrap<PSECURITY_DESCRIPTOR> ac_sd;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(ac_access.c_str(), SDDL_REVISION_1, &ac_sd, NULL))
            abort();

        // open registry path
        CComBSTR reg_path(L"AppID\\");
        reg_path.Append(app_id);

        CRegKey appid_reg;
        if (appid_reg.Open(HKEY_CLASSES_ROOT, reg_path, KEY_READ | KEY_WRITE) != ERROR_SUCCESS)
            abort();

        // Set AppID LaunchPermission registry key to grant appContainer local launch & activation permission
        // REF: https://docs.microsoft.com/en-us/windows/win32/com/launchpermission
        DWORD dwLen = GetSecurityDescriptorLength(ac_sd);
        LSTATUS lResult = appid_reg.SetBinaryValue(L"LaunchPermission", (BYTE*)*&ac_sd, dwLen);
        return lResult;
    }

    /** Retrieve the account type, username & domain for a given SID. */
    static std::tuple<SID_NAME_USE,std::wstring, std::wstring> LookupSID(SID* sid) {
        std::wstring name(128, L'\0');
        auto name_len = (DWORD)name.size();
        std::wstring domain(128, L'\0');
        auto domain_len = (DWORD)name.size();
        SID_NAME_USE snu = {};
        BOOL ok = LookupAccountSidW(NULL, sid, const_cast<wchar_t*>(name.data()), &name_len, const_cast<wchar_t*>(domain.data()), &domain_len, &snu);
        if (!ok) {
            DWORD err = GetLastError();
            HRESULT hr = HRESULT_FROM_WIN32(err); hr;
            return {};
        }
        name.resize(name_len);
        domain.resize(domain_len);
        return {snu, name, domain};
    }
};


/** RAII class for temporarily impersonating users & integrity levels for the current thread.
    Intended to be used together with CLSCTX_ENABLE_CLOAKING when creating COM objects. */
struct ImpersonateThread {
    ImpersonateThread(IntegrityLevel integrity, HANDLE proc) {
        {
            // current user
            HandleWrap cur_token;
            WIN32_CHECK(OpenProcessToken(proc, TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &m_token));
            //WIN32_CHECK(DuplicateTokenEx(cur_token, 0, NULL, SecurityImpersonation, TokenPrimary, &m_token));
        }

        TOKEN_LINKED_TOKEN tlt = {};
        DWORD tlt_len = 0;
        WIN32_CHECK(GetTokenInformation(m_token, TokenLinkedToken, &tlt, sizeof(tlt), &tlt_len));

        TOKEN_ELEVATION elevation = {};
        DWORD ret_len = 0;
        if (!GetTokenInformation(tlt.LinkedToken, TokenElevation, &elevation, sizeof(elevation), &ret_len))
            abort();
        assert(elevation.TokenIsElevated == 0);

        WIN32_CHECK(ImpersonateLoggedOnUser(tlt.LinkedToken)); // change current thread integrity

        //CloseHandle(tlt.LinkedToken);
    }

    ImpersonateThread(HandleWrap & handle) {
        HandleWrap cur_token;
        WIN32_CHECK(OpenProcessToken(handle, TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &cur_token));
        WIN32_CHECK(DuplicateTokenEx(cur_token, 0, NULL, SecurityImpersonation, TokenPrimary, &m_token));

        WIN32_CHECK(ImpersonateLoggedOnUser(m_token)); // change current thread integrity
    }

    ~ImpersonateThread() {
        WIN32_CHECK(RevertToSelf());
    }

    /** Adjust integrity level for the impersonation token.
        Based on "Designing Applications to Run at a Low Integrity Level" https://docs.microsoft.com/en-us/previous-versions/dotnet/articles/bb625960(v%3dmsdn.10) */
    void ApplyIntegrity(IntegrityLevel integrity) {
        assert(integrity != IntegrityLevel::AppContainer);

        SidWrap impersonation_sid;
        impersonation_sid.Create(static_cast<WELL_KNOWN_SID_TYPE>(integrity));

        // reduce process integrity level
        TOKEN_MANDATORY_LABEL TIL = {};
        TIL.Label.Attributes = SE_GROUP_INTEGRITY;
        TIL.Label.Sid = impersonation_sid;
        WIN32_CHECK(SetTokenInformation(m_token, TokenIntegrityLevel, &TIL, sizeof(TIL) + GetLengthSid(impersonation_sid)));
    }

    static HandleWrap GetShellProc() {
        // use explorer.exe as parent process to escape UAC elevation
        // REF: https://devblogs.microsoft.com/oldnewthing/20190425-00/?p=102443
        DWORD pid = 0;
        WIN32_CHECK(GetWindowThreadProcessId(GetShellWindow(), &pid));

        HandleWrap shell_proc;
        shell_proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_CREATE_PROCESS, FALSE, pid); // QUERY_INFORMATION needed for impersonation & CREATE_PROCESS for parent-process setting
        assert(shell_proc);
        return shell_proc;
    }

    /** Determine the integrity level for a process.
    Based on https://github.com/chromium/chromium/blob/master/base/process/process_info_win.cc */
    static IntegrityLevel GetProcessLevel(HANDLE process_token = GetCurrentProcessToken()) {
        DWORD token_info_length = 0;
        if (GetTokenInformation(process_token, TokenIntegrityLevel, NULL, 0, &token_info_length))
            abort(); // should never fail

        std::vector<char> token_info_buf(token_info_length);
        auto* token_info = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(token_info_buf.data());
        if (!GetTokenInformation(process_token, TokenIntegrityLevel, token_info, token_info_length, &token_info_length))
            abort(); // should never fail

        DWORD integrity_level = *GetSidSubAuthority(token_info->Label.Sid, *GetSidSubAuthorityCount(token_info->Label.Sid) - 1);

        if (integrity_level < SECURITY_MANDATORY_LOW_RID)
            return IntegrityLevel::Untrusted;
        if (integrity_level < SECURITY_MANDATORY_MEDIUM_RID)
            return IntegrityLevel::Low;
        else if (integrity_level < SECURITY_MANDATORY_HIGH_RID)
            return IntegrityLevel::Medium;
        else
            return IntegrityLevel::High;
    }

    /** Check if a process is "elevated".
        Please note that elevated processes might still run under medium or low integrity, so this is _not_ a reliable way of checking for administrative privileges. */
    static bool IsProcessElevated (HANDLE process = GetCurrentProcess()) {
        HandleWrap token;
        if (!OpenProcessToken(process, TOKEN_QUERY, &token))
            abort(); // should never happen

        TOKEN_ELEVATION elevation = {};
        DWORD ret_len = 0;
        if (!GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &ret_len))
            abort(); // should never happen

        if (elevation.TokenIsElevated) {
            TOKEN_ELEVATION_TYPE elevation_type = {};
            ret_len = 0;
            if (!GetTokenInformation(token, TokenElevationType, &elevation_type, sizeof(elevation_type), &ret_len))
                abort(); // should never happen

            // elevation_type is usually TokenElevationTypeFull, or
            // TokenElevationTypeDefault if UAC is disabled.
        }

        return elevation.TokenIsElevated;
    }

    HandleWrap  m_token;
};


class RegQuery {
public:
    /** Get EXE path for a COM class. Input is on "{hex-guid}" format. Returns empty string if the COM class is DLL-based and on failure. */
    static std::wstring GetExePath (const std::wstring & clsid, REGSAM bitness = 0/*same bitness as client*/) {
        // extract COM class
        std::wstring reg_path = L"CLSID\\" + clsid + L"\\LocalServer32";

        CRegKey cls_reg;
        if (cls_reg.Open(HKEY_CLASSES_ROOT, reg_path.c_str(), KEY_READ | bitness) != ERROR_SUCCESS)
            return L""; // unknown CLSID

        ULONG exe_path_len = 0;
        if (cls_reg.QueryStringValue(nullptr, nullptr, &exe_path_len) != ERROR_SUCCESS)
            return L""; // unknown key

        std::wstring exe_path(exe_path_len, L'\0');
        if (cls_reg.QueryStringValue(nullptr, const_cast<wchar_t*>(exe_path.data()), &exe_path_len) != ERROR_SUCCESS)
            abort(); // should never happen
        exe_path.resize(exe_path_len - 1); // remove extra zero-termination

        if (exe_path[0] == L'"') {
            // remove quotes and "/automation" or "-activex" arguments
            exe_path = exe_path.substr(1); // remove begin quote

            size_t idx = exe_path.find(L'"');
            if (idx == exe_path.npos)
                return L""; // malformed quoting
            exe_path = exe_path.substr(0, idx); // remove end quote and arguments
        }

        auto to_lower = [](std::wstring str) {
            for (wchar_t & c : str)
                c = towlower(c);
            return str;
        };

        // remove "/automation" arguments after unquoted ".exe" (necessary for PowerPoint)
        size_t idx = to_lower(exe_path).find(L".exe "); // trailing whitespace deliberate
        if (idx != exe_path.npos)
            exe_path = exe_path.substr(0, idx+4);

        return exe_path;
    }

    /** Get AppID GUID for a COM class. Both input & output is on "{hex-guid}" format. Returns empty string on failure. */
    static std::wstring GetAppID (const std::wstring & clsid, REGSAM bitness = 0/*same bitness as client*/) {
        // extract COM class
        std::wstring reg_path = L"CLSID\\" + clsid;

        CRegKey cls_reg;
        if (cls_reg.Open(HKEY_CLASSES_ROOT, reg_path.c_str(), KEY_READ | bitness) != ERROR_SUCCESS)
            return L""; // unknown CLSID

        ULONG app_id_len = 0;
        if (cls_reg.QueryStringValue(L"AppID", nullptr, &app_id_len) != ERROR_SUCCESS)
            return L""; // AppID missing

        std::wstring app_id(app_id_len, L'\0');
        if (cls_reg.QueryStringValue(L"AppID", const_cast<wchar_t*>(app_id.data()), &app_id_len) != ERROR_SUCCESS)
            abort(); // should never happen
        app_id.resize(app_id_len - 1); // remove extra zero-termination
        return app_id;
    }
};
