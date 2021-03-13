#pragma once
#include "ComSupport.hpp"
#include "Resource.h"
#include "TestControl_h.h"

// copied from https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/compatibility/dn519894(v=vs.85)
DEFINE_GUID(CATID_AppContainerCompatible, 0x59fb2056, 0xd625, 0x48d0, 0xa9, 0x44, 0x1a, 0x85, 0xb5, 0xab, 0x26, 0x40);


class ATL_NO_VTABLE TestControl :
    public CComObjectRootEx<CComMultiThreadModel>, // also compatible with single-threaded apartment
    public CComCoClass<TestControl, &CLSID_TestControl>,
    public ITestInterface
{
public:
    TestControl();

    /*NOT virtual*/ ~TestControl();

    HRESULT STDMETHODCALLTYPE Add(int a, int b, int * sum) override;

    HRESULT STDMETHODCALLTYPE IsElevated (/*out*/BOOL * is_elevated, /*out*/BOOL * is_high_il) override;

    HRESULT STDMETHODCALLTYPE TestNetworkConnection (/*in*/BSTR host, USHORT port, /*out*/BOOL * can_access) override;

    HRESULT STDMETHODCALLTYPE CreateInstance (BOOL elevated, CLSID clsid, /*out*/IUnknown ** obj) override;

    HRESULT STDMETHODCALLTYPE TestCallback(IUnknown * obj) override;

    HRESULT STDMETHODCALLTYPE MoveMouseCursor(int x_pos, int y_pos, /*out*/DWORD * access) override;

    DECLARE_REGISTRY_RESOURCEID(IDR_TestControl)

    BEGIN_COM_MAP(TestControl)
        COM_INTERFACE_ENTRY(ITestInterface)
    END_COM_MAP()

#if 0
    BEGIN_CATEGORY_MAP(TestControl)
        IMPLEMENTED_CATEGORY(CATID_AppContainerCompatible)
    END_CATEGORY_MAP()
#endif
};

OBJECT_ENTRY_AUTO(CLSID_TestControl, TestControl)
