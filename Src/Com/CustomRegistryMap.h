/*
 * Copyright (C) 2010-2014 Nektra S.A., Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

#pragma once

#include <atlbase.h>

//-----------------------------------------------------------

#define DECLARE_REGISTRY_RESOURCEID_EX(x, szProgId, szVersion, szDescription, rClsId, \
                                       rLibId, szThreadingModel)                      \
  static HRESULT WINAPI UpdateRegistry(BOOL bRegister)                                \
  {                                                                                   \
    struct _ATL_REGMAP_ENTRY aMapEntries[7];                                          \
    WCHAR szClsId[40], szLibId[40];                                                   \
                                                                                      \
    memset(&aMapEntries[6], 0, sizeof(aMapEntries[6]));                               \
    aMapEntries[0].szKey = L"PROGID";                                                 \
    aMapEntries[0].szData = szProgId;                                                 \
    aMapEntries[1].szKey = L"VERSION";                                                \
    aMapEntries[1].szData = szVersion;                                                \
    aMapEntries[2].szKey = L"DESCRIPTION";                                            \
    aMapEntries[2].szData = szDescription;                                            \
    aMapEntries[3].szKey = L"CLSID";                                                  \
    ::StringFromGUID2(rClsId, szClsId, 40);                                           \
    aMapEntries[3].szData = szClsId;                                                  \
    aMapEntries[4].szKey = L"LIBID";                                                  \
    ::StringFromGUID2(rLibId, szLibId, 40);                                           \
    aMapEntries[4].szData = szLibId;                                                  \
    aMapEntries[5].szKey = L"THREADING";                                              \
    aMapEntries[5].szData = szThreadingModel;                                         \
    __if_exists(_Module)                                                              \
      {                                                                               \
      return _Module.UpdateRegistryFromResource(x, bRegister, aMapEntries);           \
      }                                                                               \
      __if_not_exists(_Module)                                                        \
      {                                                                               \
      return ATL::_pAtlModule->UpdateRegistryFromResource(x, bRegister, aMapEntries); \
      }                                                                               \
  };
