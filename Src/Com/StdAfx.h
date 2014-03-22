/*
 * Copyright (C) 2010-2014 Nektra S.A., Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

#pragma once

#define STRICT
#include "TargetVer.h"
#define WIN32_LEAN_AND_MEAN

#define _ATL_APARTMENT_THREADED
#define _ATL_NO_AUTOMATIC_NAMESPACE
#define _ATL_CSTRING_EXPLICIT_CONSTRUCTORS	// some CString constructors will be explicit

#include "resource.h"
#include <atlbase.h>
#include <atlcom.h>
#include <atlctl.h>


//-----------------------------------------------------------

using namespace ATL;
