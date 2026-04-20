#pragma once

// 🔥 REQUIRED MACROS
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)

// Platform define
#define CK_DEFINE_FUNCTION(returnType, name) returnType name

// Include PKCS11 headers
#include "pkcs11/pkcs11.h"