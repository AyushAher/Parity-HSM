#include "pkcs11_wrapper.h"

#include <dlfcn.h>

#include <algorithm>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

namespace {
CK_FUNCTION_LIST_PTR p11 = nullptr;
void* module_handle = nullptr;

std::string rv_name(CK_RV rv)
{
    switch (rv) {
    case CKR_OK: return "CKR_OK";
    case CKR_ARGUMENTS_BAD: return "CKR_ARGUMENTS_BAD";
    case CKR_BUFFER_TOO_SMALL: return "CKR_BUFFER_TOO_SMALL";
    case CKR_SLOT_ID_INVALID: return "CKR_SLOT_ID_INVALID";
    case CKR_NO_EVENT: return "CKR_NO_EVENT";
    case CKR_ACTION_PROHIBITED: return "CKR_ACTION_PROHIBITED";
    case CKR_ATTRIBUTE_READ_ONLY: return "CKR_ATTRIBUTE_READ_ONLY";
    case CKR_CRYPTOKI_ALREADY_INITIALIZED: return "CKR_CRYPTOKI_ALREADY_INITIALIZED";
    case CKR_CRYPTOKI_NOT_INITIALIZED: return "CKR_CRYPTOKI_NOT_INITIALIZED";
    case CKR_FUNCTION_NOT_SUPPORTED: return "CKR_FUNCTION_NOT_SUPPORTED";
    case CKR_MECHANISM_INVALID: return "CKR_MECHANISM_INVALID";
    case CKR_OBJECT_HANDLE_INVALID: return "CKR_OBJECT_HANDLE_INVALID";
    case CKR_OPERATION_NOT_INITIALIZED: return "CKR_OPERATION_NOT_INITIALIZED";
    case CKR_PIN_INCORRECT: return "CKR_PIN_INCORRECT";
    case CKR_SESSION_HANDLE_INVALID: return "CKR_SESSION_HANDLE_INVALID";
    case CKR_SESSION_PARALLEL_NOT_SUPPORTED: return "CKR_SESSION_PARALLEL_NOT_SUPPORTED";
    case CKR_USER_ALREADY_LOGGED_IN: return "CKR_USER_ALREADY_LOGGED_IN";
    case CKR_USER_NOT_LOGGED_IN: return "CKR_USER_NOT_LOGGED_IN";
    case CKR_USER_TYPE_INVALID: return "CKR_USER_TYPE_INVALID";
    default: return "0x" + std::to_string(rv);
    }
}

bool expect(const std::string& label, CK_RV actual, CK_RV expected)
{
    if (actual == expected) {
        std::cout << "PASS " << label << " -> " << rv_name(actual) << "\n";
        return true;
    }

    std::cerr << "FAIL " << label << " -> got " << rv_name(actual)
              << ", expected " << rv_name(expected) << "\n";
    return false;
}

std::string trim_pkcs11_text(const CK_UTF8CHAR* data, size_t len)
{
    std::string value(reinterpret_cast<const char*>(data), len);
    while (!value.empty() && (value.back() == '\0' || value.back() == ' '))
        value.pop_back();
    return value;
}

bool load_module(const char* path)
{
    module_handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!module_handle) {
        std::cerr << "dlopen failed: " << dlerror() << "\n";
        return false;
    }

    auto get_function_list =
        reinterpret_cast<CK_C_GetFunctionList>(dlsym(module_handle, "C_GetFunctionList"));
    if (!get_function_list) {
        std::cerr << "C_GetFunctionList not found\n";
        return false;
    }

    CK_RV rv = get_function_list(&p11);
    return expect("C_GetFunctionList", rv, CKR_OK) && p11;
}

CK_SESSION_HANDLE open_session(CK_FLAGS flags = CKF_SERIAL_SESSION | CKF_RW_SESSION)
{
    CK_SESSION_HANDLE session = 0;
    CK_RV rv = p11->C_OpenSession(1, flags, nullptr, nullptr, &session);
    if (!expect("C_OpenSession", rv, CKR_OK))
        return 0;
    return session;
}

bool login(CK_SESSION_HANDLE session, const std::string& pin)
{
    CK_RV rv = p11->C_Login(
        session,
        CKU_USER,
        reinterpret_cast<CK_UTF8CHAR_PTR>(const_cast<char*>(pin.data())),
        static_cast<CK_ULONG>(pin.size()));
    return expect("C_Login(CKU_USER)", rv, CKR_OK);
}

bool mode_general()
{
    bool ok = true;
    ok &= expect("C_Initialize", p11->C_Initialize(nullptr), CKR_OK);
    ok &= expect("C_Initialize again", p11->C_Initialize(nullptr), CKR_CRYPTOKI_ALREADY_INITIALIZED);

    CK_INFO info {};
    ok &= expect("C_GetInfo", p11->C_GetInfo(&info), CKR_OK);
    std::cout << "INFO manufacturer=" << trim_pkcs11_text(info.manufacturerID, sizeof(info.manufacturerID))
              << " library=" << trim_pkcs11_text(info.libraryDescription, sizeof(info.libraryDescription))
              << " cryptoki=" << static_cast<int>(info.cryptokiVersion.major) << "."
              << static_cast<int>(info.cryptokiVersion.minor) << "\n";

    ok &= expect("C_Finalize", p11->C_Finalize(nullptr), CKR_OK);
    ok &= expect("C_Finalize again", p11->C_Finalize(nullptr), CKR_CRYPTOKI_NOT_INITIALIZED);
    return ok;
}

bool mode_slot_token()
{
    bool ok = true;
    ok &= expect("C_Initialize", p11->C_Initialize(nullptr), CKR_OK);

    CK_ULONG count = 0;
    ok &= expect("C_GetSlotList(count)", p11->C_GetSlotList(CK_TRUE, nullptr, &count), CKR_OK);
    ok &= count == 1;
    std::vector<CK_SLOT_ID> slots(count);
    ok &= expect("C_GetSlotList(values)", p11->C_GetSlotList(CK_TRUE, slots.data(), &count), CKR_OK);
    ok &= slots[0] == 1;

    CK_SLOT_INFO slot_info {};
    ok &= expect("C_GetSlotInfo", p11->C_GetSlotInfo(1, &slot_info), CKR_OK);
    ok &= expect("C_GetSlotInfo(invalid)", p11->C_GetSlotInfo(99, &slot_info), CKR_SLOT_ID_INVALID);

    CK_TOKEN_INFO token_info {};
    ok &= expect("C_GetTokenInfo", p11->C_GetTokenInfo(1, &token_info), CKR_OK);
    std::cout << "TOKEN label=" << trim_pkcs11_text(token_info.label, sizeof(token_info.label)) << "\n";

    CK_SLOT_ID event_slot = 0;
    ok &= expect("C_WaitForSlotEvent(nonblocking)", p11->C_WaitForSlotEvent(CKF_DONT_BLOCK, &event_slot, nullptr), CKR_NO_EVENT);

    ok &= expect("C_Finalize", p11->C_Finalize(nullptr), CKR_OK);
    return ok;
}

bool mode_session()
{
    bool ok = true;
    ok &= expect("C_Initialize", p11->C_Initialize(nullptr), CKR_OK);

    CK_SESSION_HANDLE ro = open_session(CKF_SERIAL_SESSION);
    CK_SESSION_INFO info {};
    ok &= ro != 0;
    ok &= expect("C_GetSessionInfo(RO)", p11->C_GetSessionInfo(ro, &info), CKR_OK);
    ok &= info.state == CKS_RO_PUBLIC_SESSION;

    CK_SESSION_HANDLE rw = open_session(CKF_SERIAL_SESSION | CKF_RW_SESSION);
    ok &= rw != 0;
    ok &= expect("C_GetSessionInfo(RW)", p11->C_GetSessionInfo(rw, &info), CKR_OK);
    ok &= info.state == CKS_RW_PUBLIC_SESSION;

    ok &= expect("C_CloseSession(RO)", p11->C_CloseSession(ro), CKR_OK);
    ok &= expect("C_CloseSession(RO again)", p11->C_CloseSession(ro), CKR_SESSION_HANDLE_INVALID);
    ok &= expect("C_CloseAllSessions", p11->C_CloseAllSessions(1), CKR_OK);
    ok &= expect("C_GetSessionInfo(closed)", p11->C_GetSessionInfo(rw, &info), CKR_SESSION_HANDLE_INVALID);

    ok &= expect("C_Finalize", p11->C_Finalize(nullptr), CKR_OK);
    return ok;
}

bool mode_auth(const std::string& pin)
{
    bool ok = true;
    ok &= expect("C_Initialize", p11->C_Initialize(nullptr), CKR_OK);
    CK_SESSION_HANDLE session = open_session();
    ok &= session != 0;

    std::string wrong = pin + "-wrong";
    ok &= expect("C_Login(wrong PIN)",
                 p11->C_Login(session, CKU_USER, reinterpret_cast<CK_UTF8CHAR_PTR>(wrong.data()), wrong.size()),
                 CKR_PIN_INCORRECT);
    ok &= expect("C_Login(CKU_SO)",
                 p11->C_Login(session, CKU_SO, reinterpret_cast<CK_UTF8CHAR_PTR>(const_cast<char*>(pin.data())), pin.size()),
                 CKR_USER_TYPE_INVALID);
    ok &= login(session, pin);
    ok &= expect("C_Login(already)",
                 p11->C_Login(session, CKU_USER, reinterpret_cast<CK_UTF8CHAR_PTR>(const_cast<char*>(pin.data())), pin.size()),
                 CKR_USER_ALREADY_LOGGED_IN);

    CK_SESSION_INFO info {};
    ok &= expect("C_GetSessionInfo(logged in)", p11->C_GetSessionInfo(session, &info), CKR_OK);
    ok &= info.state == CKS_RW_USER_FUNCTIONS;
    ok &= expect("C_Logout", p11->C_Logout(session), CKR_OK);
    ok &= expect("C_Logout again", p11->C_Logout(session), CKR_USER_NOT_LOGGED_IN);
    ok &= expect("C_Finalize", p11->C_Finalize(nullptr), CKR_OK);
    return ok;
}

bool mode_object_management(const std::string& pin)
{
    bool ok = true;
    ok &= expect("C_Initialize", p11->C_Initialize(nullptr), CKR_OK);
    CK_SESSION_HANDLE session = open_session();
    ok &= session != 0 && login(session, pin);

    CK_ULONG size = 0;
    ok &= expect("C_GetObjectSize(private)", p11->C_GetObjectSize(session, 1, &size), CKR_OK);
    ok &= expect("C_GetObjectSize(invalid)", p11->C_GetObjectSize(session, 99, &size), CKR_OBJECT_HANDLE_INVALID);

    char label[32] {};
    CK_ATTRIBUTE label_attr {CKA_LABEL, label, sizeof(label)};
    ok &= expect("C_GetAttributeValue(label)", p11->C_GetAttributeValue(session, 2, &label_attr, 1), CKR_OK);
    ok &= std::string(label, label_attr.ulValueLen) == "ParityKey";

    CK_OBJECT_HANDLE created = 0;
    ok &= expect("C_CreateObject", p11->C_CreateObject(session, nullptr, 0, &created), CKR_ACTION_PROHIBITED);
    ok &= expect("C_CopyObject", p11->C_CopyObject(session, 2, nullptr, 0, &created), CKR_ACTION_PROHIBITED);
    ok &= expect("C_DestroyObject", p11->C_DestroyObject(session, 2), CKR_ACTION_PROHIBITED);
    ok &= expect("C_SetAttributeValue", p11->C_SetAttributeValue(session, 2, &label_attr, 1), CKR_ATTRIBUTE_READ_ONLY);

    ok &= expect("C_Finalize", p11->C_Finalize(nullptr), CKR_OK);
    return ok;
}

bool mode_object_search(const std::string& pin)
{
    bool ok = true;
    ok &= expect("C_Initialize", p11->C_Initialize(nullptr), CKR_OK);
    CK_SESSION_HANDLE session = open_session();
    ok &= session != 0 && login(session, pin);

    CK_OBJECT_CLASS cls = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE templ[] = {{CKA_CLASS, &cls, sizeof(cls)}};
    ok &= expect("C_FindObjectsInit(private)", p11->C_FindObjectsInit(session, templ, 1), CKR_OK);
    CK_OBJECT_HANDLE found = 0;
    CK_ULONG found_count = 0;
    ok &= expect("C_FindObjects(private)", p11->C_FindObjects(session, &found, 1, &found_count), CKR_OK);
    ok &= found_count == 1 && found == 1;
    ok &= expect("C_FindObjectsFinal(private)", p11->C_FindObjectsFinal(session), CKR_OK);

    cls = CKO_PUBLIC_KEY;
    ok &= expect("C_FindObjectsInit(public)", p11->C_FindObjectsInit(session, templ, 1), CKR_OK);
    found = 0;
    found_count = 0;
    ok &= expect("C_FindObjects(public)", p11->C_FindObjects(session, &found, 1, &found_count), CKR_OK);
    ok &= found_count == 1 && found == 2;
    ok &= expect("C_FindObjectsFinal(public)", p11->C_FindObjectsFinal(session), CKR_OK);

    ok &= expect("C_Finalize", p11->C_Finalize(nullptr), CKR_OK);
    return ok;
}

bool mode_key_management(const std::string& pin)
{
    bool ok = true;
    ok &= expect("C_Initialize", p11->C_Initialize(nullptr), CKR_OK);
    CK_SESSION_HANDLE session = open_session();
    ok &= session != 0 && login(session, pin);

    CK_MECHANISM mechanism {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
    CK_OBJECT_HANDLE key = 0;
    CK_OBJECT_HANDLE public_key = 0;
    CK_OBJECT_HANDLE private_key = 0;
    CK_BYTE wrapped[256] {};
    CK_ULONG wrapped_len = sizeof(wrapped);

    ok &= expect("C_GenerateKey", p11->C_GenerateKey(session, &mechanism, nullptr, 0, &key), CKR_FUNCTION_NOT_SUPPORTED);
    unsigned char id_02[] = {0x02};
    const char label_02[] = "ParityKey-02";
    CK_ULONG bits = 2048;
    CK_ATTRIBUTE pub_template[] = {
        {CKA_ID, id_02, sizeof(id_02)},
        {CKA_LABEL, const_cast<char*>(label_02), sizeof(label_02) - 1},
        {CKA_MODULUS_BITS, &bits, sizeof(bits)},
    };
    CK_ATTRIBUTE priv_template[] = {
        {CKA_ID, id_02, sizeof(id_02)},
        {CKA_LABEL, const_cast<char*>(label_02), sizeof(label_02) - 1},
    };
    ok &= expect("C_GenerateKeyPair", p11->C_GenerateKeyPair(session,
                                                             &mechanism,
                                                             pub_template,
                                                             3,
                                                             priv_template,
                                                             2,
                                                             &public_key,
                                                             &private_key),
                 CKR_OK);
    ok &= public_key != 0 && private_key != 0 && public_key != private_key;
    ok &= expect("C_DeriveKey", p11->C_DeriveKey(session, &mechanism, 1, nullptr, 0, &key), CKR_FUNCTION_NOT_SUPPORTED);
    ok &= expect("C_WrapKey", p11->C_WrapKey(session, &mechanism, 2, 1, wrapped, &wrapped_len), CKR_FUNCTION_NOT_SUPPORTED);
    ok &= expect("C_UnwrapKey", p11->C_UnwrapKey(session, &mechanism, 1, wrapped, wrapped_len, nullptr, 0, &key), CKR_FUNCTION_NOT_SUPPORTED);

    ok &= expect("C_Finalize", p11->C_Finalize(nullptr), CKR_OK);
    return ok;
}

bool mode_initialize_token(const std::string& pin)
{
    bool ok = true;
    ok &= expect("C_Initialize", p11->C_Initialize(nullptr), CKR_OK);

    CK_UTF8CHAR label[32];
    memset(label, ' ', sizeof(label));
    memcpy(label, "ParityHSM", 9);
    ok &= expect("C_InitToken",
                 p11->C_InitToken(1,
                                  reinterpret_cast<CK_UTF8CHAR_PTR>(const_cast<char*>(pin.data())),
                                  pin.size(),
                                  label),
                 CKR_OK);

    CK_SESSION_HANDLE session = open_session();
    ok &= session != 0 && login(session, pin);
    ok &= expect("C_Finalize", p11->C_Finalize(nullptr), CKR_OK);
    return ok;
}

bool mode_crypto(const std::string& pin)
{
    bool ok = true;
    ok &= expect("C_Initialize", p11->C_Initialize(nullptr), CKR_OK);
    CK_SESSION_HANDLE session = open_session();
    ok &= session != 0 && login(session, pin);

    CK_MECHANISM mechanism {CKM_RSA_PKCS, nullptr, 0};
    const std::string plaintext = "parity pkcs11 encryption validation";
    CK_ULONG encrypted_len = 0;
    ok &= expect("C_EncryptInit", p11->C_EncryptInit(session, &mechanism, 2), CKR_OK);
    ok &= expect("C_Encrypt(length)", p11->C_Encrypt(session,
                                                     reinterpret_cast<CK_BYTE_PTR>(const_cast<char*>(plaintext.data())),
                                                     plaintext.size(),
                                                     nullptr,
                                                     &encrypted_len),
                 CKR_OK);
    std::vector<CK_BYTE> encrypted(encrypted_len);
    ok &= expect("C_Encrypt(data)", p11->C_Encrypt(session,
                                                   reinterpret_cast<CK_BYTE_PTR>(const_cast<char*>(plaintext.data())),
                                                   plaintext.size(),
                                                   encrypted.data(),
                                                   &encrypted_len),
                 CKR_OK);
    encrypted.resize(encrypted_len);

    CK_ULONG decrypted_len = 0;
    ok &= expect("C_DecryptInit", p11->C_DecryptInit(session, &mechanism, 1), CKR_OK);
    ok &= expect("C_Decrypt(length)", p11->C_Decrypt(session, encrypted.data(), encrypted.size(), nullptr, &decrypted_len), CKR_OK);
    std::vector<CK_BYTE> decrypted(decrypted_len);
    ok &= expect("C_Decrypt(data)", p11->C_Decrypt(session, encrypted.data(), encrypted.size(), decrypted.data(), &decrypted_len), CKR_OK);
    decrypted.resize(decrypted_len);
    ok &= std::string(reinterpret_cast<char*>(decrypted.data()), decrypted.size()) == plaintext;

    CK_ULONG out_len = 0;
    ok &= expect("C_EncryptUpdate", p11->C_EncryptUpdate(session, nullptr, 0, nullptr, &out_len), CKR_FUNCTION_NOT_SUPPORTED);
    ok &= expect("C_EncryptFinal", p11->C_EncryptFinal(session, nullptr, &out_len), CKR_FUNCTION_NOT_SUPPORTED);
    ok &= expect("C_DecryptUpdate", p11->C_DecryptUpdate(session, nullptr, 0, nullptr, &out_len), CKR_FUNCTION_NOT_SUPPORTED);
    ok &= expect("C_DecryptFinal", p11->C_DecryptFinal(session, nullptr, &out_len), CKR_FUNCTION_NOT_SUPPORTED);

    ok &= expect("C_Finalize", p11->C_Finalize(nullptr), CKR_OK);
    return ok;
}
}

int main(int argc, char** argv)
{
    if (argc < 3) {
        std::cerr << "usage: " << argv[0] << " <mode> <module-path> [pin]\n";
        return 2;
    }

    const std::string mode = argv[1];
    const std::string pin = argc >= 4 ? argv[3] : "1234";

    if (!load_module(argv[2]))
        return 1;

    bool ok = false;
    if (mode == "general")
        ok = mode_general();
    else if (mode == "slot-token")
        ok = mode_slot_token();
    else if (mode == "session")
        ok = mode_session();
    else if (mode == "auth")
        ok = mode_auth(pin);
    else if (mode == "object-management")
        ok = mode_object_management(pin);
    else if (mode == "object-search")
        ok = mode_object_search(pin);
    else if (mode == "key-management")
        ok = mode_key_management(pin);
    else if (mode == "initialize-token")
        ok = mode_initialize_token(pin);
    else if (mode == "crypto")
        ok = mode_crypto(pin);
    else {
        std::cerr << "unknown mode: " << mode << "\n";
        return 2;
    }

    if (module_handle)
        dlclose(module_handle);

    return ok ? 0 : 1;
}
