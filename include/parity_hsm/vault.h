#pragma once

#include "pkcs11_wrapper.h"

#include <string>
#include <vector>

struct HsmKeyRecord
{
    std::string id_hex;
    std::string label;
    std::string partition;
    int bits = 2048;
};

struct HsmVaultView
{
    std::string label;
    unsigned long long revision = 0;
    bool user_pin_initialized = false;
    std::vector<HsmKeyRecord> keys;
};

std::string hsm_vault_path();
bool hsm_vault_exists();
void hsm_vault_initialize(const std::string& so_pin, const std::string& label);
void hsm_vault_initialize_user_pin(const std::vector<unsigned char>& auth_key, const std::string& user_pin);
void hsm_vault_change_pin(const std::vector<unsigned char>& auth_key, CK_USER_TYPE user_type, const std::string& new_pin);

std::vector<unsigned char> hsm_vault_authenticate(CK_USER_TYPE user_type, const std::string& pin);

HsmVaultView hsm_vault_view(const std::vector<unsigned char>& auth_key, const std::string& partition);

std::vector<unsigned char> hsm_vault_load_private_key(const std::vector<unsigned char>& auth_key,
                                                      const std::string& partition,
                                                      const std::string& id_hex);

HsmKeyRecord hsm_vault_generate_rsa_key(const std::vector<unsigned char>& auth_key,
                                        const std::string& partition,
                                        const std::string& id_hex,
                                        const std::string& label,
                                        int bits);

void hsm_vault_import_legacy_if_needed(const std::string& pin);
