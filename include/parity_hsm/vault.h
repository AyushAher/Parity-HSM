#pragma once

#include <string>
#include <vector>

struct HsmKeyRecord {
    std::string id_hex;
    std::string label;
    int bits = 2048;
    std::vector<unsigned char> private_der;
};

std::string hsm_vault_path();
bool hsm_vault_exists();
void hsm_vault_initialize(const std::string& master_pin, const std::string& label);
std::vector<HsmKeyRecord> hsm_vault_load(const std::string& master_pin);
void hsm_vault_save(const std::string& master_pin, const std::vector<HsmKeyRecord>& keys);
HsmKeyRecord hsm_vault_generate_rsa_key(const std::string& master_pin,
                                        const std::string& id_hex,
                                        const std::string& label,
                                        int bits);
std::vector<unsigned char> hsm_vault_get_private_key(const std::string& master_pin,
                                                     const std::string& id_hex);
std::vector<unsigned char> hsm_vault_default_private_key(const std::string& master_pin);
void hsm_vault_import_legacy_if_needed(const std::string& master_pin);
