#include "parity_hsm/vault.h"

#include "parity_hsm/common.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <filesystem>
#include <fstream>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <sstream>
#include <stdexcept>

using json = nlohmann::json;

namespace {
std::string hex_encode(const std::vector<unsigned char>& data)
{
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (unsigned char byte : data)
        out << std::setw(2) << static_cast<int>(byte);
    return out.str();
}

std::vector<unsigned char> hex_decode(const std::string& hex)
{
    if (hex.size() % 2 != 0)
        throw std::runtime_error("invalid hex length");

    std::vector<unsigned char> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        unsigned int value = 0;
        std::istringstream in(hex.substr(i, 2));
        in >> std::hex >> value;
        out.push_back(static_cast<unsigned char>(value));
    }
    return out;
}

std::vector<unsigned char> read_file_bytes(const std::string& path)
{
    std::ifstream f(path, std::ios::binary);
    if (!f)
        throw std::runtime_error("unable to open vault");
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}

void write_file_bytes(const std::string& path, const std::vector<unsigned char>& data)
{
    std::filesystem::path p(path);
    std::filesystem::create_directories(p.parent_path());
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f)
        throw std::runtime_error("unable to write vault");
    f.write(reinterpret_cast<const char*>(data.data()), data.size());
    std::filesystem::permissions(p,
                                 std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                                 std::filesystem::perm_options::replace);
}

json empty_vault_json(const std::string& label)
{
    return {
        {"version", 1},
        {"label", label.empty() ? "ParityHSM" : label},
        {"keys", json::array()},
    };
}

json decrypt_vault_json(const std::string& master_pin)
{
    auto encrypted = read_file_bytes(hsm_vault_path());
    auto plaintext = aes_decrypt(encrypted, master_pin);
    return json::parse(plaintext.begin(), plaintext.end());
}

void encrypt_vault_json(const std::string& master_pin, const json& vault)
{
    std::string serialized = vault.dump();
    std::vector<unsigned char> plaintext(serialized.begin(), serialized.end());
    auto encrypted = aes_encrypt(plaintext, master_pin);
    write_file_bytes(hsm_vault_path(), encrypted);
}

std::string next_id_hex(const std::vector<HsmKeyRecord>& keys)
{
    unsigned int candidate = 1;
    while (true) {
        std::ostringstream id;
        id << std::hex << std::setfill('0') << std::setw(2) << candidate;
        bool used = false;
        for (const auto& key : keys)
            used = used || key.id_hex == id.str();
        if (!used)
            return id.str();
        ++candidate;
    }
}
}

std::string hsm_vault_path()
{
    if (const char* env = std::getenv("PARITY_HSM_VAULT"); env && *env)
        return env;

    return (std::filesystem::current_path() / ".parity_hsm" / "token.vault").string();
}

bool hsm_vault_exists()
{
    return std::filesystem::exists(hsm_vault_path());
}

void hsm_vault_initialize(const std::string& master_pin, const std::string& label)
{
    if (master_pin.empty())
        throw std::runtime_error("empty master PIN is not allowed");
    encrypt_vault_json(master_pin, empty_vault_json(label));
}

std::vector<HsmKeyRecord> hsm_vault_load(const std::string& master_pin)
{
    auto vault = decrypt_vault_json(master_pin);
    std::vector<HsmKeyRecord> keys;

    for (const auto& item : vault.value("keys", json::array())) {
        auto B = hex_decode(item.at("b_share").get<std::string>());
        auto C = hex_decode(item.at("c_share").get<std::string>());
        HsmKeyRecord record;
        record.id_hex = item.at("id").get<std::string>();
        record.label = item.value("label", "ParityKey");
        record.bits = item.value("bits", 2048);
        record.private_der = xor_data(B, C);
        keys.push_back(std::move(record));
    }

    return keys;
}

void hsm_vault_save(const std::string& master_pin, const std::vector<HsmKeyRecord>& keys)
{
    json vault = hsm_vault_exists() ? decrypt_vault_json(master_pin) : empty_vault_json("ParityHSM");
    vault["keys"] = json::array();

    for (const auto& key : keys) {
        std::vector<unsigned char> B(key.private_der.size());
        if (RAND_bytes(B.data(), B.size()) != 1)
            throw std::runtime_error("RAND_bytes failed");
        auto C = xor_data(key.private_der, B);

        vault["keys"].push_back({
            {"id", key.id_hex},
            {"label", key.label},
            {"bits", key.bits},
            {"type", "rsa"},
            {"b_share", hex_encode(B)},
            {"c_share", hex_encode(C)},
        });
    }

    encrypt_vault_json(master_pin, vault);
}

HsmKeyRecord hsm_vault_generate_rsa_key(const std::string& master_pin,
                                        const std::string& id_hex,
                                        const std::string& label,
                                        int bits)
{
    auto keys = hsm_vault_load(master_pin);
    HsmKeyRecord record;
    record.id_hex = id_hex.empty() ? next_id_hex(keys) : id_hex;
    record.label = label.empty() ? "ParityKey-" + record.id_hex : label;
    record.bits = bits > 0 ? bits : 2048;
    record.private_der = generate_rsa_private(record.bits);
    keys.push_back(record);
    hsm_vault_save(master_pin, keys);
    return record;
}

std::vector<unsigned char> hsm_vault_get_private_key(const std::string& master_pin,
                                                     const std::string& id_hex)
{
    for (const auto& key : hsm_vault_load(master_pin)) {
        if (key.id_hex == id_hex)
            return key.private_der;
    }
    throw std::runtime_error("key not found");
}

std::vector<unsigned char> hsm_vault_default_private_key(const std::string& master_pin)
{
    auto keys = hsm_vault_load(master_pin);
    if (keys.empty())
        throw std::runtime_error("no keys in vault");
    return keys.front().private_der;
}

void hsm_vault_import_legacy_if_needed(const std::string& master_pin)
{
    if (hsm_vault_exists())
        return;

    auto B_enc = load_file("B.enc");
    auto C_enc = load_file("C.enc");
    if (B_enc.empty() || C_enc.empty())
        throw std::runtime_error("vault does not exist");

    HsmKeyRecord record;
    record.id_hex = "01";
    record.label = "ParityKey";
    record.bits = 2048;
    auto B = aes_decrypt(B_enc, master_pin);
    auto C = aes_decrypt(C_enc, master_pin);
    record.private_der = xor_data(B, C);

    hsm_vault_initialize(master_pin, "ParityHSM");
    hsm_vault_save(master_pin, {record});
}
