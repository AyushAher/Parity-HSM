#include "parity_hsm/vault.h"

#include "parity_hsm/common.hpp"
#include "parity_hsm/secure_memory.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <fstream>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <sstream>
#include <stdexcept>

using json = nlohmann::json;

namespace
{
struct VaultEnvelope
{
    std::string label;
    unsigned long long revision = 0;
    bool user_pin_initialized = false;
    std::string so_wrap_hex;
    std::string user_wrap_hex;
    std::string ciphertext_hex;
    std::string auth_tag_hex;
};

struct VaultState
{
    std::string label;
    unsigned long long revision = 0;
    bool user_pin_initialized = false;
    std::vector<json> key_entries;
};

struct VaultStorageConfig
{
    std::string path;
    size_t offset = 4096;
    size_t slot_span = 1024 * 1024;
};

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
    if ((hex.size() % 2) != 0)
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

VaultStorageConfig vault_storage_config()
{
    VaultStorageConfig cfg;
    if (const char* env = std::getenv("PARITY_HSM_VAULT"); env && *env)
        cfg.path = env;
    if (const char* env = std::getenv("PARITY_HSM_VAULT_OFFSET"); env && *env)
        cfg.offset = static_cast<size_t>(std::stoull(env));
    if (const char* env = std::getenv("PARITY_HSM_VAULT_SLOT_SPAN"); env && *env)
        cfg.slot_span = static_cast<size_t>(std::stoull(env));

    if (!cfg.path.empty())
        return cfg;

    std::ifstream f("config/config.json");
    if (!f)
        throw std::runtime_error("unable to open config/config.json");

    json parsed;
    f >> parsed;
    cfg.path = parsed.value("usb_path", std::string("/dev/rdisk4s2"));
    cfg.offset = parsed.value("usb_offset", 4096);
    return cfg;
}

size_t slot_offset(const VaultStorageConfig& cfg, size_t slot_index)
{
    return cfg.offset + (slot_index * cfg.slot_span);
}

std::vector<unsigned char> read_slot_bytes(const VaultStorageConfig& cfg, size_t slot_index)
{
    return usb_read(cfg.path, slot_offset(cfg, slot_index), cfg.slot_span);
}

void write_slot_bytes(const VaultStorageConfig& cfg, size_t slot_index, const std::vector<unsigned char>& data)
{
    if (data.size() + sizeof(uint32_t) > cfg.slot_span)
        throw std::runtime_error("vault envelope exceeds reserved raw slot");
    usb_write(cfg.path, slot_offset(cfg, slot_index), data);
}

std::string key_as_password(const std::vector<unsigned char>& key)
{
    return hex_encode(key);
}

std::vector<unsigned char> random_bytes(size_t size)
{
    std::vector<unsigned char> out(size);
    if (RAND_bytes(out.data(), static_cast<int>(out.size())) != 1)
        throw std::runtime_error("RAND_bytes failed");
    return out;
}

std::vector<unsigned char> sha256_bytes(const std::vector<unsigned char>& input)
{
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx)
        throw std::runtime_error("EVP_MD_CTX_new failed");

    std::vector<unsigned char> digest(EVP_MAX_MD_SIZE);
    unsigned int digest_len = 0;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, input.data(), input.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, digest.data(), &digest_len) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("sha256 failed");
    }

    EVP_MD_CTX_free(ctx);
    digest.resize(digest_len);
    return digest;
}

std::vector<unsigned char> hmac_sha256(const std::vector<unsigned char>& key, const std::vector<unsigned char>& data)
{
    EVP_MAC* mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    EVP_MAC_CTX* ctx = mac ? EVP_MAC_CTX_new(mac) : nullptr;
    if (!mac || !ctx) {
        EVP_MAC_free(mac);
        throw std::runtime_error("HMAC init failed");
    }

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(const_cast<char*>("digest"),
                                                 const_cast<char*>("SHA256"),
                                                 0);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_MAC_init(ctx, key.data(), key.size(), params) != 1 ||
        EVP_MAC_update(ctx, data.data(), data.size()) != 1) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        throw std::runtime_error("HMAC update failed");
    }

    size_t out_len = 0;
    std::vector<unsigned char> out(EVP_MAX_MD_SIZE);
    if (EVP_MAC_final(ctx, out.data(), &out_len, out.size()) != 1) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        throw std::runtime_error("HMAC final failed");
    }

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    out.resize(out_len);
    return out;
}

std::vector<unsigned char> auth_payload(unsigned long long revision, const std::string& ciphertext_hex)
{
    std::string payload = std::to_string(revision) + ":" + ciphertext_hex;
    return std::vector<unsigned char>(payload.begin(), payload.end());
}

VaultEnvelope parse_envelope_bytes(const std::vector<unsigned char>& bytes)
{
    auto parsed = json::parse(bytes.begin(), bytes.end());

    VaultEnvelope envelope;
    envelope.label = parsed.value("label", "ParityHSM");
    envelope.revision = parsed.value("revision", 0ULL);
    envelope.user_pin_initialized = parsed.value("user_pin_initialized", false);
    envelope.so_wrap_hex = parsed.value("so_wrap", "");
    envelope.user_wrap_hex = parsed.value("user_wrap", "");
    envelope.ciphertext_hex = parsed.value("ciphertext", "");
    envelope.auth_tag_hex = parsed.value("auth_tag", "");
    return envelope;
}

std::vector<unsigned char> serialize_envelope(const VaultEnvelope& envelope)
{
    json out = {
        {"version", 2},
        {"label", envelope.label},
        {"revision", envelope.revision},
        {"user_pin_initialized", envelope.user_pin_initialized},
        {"so_wrap", envelope.so_wrap_hex},
        {"user_wrap", envelope.user_wrap_hex},
        {"ciphertext", envelope.ciphertext_hex},
        {"auth_tag", envelope.auth_tag_hex},
    };

    std::string serialized = out.dump();
    return std::vector<unsigned char>(serialized.begin(), serialized.end());
}

std::pair<VaultEnvelope, size_t> read_active_envelope()
{
    const auto cfg = vault_storage_config();
    bool found = false;
    VaultEnvelope best;
    size_t best_slot = 0;

    for (size_t slot = 0; slot < 2; ++slot) {
        try {
            auto bytes = read_slot_bytes(cfg, slot);
            if (bytes.empty())
                continue;
            auto envelope = parse_envelope_bytes(bytes);
            if (!found || envelope.revision > best.revision) {
                found = true;
                best = std::move(envelope);
                best_slot = slot;
            }
        } catch (...) {
        }
    }

    if (!found)
        throw std::runtime_error("unable to read vault envelope");
    return {best, best_slot};
}

VaultState decrypt_state(const std::vector<unsigned char>& vault_key, const VaultEnvelope& envelope)
{
    auto expected_tag = hmac_sha256(vault_key, auth_payload(envelope.revision, envelope.ciphertext_hex));
    if (hex_encode(expected_tag) != envelope.auth_tag_hex)
        throw std::runtime_error("vault auth tag mismatch");

    auto ciphertext = hex_decode(envelope.ciphertext_hex);
    auto plaintext = aes_decrypt(ciphertext, key_as_password(vault_key));
    auto parsed = json::parse(plaintext.begin(), plaintext.end());

    VaultState state;
    state.label = parsed.value("label", envelope.label);
    state.revision = parsed.value("revision", envelope.revision);
    state.user_pin_initialized = envelope.user_pin_initialized;
    state.key_entries = parsed.value("keys", json::array()).get<std::vector<json>>();

    secure_clear(plaintext);
    return state;
}

void write_state(const std::vector<unsigned char>& vault_key,
                 VaultEnvelope& envelope,
                 const VaultState& state)
{
    json plaintext_json = {
        {"label", state.label},
        {"revision", state.revision},
        {"keys", state.key_entries},
    };
    std::string serialized = plaintext_json.dump();
    std::vector<unsigned char> plaintext(serialized.begin(), serialized.end());
    auto ciphertext = aes_encrypt(plaintext, key_as_password(vault_key));
    envelope.label = state.label;
    envelope.revision = state.revision;
    envelope.user_pin_initialized = state.user_pin_initialized;
    envelope.ciphertext_hex = hex_encode(ciphertext);
    envelope.auth_tag_hex = hex_encode(hmac_sha256(vault_key, auth_payload(envelope.revision, envelope.ciphertext_hex)));

    const auto cfg = vault_storage_config();
    const size_t slot_index = static_cast<size_t>(envelope.revision % 2ULL);
    auto bytes = serialize_envelope(envelope);
    write_slot_bytes(cfg, slot_index, bytes);

    secure_clear(bytes);
    secure_clear(plaintext);
    secure_clear(ciphertext);
}

std::string wrap_field_name(CK_USER_TYPE user_type)
{
    if (user_type == CKU_SO)
        return "so";
    if (user_type == CKU_USER)
        return "user";
    throw std::runtime_error("unsupported user type");
}

std::vector<unsigned char> unwrap_vault_key(const VaultEnvelope& envelope,
                                            CK_USER_TYPE user_type,
                                            const std::string& pin)
{
    const std::string& wrap_hex = (user_type == CKU_SO) ? envelope.so_wrap_hex : envelope.user_wrap_hex;
    if (wrap_hex.empty())
        throw std::runtime_error("pin not initialized");

    auto wrapped = hex_decode(wrap_hex);
    auto vault_key = aes_decrypt(wrapped, pin);
    secure_clear(wrapped);
    return vault_key;
}

void update_wrapped_pin(VaultEnvelope& envelope, CK_USER_TYPE user_type, const std::vector<unsigned char>& vault_key, const std::string& pin)
{
    auto wrapped = aes_encrypt(vault_key, pin);
    if (user_type == CKU_SO)
        envelope.so_wrap_hex = hex_encode(wrapped);
    else
        envelope.user_wrap_hex = hex_encode(wrapped);
    secure_clear(wrapped);
}

std::string next_id_hex(const std::vector<json>& keys)
{
    unsigned int candidate = 1;
    while (true) {
        std::ostringstream id;
        id << std::hex << std::setfill('0') << std::setw(2) << candidate;
        bool used = false;
        for (const auto& key : keys)
            used = used || key.value("id", std::string()) == id.str();
        if (!used)
            return id.str();
        ++candidate;
    }
}
}

std::string hsm_vault_path()
{
    const auto cfg = vault_storage_config();
    return cfg.path + "@" + std::to_string(cfg.offset);
}

bool hsm_vault_exists()
{
    try {
        (void)read_active_envelope();
        return true;
    } catch (...) {
        return false;
    }
}

void hsm_vault_initialize(const std::string& so_pin, const std::string& label)
{
    if (so_pin.empty())
        throw std::runtime_error("empty SO PIN is not allowed");

    auto vault_key = random_bytes(32);
    VaultEnvelope envelope;
    envelope.label = label.empty() ? "ParityHSM" : label;
    envelope.revision = 1;
    envelope.user_pin_initialized = false;
    update_wrapped_pin(envelope, CKU_SO, vault_key, so_pin);

    VaultState state;
    state.label = envelope.label;
    state.revision = envelope.revision;
    state.user_pin_initialized = false;
    write_state(vault_key, envelope, state);
    secure_clear(vault_key);
}

void hsm_vault_initialize_user_pin(const std::vector<unsigned char>& auth_key, const std::string& user_pin)
{
    if (user_pin.empty())
        throw std::runtime_error("empty user PIN is not allowed");

    auto [envelope, slot_index] = read_active_envelope();
    (void)slot_index;
    auto state = decrypt_state(auth_key, envelope);
    envelope.user_pin_initialized = true;
    state.user_pin_initialized = true;
    ++state.revision;
    envelope.revision = state.revision;
    update_wrapped_pin(envelope, CKU_USER, auth_key, user_pin);
    write_state(auth_key, envelope, state);
}

void hsm_vault_change_pin(const std::vector<unsigned char>& auth_key, CK_USER_TYPE user_type, const std::string& new_pin)
{
    if (new_pin.empty())
        throw std::runtime_error("empty PIN is not allowed");

    auto [envelope, slot_index] = read_active_envelope();
    (void)slot_index;
    auto state = decrypt_state(auth_key, envelope);
    if (user_type == CKU_USER)
        state.user_pin_initialized = true;
    envelope.user_pin_initialized = state.user_pin_initialized;
    ++state.revision;
    envelope.revision = state.revision;
    update_wrapped_pin(envelope, user_type, auth_key, new_pin);
    write_state(auth_key, envelope, state);
}

std::vector<unsigned char> hsm_vault_authenticate(CK_USER_TYPE user_type, const std::string& pin)
{
    auto [envelope, slot_index] = read_active_envelope();
    (void)slot_index;
    auto key = unwrap_vault_key(envelope, user_type, pin);
    (void)decrypt_state(key, envelope);
    return key;
}

HsmVaultView hsm_vault_view(const std::vector<unsigned char>& auth_key, const std::string& partition)
{
    auto [envelope, slot_index] = read_active_envelope();
    (void)slot_index;
    auto state = decrypt_state(auth_key, envelope);

    HsmVaultView view;
    view.label = state.label;
    view.revision = state.revision;
    view.user_pin_initialized = state.user_pin_initialized;

    for (const auto& item : state.key_entries) {
        if (item.value("partition", "default") != partition)
            continue;
        HsmKeyRecord record;
        record.id_hex = item.value("id", "01");
        record.label = item.value("label", "ParityKey");
        record.partition = item.value("partition", "default");
        record.bits = item.value("bits", 2048);
        view.keys.push_back(std::move(record));
    }

    return view;
}

std::vector<unsigned char> hsm_vault_load_private_key(const std::vector<unsigned char>& auth_key,
                                                      const std::string& partition,
                                                      const std::string& id_hex)
{
    auto [envelope, slot_index] = read_active_envelope();
    (void)slot_index;
    auto state = decrypt_state(auth_key, envelope);

    for (const auto& item : state.key_entries) {
        if (item.value("partition", "default") != partition)
            continue;
        if (item.value("id", std::string()) != id_hex)
            continue;

        auto b = hex_decode(item.at("b_share").get<std::string>());
        auto c = hex_decode(item.at("c_share").get<std::string>());
        auto key = xor_data(b, c);
        secure_clear(b);
        secure_clear(c);
        return key;
    }

    throw std::runtime_error("key not found");
}

HsmKeyRecord hsm_vault_generate_rsa_key(const std::vector<unsigned char>& auth_key,
                                        const std::string& partition,
                                        const std::string& id_hex,
                                        const std::string& label,
                                        int bits)
{
    auto [envelope, slot_index] = read_active_envelope();
    (void)slot_index;
    auto state = decrypt_state(auth_key, envelope);

    auto private_der = generate_rsa_private(bits > 0 ? bits : 2048);
    auto share_b = random_bytes(private_der.size());
    auto share_c = xor_data(private_der, share_b);

    HsmKeyRecord record;
    record.id_hex = id_hex.empty() ? next_id_hex(state.key_entries) : id_hex;
    record.label = label.empty() ? "ParityKey-" + record.id_hex : label;
    record.partition = partition.empty() ? "default" : partition;
    record.bits = bits > 0 ? bits : 2048;

    state.key_entries.push_back({
        {"id", record.id_hex},
        {"label", record.label},
        {"partition", record.partition},
        {"bits", record.bits},
        {"type", "rsa"},
        {"b_share", hex_encode(share_b)},
        {"c_share", hex_encode(share_c)},
    });

    ++state.revision;
    envelope.revision = state.revision;
    state.user_pin_initialized = envelope.user_pin_initialized;
    write_state(auth_key, envelope, state);

    secure_clear(private_der);
    secure_clear(share_b);
    secure_clear(share_c);
    return record;
}

void hsm_vault_import_legacy_if_needed(const std::string& pin)
{
    if (hsm_vault_exists())
        return;

    auto b_enc = load_file("B.enc");
    auto c_enc = load_file("C.enc");
    if (b_enc.empty() || c_enc.empty())
        throw std::runtime_error("vault does not exist");

    auto share_b = aes_decrypt(b_enc, pin);
    auto share_c = aes_decrypt(c_enc, pin);
    auto private_der = xor_data(share_b, share_c);

    hsm_vault_initialize(pin, "ParityHSM");
    auto auth_key = hsm_vault_authenticate(CKU_SO, pin);
    hsm_vault_initialize_user_pin(auth_key, pin);

    auto [envelope, slot_index] = read_active_envelope();
    (void)slot_index;
    auto state = decrypt_state(auth_key, envelope);
    state.key_entries.push_back({
        {"id", "01"},
        {"label", "ParityKey"},
        {"partition", "default"},
        {"bits", 2048},
        {"type", "rsa"},
        {"b_share", hex_encode(share_b)},
        {"c_share", hex_encode(share_c)},
    });
    ++state.revision;
    envelope.revision = state.revision;
    state.user_pin_initialized = true;
    envelope.user_pin_initialized = true;
    write_state(auth_key, envelope, state);

    secure_clear(share_b);
    secure_clear(share_c);
    secure_clear(private_der);
    secure_clear(auth_key);
}
