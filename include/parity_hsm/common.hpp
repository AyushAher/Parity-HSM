#pragma once
#include <vector>
#include <string>

std::vector<uint8_t> xor_data(
    const std::vector<uint8_t>& a,
    const std::vector<uint8_t>& b
);

std::vector<uint8_t> aes_encrypt(
    const std::vector<uint8_t>& data,
    const std::string& password
);

std::vector<uint8_t> aes_decrypt(
    const std::vector<uint8_t>& data,
    const std::string& password
);

void usb_write(const std::string& path, size_t offset, const std::vector<uint8_t>& data);
std::vector<uint8_t> usb_read(const std::string& path, size_t offset, size_t size);

void save_file(const std::string& path, const std::vector<uint8_t>& data);
std::vector<uint8_t> load_file(const std::string& path);

std::vector<uint8_t> generate_rsa_private(int bits);

void recover_key(
    const std::string& usb_path,
    size_t offset,
    const std::string& password
);