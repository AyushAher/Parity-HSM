#pragma once
#include <vector>
#include <string>

std::vector<unsigned char> aes_encrypt(
    const std::vector<unsigned char>& data,
    const std::string& password
);

std::vector<unsigned char> aes_decrypt(
    const std::vector<unsigned char>& data,
    const std::string& password
);