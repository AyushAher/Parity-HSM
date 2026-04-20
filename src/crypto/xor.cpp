#include "parity_hsm/common.hpp"

std::vector<uint8_t> xor_data(
    const std::vector<uint8_t>& a,
    const std::vector<uint8_t>& b
) {
    std::vector<uint8_t> out(a.size());
    for (size_t i = 0; i < a.size(); i++)
        out[i] = a[i] ^ b[i];
    return out;
}