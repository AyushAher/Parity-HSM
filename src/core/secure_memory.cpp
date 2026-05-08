#include "parity_hsm/secure_memory.h"

#include <openssl/crypto.h>

void secure_zero(void* ptr, size_t len)
{
    if (ptr && len > 0)
        OPENSSL_cleanse(ptr, len);
}

void secure_clear(std::string& value)
{
    secure_zero(value.data(), value.size());
    value.clear();
}

void secure_clear(std::vector<unsigned char>& value)
{
    secure_zero(value.data(), value.size());
    value.clear();
    value.shrink_to_fit();
}
