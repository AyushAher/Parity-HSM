#pragma once

#include <string>
#include <vector>

void secure_zero(void* ptr, size_t len);
void secure_clear(std::string& value);
void secure_clear(std::vector<unsigned char>& value);
