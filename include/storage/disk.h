#pragma once
#include <vector>
#include <string>

std::vector<unsigned char> load_file(const std::string& path);
void save_file(const std::string& path, const std::vector<unsigned char>& data);