#include <iostream>
#include "parity_hsm/common.hpp"

void generate_and_store(const std::string& config_path);

int main() {
    std::cout << "Parity HSM Init\n";
    generate_and_store("config/config.json");
    return 0;
}