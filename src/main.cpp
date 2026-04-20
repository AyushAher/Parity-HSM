#include <iostream>
#include <fstream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

void generate_and_store(const std::string&);
void recover_key(const std::string&, size_t, const std::string&);

int main() {
    std::ifstream f("config/config.json");
    json cfg;
    f >> cfg;

    std::string usb = cfg["usb_path"];
    size_t offset = cfg["usb_offset"];
    std::string password = cfg["password"];

    std::cout << "1. Generate\n2. Recover\nChoice: ";
    int choice;
    std::cin >> choice;

    if (choice == 1) {
        generate_and_store("config/config.json");
    } else if (choice == 2) {
        recover_key(usb, offset, password);
    }

    return 0;
}