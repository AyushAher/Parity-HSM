#include "parity_hsm/common.hpp"

#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include <cstring>

static const size_t BLOCK_SIZE = 512;

// Align size to 512 bytes
size_t align_size(size_t size) {
    size_t remainder = size % BLOCK_SIZE;
    if (remainder == 0) return size;
    return size + (BLOCK_SIZE - remainder);
}

void usb_write(const std::string& path, size_t offset, const std::vector<uint8_t>& data) {
    int fd = open(path.c_str(), O_RDWR);

    if (fd < 0) {
        perror("open failed");
        return;
    }

    // Ensure offset alignment
    if (offset % BLOCK_SIZE != 0) {
        std::cerr << "Offset must be 512-byte aligned\n";
        close(fd);
        return;
    }

    // Prepare buffer: [SIZE][DATA][PADDING]
    uint32_t original_size = data.size();

    size_t total_size = sizeof(original_size) + data.size();
    size_t aligned_total = align_size(total_size);

    std::vector<uint8_t> buffer(aligned_total, 0);

    // Copy size
    std::memcpy(buffer.data(), &original_size, sizeof(original_size));

    // Copy actual data
    std::memcpy(buffer.data() + sizeof(original_size), data.data(), data.size());

    // Seek
    if (lseek(fd, offset, SEEK_SET) < 0) {
        perror("lseek failed");
        close(fd);
        return;
    }

    // Write
    ssize_t written = write(fd, buffer.data(), buffer.size());

    if (written < 0) {
        perror("write failed");
    } else {
        std::cout << "USB WRITE SUCCESS\n";
        std::cout << "Original size: " << original_size << "\n";
        std::cout << "Written (aligned): " << written << "\n";
    }

    fsync(fd);
    close(fd);
}

// Read back data from USB
std::vector<uint8_t> usb_read(const std::string& path, size_t offset) {
    int fd = open(path.c_str(), O_RDONLY);

    if (fd < 0) {
        perror("open failed");
        return {};
    }

    if (offset % BLOCK_SIZE != 0) {
        std::cerr << "Offset must be aligned\n";
        close(fd);
        return {};
    }

    // Read size first
    uint32_t original_size = 0;

    if (lseek(fd, offset, SEEK_SET) < 0) {
        perror("lseek failed");
        close(fd);
        return {};
    }

    if (read(fd, &original_size, sizeof(original_size)) <= 0) {
        perror("read size failed");
        close(fd);
        return {};
    }

    // Read actual data
    std::vector<uint8_t> data(original_size);

    if (read(fd, data.data(), original_size) <= 0) {
        perror("read data failed");
        close(fd);
        return {};
    }

    std::cout << "USB READ SUCCESS\n";
    std::cout << "Recovered size: " << original_size << "\n";

    close(fd);
    return data;
}