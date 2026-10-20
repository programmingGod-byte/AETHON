#include <fluxio.h>
#include <iostream>

int main() {
    std::cout << "Initializing FluxIO DefaultStorageEngine..." << std::endl;
    flux::DefaultStorageEngine engine;
    if (!engine.register_file(0, "data.bin")) {
        std::cerr << "Failed to register data.bin" << std::endl;
        return 1;
    }
    if (!engine.setup_io_uring()) {
        std::cerr << "Failed to setup io_uring backend" << std::endl;
        return 1;
    }
    std::cout << "FluxIO storage engine initialized successfully." << std::endl;
    // Your code here
    return 0;
}
