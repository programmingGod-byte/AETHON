find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBXDP REQUIRED libxdp)
pkg_check_modules(LIBBPF REQUIRED libbpf)

pkg_check_modules(LIBHS REQUIRED libhs)
find_package(OpenSSL REQUIRED)

# Determine host architecture include directory for BPF compilation
if(EXISTS "/usr/include/${CMAKE_LIBRARY_ARCHITECTURE}")
    set(BPF_ARCH_INCLUDE "-I/usr/include/${CMAKE_LIBRARY_ARCHITECTURE}")
elseif(EXISTS "/usr/include/x86_64-linux-gnu")
    set(BPF_ARCH_INCLUDE "-I/usr/include/x86_64-linux-gnu")
else()
    set(BPF_ARCH_INCLUDE "")
endif()

# Compile eBPF program
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/main/xdp_kern_prog.o
    COMMAND clang -O2 -g -target bpf -D__BPF_TRACING__ -I/usr/include ${BPF_ARCH_INCLUDE} -c ${CMAKE_CURRENT_SOURCE_DIR}/main/xdp_kern_prog.c -o ${CMAKE_CURRENT_SOURCE_DIR}/main/xdp_kern_prog.o
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/main/xdp_kern_prog.c
    VERBATIM
)
add_custom_target(ebpf_prog ALL DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/main/xdp_kern_prog.o)

add_executable(test_tls_engine ../tests/test_tls_engine.cpp)
target_include_directories(test_tls_engine PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR} 
    ${LIBHS_INCLUDE_DIRS}
)
target_link_libraries(test_tls_engine PRIVATE 
    aethon::aethon 
    OpenSSL::SSL 
    OpenSSL::Crypto 
    ${LIBHS_LIBRARIES}
)
target_compile_options(test_tls_engine PRIVATE -Wno-interference-size)

add_executable(afxdp_control main/afxdp_control.cpp main/hs_engine.cpp)
add_dependencies(afxdp_control ebpf_prog)
target_include_directories(afxdp_control PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR} 
    ${LIBXDP_INCLUDE_DIRS} 
    ${LIBBPF_INCLUDE_DIRS}
    ${LIBHS_INCLUDE_DIRS}
)
target_link_libraries(afxdp_control PRIVATE 
    aethon::aethon 
    CLI11::CLI11 
    ${LIBXDP_LIBRARIES} 
    ${LIBBPF_LIBRARIES} 
    ${LIBHS_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
    pthread
)
target_compile_options(afxdp_control PRIVATE -Wall -Wextra -pthread -Wno-interference-size)


add_executable(raw_socket_baseline main/raw_socket_baseline.cpp)
target_link_libraries(raw_socket_baseline PRIVATE pthread)
target_compile_options(raw_socket_baseline PRIVATE -Wall -Wextra -pthread)

add_executable(max_power_blaster ../tests/max_power_blaster.cpp)
target_link_libraries(max_power_blaster PRIVATE pthread)
target_compile_options(max_power_blaster PRIVATE -O3 -Wall -Wextra -pthread)

add_executable(chaos_torture_test ../tests/chaos_torture_test.cpp)
target_link_libraries(chaos_torture_test PRIVATE pthread)
target_compile_options(chaos_torture_test PRIVATE -O3 -Wall -Wextra -pthread)

add_executable(stateful_exploit_torture ../tests/stateful_exploit_torture.cpp)
target_link_libraries(stateful_exploit_torture PRIVATE pthread)
target_compile_options(stateful_exploit_torture PRIVATE -O3 -Wall -Wextra -pthread)

