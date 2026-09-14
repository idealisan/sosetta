set(TEST_INCLUDE_DIRS
    ${PROJECT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/fixtures
)

add_executable(test_macho test_macho.c)
target_link_libraries(test_macho PRIVATE sosetta_core)
target_include_directories(test_macho PRIVATE ${TEST_INCLUDE_DIRS})
sosetta_setup_target(test_macho)
add_test(NAME test_macho COMMAND test_macho)

add_executable(test_cpu test_cpu.c)
target_link_libraries(test_cpu PRIVATE sosetta_core)
target_include_directories(test_cpu PRIVATE ${TEST_INCLUDE_DIRS})
sosetta_setup_target(test_cpu)
add_test(NAME test_cpu COMMAND test_cpu)

add_executable(test_syscall test_syscall.c)
target_link_libraries(test_syscall PRIVATE sosetta_core)
target_include_directories(test_syscall PRIVATE ${TEST_INCLUDE_DIRS})
sosetta_setup_target(test_syscall)
add_test(NAME test_syscall COMMAND test_syscall)

add_executable(test_integration test_integration.c)
target_link_libraries(test_integration PRIVATE sosetta_core)
target_include_directories(test_integration PRIVATE ${TEST_INCLUDE_DIRS})
sosetta_setup_target(test_integration)
add_test(NAME test_integration COMMAND test_integration)

add_executable(gen_hello gen_hello.c)
target_link_libraries(gen_hello PRIVATE sosetta_core)
target_include_directories(gen_hello PRIVATE ${TEST_INCLUDE_DIRS})
sosetta_setup_target(gen_hello)

add_test(
    NAME e2e_hello
    COMMAND ${CMAKE_COMMAND}
            -DWORK_DIR=${CMAKE_CURRENT_BINARY_DIR}/e2e
            -DGEN_HELLO=$<TARGET_FILE:gen_hello>
            -DSOSETTA=$<TARGET_FILE:sosetta>
            -P ${CMAKE_CURRENT_SOURCE_DIR}/e2e_hello.cmake
)