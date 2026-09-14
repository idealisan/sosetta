cmake_minimum_required(VERSION 3.16)

project(sosetta VERSION 0.1.0 LANGUAGES C)

include(FetchContent)

set(UNICORN_GIT_TAG 2.1.4)
FetchContent_Declare(
    unicorn
    GIT_REPOSITORY https://github.com/unicorn-engine/unicorn.git
    GIT_TAG        ${UNICORN_GIT_TAG}
    GIT_SHALLOW    TRUE
)

set(UNICORN_ARCH "ppc" CACHE STRING "" FORCE)
set(UNICORN_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(UNICORN_INSTALL OFF CACHE BOOL "" FORCE)
set(UNICORN_FUZZ OFF CACHE BOOL "" FORCE)
set(UNICORN_LOGGING OFF CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(unicorn)

add_library(sosetta_core STATIC
    src/macho.c
    src/cpu.c
    src/syscall.c
    src/runtime.c
)
target_include_directories(sosetta_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(sosetta_core PUBLIC unicorn)

add_executable(sosetta src/main.c)
target_link_libraries(sosetta PRIVATE sosetta_core)

function(sosetta_setup_target target)
    set_target_properties(${target} PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${target} PRIVATE -Wall -Wextra -Werror)
    elseif(MSVC)
        target_compile_options(${target} PRIVATE /W4 /WX)
    endif()
endfunction()

sosetta_setup_target(sosetta_core)
sosetta_setup_target(sosetta)

enable_testing()
add_subdirectory(tests)