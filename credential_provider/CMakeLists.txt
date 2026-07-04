cmake_minimum_required(VERSION 3.20)
project(Taala2KenCredentialProvider LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Configure output directories
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Source files
set(SOURCE_FILES
    dllmain.cpp
    Taala2KenProvider.cpp
    Taala2KenCredential.cpp
    PipeServer.cpp
    SecureDesktopHelper.cpp
    provider.def
)

# DLL target config
add_library(Taala2KenCredentialProvider SHARED ${SOURCE_FILES})

# Compiler Definitions & Options
target_compile_definitions(Taala2KenCredentialProvider PRIVATE 
    UNICODE 
    _UNICODE 
    WIN32_LEAN_AND_MEAN
)

# Include directories
target_include_directories(Taala2KenCredentialProvider PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# System Library Linkings
target_link_libraries(Taala2KenCredentialProvider PRIVATE
    credui.lib
    shlwapi.lib
    ole32.lib
    advapi32.lib
    secur32.lib
    setupapi.lib
)

# Set DLL options
set_target_properties(Taala2KenCredentialProvider PROPERTIES
    LINK_FLAGS "/DEF:\"${CMAKE_CURRENT_SOURCE_DIR}/provider.def\""
)
