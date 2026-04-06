cmake_minimum_required(VERSION 3.14)
project(TelegramBotanBot)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find Botan
find_package(Botan REQUIRED)

# Find cpp-httplib (header-only)
include_directories(${CMAKE_SOURCE_DIR}/third_party/httplib)

# Find nlohmann/json (header-only)
include_directories(${CMAKE_SOURCE_DIR}/third_party/json)

add_executable(bot src/main.cpp)

target_link_libraries(bot
    Botan::Botan
    pthread
    curl  # for HTTPS requests
)

target_compile_definitions(bot PRIVATE
    BOT_TOKEN="${BOT_TOKEN}"
)