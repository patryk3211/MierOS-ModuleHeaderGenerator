cmake_minimum_required(VERSION 3.11)

project(MierOSModuleHeaderGenerator VERSION 1.0.0 LANGUAGES CXX)

set(SOURCES src/main.cpp)

add_executable(modhdrgen ${SOURCES})

add_subdirectory(libs/elfio)
add_subdirectory(libs/json)

target_link_libraries(modhdrgen elfio::elfio)
target_link_libraries(modhdrgen nlohmann_json::nlohmann_json)

install(TARGETS modhdrgen DESTINATION bin/modhdrgen)

