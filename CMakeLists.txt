cmake_minimum_required(VERSION 3.16)
project(certify VERSION 0.1 LANGUAGES CXX)

find_package(Boost
             COMPONENTS
               system
               filesystem
               date_time
             REQUIRED)

find_package(OpenSSL REQUIRED)


add_library(core INTERFACE)
add_library(certify::core ALIAS core)

target_compile_features(core INTERFACE cxx_std_11)

target_include_directories(core INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

if(MSVC)
    target_link_libraries(core INTERFACE Crypt32.lib)
endif()

target_link_libraries(
    core
    INTERFACE
        Boost::system
        Boost::filesystem
        Boost::date_time
        OpenSSL::SSL
        OpenSSL::Crypto)

include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "certifyConfigVersion.cmake"
    COMPATIBILITY AnyNewerVersion)

install(FILES
            "netutilsConfig.cmake"
            "${CMAKE_BINARY_DIR}/certifyConfigVersion.cmake"
        DESTINATION lib/cmake/certify)

install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/
        DESTINATION include
        FILES_MATCHING PATTERN "*.hpp")

install(TARGETS core
        EXPORT certifyTargets
        INCLUDES DESTINATION include)

install(EXPORT certifyTargets
        FILE certifyTargets.cmake
        NAMESPACE certify::
        DESTINATION lib/cmake/certify)

