PROJECT(GTJAGMJNI)

cmake_minimum_required(VERSION 3.4.1)

SET(CMAKE_BUILD_TYPE Release)

# 设置生成的so动态库最后输出的路径
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/../jniLibs/${ANDROID_ABI})

set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} -Wall -v -Wl,--no-warn-shared-textrel -Wl,--no-fatal-warnings --no-Wunused-command-line-argument")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ffunction-sections -fdata-sections -fvisibility=hidden")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ffunction-sections -fdata-sections -fvisibility=hidden")

set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -s")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -s")

set(GMSSL_DIR ${CMAKE_SOURCE_DIR}/src/main/cpp/gmssl)

add_library( # Sets the name of the library.
             GtjaGM

             # Sets the library as a shared library.
             SHARED

             # Provides a relative path to your source file(s).
             src/main/cpp/GTJAComm/GTJAGMUtil/src/GTCryptUtil.cpp
             src/main/cpp/GTJAComm/GTJAUtil/src/GTJAXHexCode.cpp
             src/main/cpp/Jni_IJniInterface.cpp
)

include_directories(
                        src/main/cpp/GTJAComm/GTJAGMUtil/inc
                        src/main/cpp/GTJAComm/GTJAUtil/inc
                        ${GMSSL_DIR}/include
                        ${GMSSL_DIR}/include/openssl
)

find_library( # Sets the name of the path variable.
              log-lib

              # Specifies the name of the NDK library that
              # you want CMake to locate.
              log )

add_library( gmssl
             STATIC
             IMPORTED)

set_target_properties(gmssl      #同上
                      PROPERTIES IMPORTED_LOCATION
                      ${GMSSL_DIR}/prebuild/${ANDROID_ABI}/libcrypto.a )      #三方库位置。


#链接第三方库的头文件
target_include_directories(GtjaGM PRIVATE
                           ${GMSSL_DIR}/include
                           ${GMSSL_DIR}/include/openssl)


target_link_libraries( # Specifies the target library.
                       GtjaGM
                       ${log-lib}
                       gmssl)