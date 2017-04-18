cmake_minimum_required(VERSION 3.3)
project(tesla-cpp-sdk)

find_program(CCACHE_FOUND ccache)
if (CCACHE_FOUND)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)

    if (CMAKE_GENERATOR STREQUAL "Xcode")
        set(CMAKE_XCODE_ATTRIBUTE_CC "/usr/local/Cellar/ccache/3.2.3/libexec/clang")
        set(CMAKE_XCODE_ATTRIBUTE_CXX "/usr/local/Cellar/ccache/3.2.3/libexec/clang++")
    endif ()
endif (CCACHE_FOUND)

include(conanbuildinfo.cmake)
CONAN_BASIC_SETUP()

#-std=c++0x    
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -g -Wno-deprecated -Werror -DFOLLY_HAVE_CLOCK_GETTIME")

if (CMAKE_SYSTEM_NAME MATCHES "Linux")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libstdc++")
endif ()

include_directories(${PROJECT_SOURCE_DIR}/src)

MAKE_DIRECTORY(${PROJECT_BINARY_DIR}/lib)
MAKE_DIRECTORY(${PROJECT_BINARY_DIR}/bin)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)

#注意：不是很可靠。可能不会自动更新，需要重新刷下本文件
FILE(GLOB_RECURSE SRC_LIST RELATIVE ${PROJECT_SOURCE_DIR} "src/*.c*")
FILE(GLOB_RECURSE SRC_INCLUDE_LIST RELATIVE ${PROJECT_SOURCE_DIR} "src/*.h*")

#library
add_library(tesla-sdk-static ${SRC_LIST} ${SRC_INCLUDE_LIST} src/net/TeslaServerChannel.h)
target_link_libraries(tesla-sdk-static ${CONAN_LIBS} pthread)
INSTALL(TARGETS tesla-sdk-static ARCHIVE DESTINATION /usr/local/lib)
#静态库指定别名
SET_TARGET_PROPERTIES(tesla-sdk-static PROPERTIES OUTPUT_NAME "tesla-cpp-sdk")

FILE(GLOB_RECURSE API RELATIVE ${PROJECT_SOURCE_DIR} "src/tesla/*.h*")
INSTALL(FILES ${API} DESTINATION /usr/local/include/tesla-cpp-sdk)


#动态库
#ADD_LIBRARY(tesla-sdk-so SHARED ${SRC_LIST} ${SRC_INCLUDE_LIST})
#target_link_libraries(tesla-sdk-so ${CONAN_LIBS} pthread)
#INSTALL(TARGETS discover LIBRARY DESTINATION /usr/local/lib)

