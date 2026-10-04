cmake_minimum_required(VERSION 3.20)
project(messagetag VERSION 0.1.0 LANGUAGES CXX)

add_executable(messagetag src/main.cpp)
target_compile_features(messagetag PRIVATE cxx_std_20)
set_target_properties(messagetag PROPERTIES CXX_EXTENSIONS OFF)
