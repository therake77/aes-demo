cmake_minimum_required(VERSION 3.23)
project("CPU-AES")

add_executable("Main")
target_sources("Main"
    PRIVATE
        "main.cpp"
)

add_library("FileReader")
add_library("AESLibrary")

target_sources("FileReader"
  PRIVATE
    "src/fileReader.cpp"
  PUBLIC
    FILE_SET HEADERS
    BASE_DIRS
      includes
    FILES
      includes/fileReader.hpp
)

target_sources("AESLibrary"
    PRIVATE
        "src/aes.cpp"
    PUBLIC
        FILE_SET HEADERS
        BASE_DIRS
            "includes"
        FILES
            "includes/aes.hpp"
)

target_link_libraries("Main"
    PRIVATE
        "FileReader"
)

target_link_libraries("Main"
    PRIVATE
        "AESLibrary"
)