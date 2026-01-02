# The Flutter tooling requires that developers have a version of Visual Studio
# installed that includes CMake 3.14 or later. You should not increase this
# version, as doing so will cause the plugin to fail to compile for some
# customers of the plugin.
cmake_minimum_required(VERSION 3.14)

# Project-level configuration.
set(PROJECT_NAME "rust_lib_kernel_lens_app")
project(${PROJECT_NAME} LANGUAGES CXX)

include("../cargokit/cmake/cargokit.cmake")

# WORKAROUND: Windows symlink issues with relative paths.
# We compute the project root from CMAKE_SOURCE_DIR (which is app/windows),
# then construct the absolute path to kernel_ffi.
# CMAKE_SOURCE_DIR = .../app/windows
# kernel_ffi is at .../crates/kernel_ffi (2 levels up from app, then into crates)
get_filename_component(PROJECT_ROOT "${CMAKE_SOURCE_DIR}/../.." ABSOLUTE)
set(KERNEL_FFI_ABS_PATH "${PROJECT_ROOT}/crates/kernel_ffi")

apply_cargokit(${PROJECT_NAME} "${KERNEL_FFI_ABS_PATH}" kernel_ffi "")

# List of absolute paths to libraries that should be bundled with the plugin.
# This list could contain prebuilt libraries, or libraries created by an
# external build triggered from this build file.
set(rust_lib_kernel_lens_app_bundled_libraries
  "${${PROJECT_NAME}_cargokit_lib}"
  PARENT_SCOPE
)
