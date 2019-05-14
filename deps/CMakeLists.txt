cmake_minimum_required (VERSION 3.12.2)
project (ipaSim-deps LANGUAGES NONE)

set (SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/..")
set (BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}")

include (ExternalProject)
add_custom_target (apple-headers-projs)

function (download_proj_nopatch name dir url)
    ExternalProject_Add ("${name}-proj-nopatch"
        SOURCE_DIR "${SOURCE_DIR}/deps/${dir}"
        URL "${url}"
        DOWNLOAD_NO_PROGRESS 1
        CONFIGURE_COMMAND ""
        BUILD_COMMAND ""
        INSTALL_COMMAND "")
endfunction (download_proj_nopatch)
function (download_proj name dir url)
    ExternalProject_Add ("${name}-proj"
        SOURCE_DIR "${SOURCE_DIR}/deps/${dir}"
        URL "${url}"
        DOWNLOAD_NO_PROGRESS 1
        PATCH_COMMAND git init
        COMMAND git apply "${SOURCE_DIR}/contrib/${dir}.patch"
        CONFIGURE_COMMAND ""
        BUILD_COMMAND ""
        INSTALL_COMMAND "")
endfunction (download_proj)
function (download_apple_headers name source_dir url)
    download_proj_nopatch ("${name}" "apple-headers/${source_dir}" "${url}")
    add_dependencies (apple-headers-projs "${name}-proj-nopatch")
endfunction (download_apple_headers)
function (download_apple_tarball name version)
    download_apple_headers ("${name}" "${name}-${version}"
        "https://opensource.apple.com/tarballs/${name}/\
${name}-${version}.tar.gz")
endfunction (download_apple_tarball)
function (download_apple_proj name version)
    download_proj ("${name}" "${name}" "https://opensource.apple.com/tarballs/\
${name}/${name}-${version}.tar.gz")
endfunction (download_apple_proj)
function (download_git name repo tag)
    ExternalProject_Add ("${name}-proj"
        SOURCE_DIR "${SOURCE_DIR}/deps/${name}"
        DOWNLOAD_COMMAND "${CMAKE_COMMAND}"
            "-DTARGET_DIR=${SOURCE_DIR}/deps/${name}"
            "-DREPO=${repo}"
            "-DTAG=${tag}"
            -P "${SOURCE_DIR}/scripts/GitClone.cmake"
        PATCH_COMMAND git apply "${SOURCE_DIR}/contrib/${name}.patch"
        CONFIGURE_COMMAND ""
        BUILD_COMMAND ""
        INSTALL_COMMAND "")
endfunction (download_git)

download_apple_tarball (dyld "519.2.2")
download_apple_tarball (Libc "825.40.1")
download_apple_tarball (libclosure "67")
download_apple_tarball (libplatform "161")
download_apple_tarball (xnu "4570.41.2")
download_apple_headers (ios "iPhoneOS11.1.sdk"
    "http://resources.airnativeextensions.com/ios/iPhoneOS11.1.sdk.zip")
download_apple_headers (macos "MacOSX10.13.sdk" "https://github.com/phracker/\
MacOSX-SDKs/releases/download/10.13/MacOSX10.13.sdk.tar.xz")
ExternalProject_Add (apple-patch-proj
    SOURCE_DIR "${SOURCE_DIR}/deps/apple-headers"
    PATCH_COMMAND git init
    COMMAND git apply "${SOURCE_DIR}/contrib/apple-headers.patch"
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND ""
    DEPENDS apple-headers-projs)
download_git (clang "https://git.llvm.org/git/clang.git/"
    "4519e2637fcc4bf6e3049a0a80e6a5e7b97667cb")
download_apple_proj (libclosure "67")
download_apple_proj (libdispatch "1008.200.78")
download_git (Libffi "https://github.com/newlawrence/Libffi"
    "03309b8867b31d49bc8ef5a6011970e5801651c1")
download_git (LIEF "https://github.com/lief-project/LIEF"
    "a448c5ef315ac9dc97a95bba3968fe79fcab543f")
download_git (lld "https://git.llvm.org/git/lld.git/"
    "b9f34e3a65782a9f33fe9eaf2240ec4f1f6e3f6e")
download_git (lldb "https://git.llvm.org/git/lldb.git/"
    "637da661b5ef6fd47f4b077ffd26a79b1c1892f9")
download_git (llvm "https://git.llvm.org/git/llvm.git/"
    "dd3329aeb25d87d4ac6429c0af220f92e1ba5f26")
download_apple_proj (objc4 "723")
download_proj_nopatch (pthreads "pthreads.2"
    "ftp://sourceware.org/pub/pthreads-win32/pthreads-w32-2-9-1-release.tar.gz")
download_git (tapi "https://github.com/ributzka/tapi"
    "b9205695b4edee91000383695be8de5ba8e0db41")
download_git (unicorn "https://github.com/unicorn-engine/unicorn"
    "d38c8fb27f7f94d81ec546bff6c306e21f949d0e")
download_git (WinObjC
    "https://jjones.visualstudio.com/DefaultCollection/WinObjC/_git/WinObjC"
    "5407646cab410b6a5636baca5841d114e7e83607")
