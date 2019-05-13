cmake_minimum_required (VERSION 3.12.2)
project (ipaSim-deps LANGUAGES NONE)

set (SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/..")
set (BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}")

include (ExternalProject)
add_custom_target (apple-headers-projs)

function (download_proj name dir url)
    ExternalProject_Add ("${name}-proj"
        SOURCE_DIR "${SOURCE_DIR}/deps/${dir}"
        URL "${url}"
        DOWNLOAD_NO_PROGRESS 1
        CONFIGURE_COMMAND ""
        BUILD_COMMAND ""
        INSTALL_COMMAND "")
endfunction (download_proj)
function (apple_download name source_dir url)
    download_proj ("${name}" "apple-headers/${source_dir}" "${url}")
    add_dependencies (apple-headers-projs "${name}-proj")
endfunction (apple_download)
function (apple_headers_download name version)
    apple_download ("${name}" "${name}-${version}"
        "https://opensource.apple.com/tarballs/${name}/\
${name}-${version}.tar.gz")
endfunction (apple_headers_download)
function (git_download name repo tag)
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
endfunction (git_download)

apple_headers_download (dyld "519.2.2")
apple_headers_download (Libc "825.40.1")
apple_headers_download (libclosure "67")
apple_headers_download (libplatform "161")
apple_headers_download (xnu "4570.41.2")
apple_download (ios "iPhoneOS11.1.sdk"
    "http://resources.airnativeextensions.com/ios/iPhoneOS11.1.sdk.zip")
apple_download (macos "MacOSX10.13.sdk" "https://github.com/phracker/\
MacOSX-SDKs/releases/download/10.13/MacOSX10.13.sdk.tar.xz")
ExternalProject_Add (apple-patch-proj
    SOURCE_DIR "${SOURCE_DIR}/deps/apple-headers"
    PATCH_COMMAND git apply "${SOURCE_DIR}/contrib/apple-headers.patch"
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND ""
    DEPENDS apple-headers-projs)
git_download (clang "https://git.llvm.org/git/clang.git/"
    "4519e2637fcc4bf6e3049a0a80e6a5e7b97667cb")
git_download (Libffi "https://github.com/newlawrence/Libffi"
    "03309b8867b31d49bc8ef5a6011970e5801651c1")
git_download (LIEF "https://github.com/lief-project/LIEF"
    "38c7ef841627e6d6d1a0a5d8ece7e01ef2a59550")
git_download (lld "https://git.llvm.org/git/lld.git/"
    "b9f34e3a65782a9f33fe9eaf2240ec4f1f6e3f6e")
git_download (lldb "https://git.llvm.org/git/lldb.git/"
    "637da661b5ef6fd47f4b077ffd26a79b1c1892f9")
git_download (llvm "https://git.llvm.org/git/llvm.git/"
    "dd3329aeb25d87d4ac6429c0af220f92e1ba5f26")
download_proj (pthreads "pthreads.2" "ftp://sourceware.org/pub/pthreads-win32/\
pthreads-w32-2-9-1-release.tar.gz")
git_download (tapi "https://github.com/ributzka/tapi"
    "b9205695b4edee91000383695be8de5ba8e0db41")
git_download (unicorn "https://github.com/unicorn-engine/unicorn"
    "d38c8fb27f7f94d81ec546bff6c306e21f949d0e")
git_download (WinObjC
    "https://jjones.visualstudio.com/DefaultCollection/WinObjC/_git/WinObjC"
    "5407646cab410b6a5636baca5841d114e7e83607")
