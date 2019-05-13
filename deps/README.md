# Third-party dependencies

1. Download and extract

   - <https://opensource.apple.com/tarballs/dyld/dyld-519.2.2.tar.gz> into
     `apple-headers/dyld-519.2.2/`,
   - <https://opensource.apple.com/tarballs/Libc/Libc-825.40.1.tar.gz> into
     `apple-headers/Libc-825.40.1/`,
   - <https://opensource.apple.com/tarballs/libclosure/libclosure-67.tar.gz>
     into `apple-headers/libclosure-67/`,
   - <https://opensource.apple.com/tarballs/libplatform/libplatform-161.tar.gz>
     into `apple-headers/libplatform-161/`,
   - <https://opensource.apple.com/tarballs/xnu/xnu-4570.41.2.tar.gz> into
     `apple-headers/xnu-4570.41.2/`,
   - <http://resources.airnativeextensions.com/ios/iPhoneOS11.1.sdk.zip> into
     `apple-headers/iPhoneOS11.1.sdk/`,
   - <https://github.com/phracker/MacOSX-SDKs/releases/download/10.13/MacOSX10.13.sdk.tar.xz>
     into `apple-headers/MacOSX10.13.sdk/`.

2. Apply patch inside `apple-headers/`:

   ```bash
   git apply ../../contrib/apple-headers.patch
   ```

3. Download and extract

   - <https://opensource.apple.com/tarballs/libclosure/libclosure-67.tar.gz>
     into `libclosure/`,
   - <https://opensource.apple.com/tarballs/libdispatch/libdispatch-1008.200.78.tar.gz>
     into `libdispatch/`,
   - <https://opensource.apple.com/tarballs/objc4/objc4-723.tar.gz> into
     `objc4/`,
   - <ftp://sourceware.org/pub/pthreads-win32/pthreads-w32-2-9-1-release.tar.gz>
     into `pthreads.2/`.

4. Clone repositories

   - <https://git.llvm.org/git/clang.git/> at
     `4519e2637fcc4bf6e3049a0a80e6a5e7b97667cb`,
   - <https://github.com/newlawrence/Libffi> at
     `03309b8867b31d49bc8ef5a6011970e5801651c1`,
   - <https://github.com/lief-project/LIEF> at
     `a448c5ef315ac9dc97a95bba3968fe79fcab543f`,
   - <https://git.llvm.org/git/lld.git/> at
     `b9f34e3a65782a9f33fe9eaf2240ec4f1f6e3f6e`,
   - <https://git.llvm.org/git/lldb.git/> at
     `637da661b5ef6fd47f4b077ffd26a79b1c1892f9`,
   - <https://git.llvm.org/git/llvm.git/> at
     `dd3329aeb25d87d4ac6429c0af220f92e1ba5f26`,
   - <https://github.com/ributzka/tapi> at
     `b9205695b4edee91000383695be8de5ba8e0db41`,
   - <https://github.com/unicorn-engine/unicorn> at
     `d38c8fb27f7f94d81ec546bff6c306e21f949d0e`,
   - <https://jjones.visualstudio.com/DefaultCollection/WinObjC/_git/WinObjC> at
     `5407646cab410b6a5636baca5841d114e7e83607`.

5. Apply patches from `../contrib/` in their corresponding directories. For
   example, apply patch `clang.patch` inside `clang/` like this:

   ```bash
   git apply ../../contrib/clang.patch
   ```
