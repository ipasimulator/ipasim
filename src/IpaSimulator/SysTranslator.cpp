// SysTranslator.cpp

#include "ipasim/SysTranslator.hpp"

#include "ipasim/Common.hpp"
#include "ipasim/IpaSimulator.hpp"
#include "ipasim/IpaSimulator/Config.hpp"
#include "ipasim/WrapperIndex.hpp"

#include <filesystem>

using namespace ipasim;
using namespace std;

namespace {

struct Trampoline {
  ffi_cif CIF;
  bool Returns;
  size_t ArgC;
  uint64_t Addr;
};

} // namespace

void SysTranslator::execute(LoadedLibrary *Lib) {
  auto *Dylib = dynamic_cast<LoadedDylib *>(Lib);
  if (!Dylib) {
    Log.error("we can only execute Dylibs right now");
    return;
  }

  // Initialize the stack.
  size_t StackSize = 8 * 1024 * 1024; // 8 MiB
  void *StackPtr = _aligned_malloc(StackSize, DynamicLoader::PageSize);
  uint64_t StackAddr = reinterpret_cast<uint64_t>(StackPtr);
  Emu.mapMemory(StackAddr, StackSize, UC_PROT_READ | UC_PROT_WRITE);
  // Reserve 12 bytes on the stack, so that our instruction logger can read
  // them.
  Emu.writeReg(UC_ARM_REG_SP, StackAddr + StackSize - 12);

  // Install hooks.
  // This hook handles calls across platform boundaries (iOS -> Windows). It
  // works thanks to mapping Windows DLLs as non-executable.
  Emu.hook(UC_HOOK_MEM_FETCH_PROT, &SysTranslator::handleFetchProtMem, this);
  if constexpr (PrintInstructions)
    // This hook logs execution for debugging purposes.
    Emu.hook(UC_HOOK_CODE, &SysTranslator::handleCode, this);
  if constexpr (PrintMemoryWrites)
    // This hook logs all memory writes.
    Emu.hook(UC_HOOK_MEM_WRITE, &SysTranslator::handleMemWrite, this);
  // This hook allows through reading and writing to unmapped memory (probably
  // heap or other external objects).
  Emu.hook(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED,
           &SysTranslator::handleMemUnmapped, this);

  // TODO: Do this also for all non-wrapper Dylibs (i.e., Dylibs that come with
  // the `.ipa` file).
  // TODO: Call also other (user) C++ initializers.
  // Initialize the binary with our Objective-C runtime. This simulates what
  // `MachOInitializer.cpp` does.
  uint64_t Hdr = Dylib->findSymbol(Dyld, "__mh_execute_header");
  IpaSim.Dyld.registerMachO(reinterpret_cast<void *>(Hdr));
  call("libobjc.dll", "_objc_init");

  // Start at entry point.
  execute(Dylib->Bin.entrypoint() + Dylib->StartAddress);
}

void SysTranslator::execute(uint64_t Addr) {
  if constexpr (PrintEmuInfo)
    Log.info() << "starting emulation at " << Dyld.dumpAddr(Addr) << Log.end();

  // Save LR.
  LRs.push(Emu.readReg(UC_ARM_REG_LR));

  // Point return address to kernel.
  Emu.writeReg(UC_ARM_REG_LR, Dyld.getKernelAddr());

  // Start execution.
  for (;;) {
    Running = true;
    Emu.start(Addr);
    assert(!Running && "Flag `Running` was not updated correctly.");

    if (Continue) {
      Continue = false;
      Continuation();
      Continuation = nullptr;
    }

    if (Restart) {
      // If restarting, continue where we left off.
      Restart = false;
      if (RestartFromLRs) {
        RestartFromLRs = false;
        Addr = LRs.top();
        LRs.pop();
      } else
        Addr = Emu.readReg(UC_ARM_REG_LR);
    } else
      break;
  }
}

void SysTranslator::returnToKernel() {
  if constexpr (PrintEmuInfo)
    Log.info() << "executing kernel at 0x"
               << to_hex_string(Dyld.getKernelAddr()) << Log.end();

  // Restore LR.
  Emu.writeReg(UC_ARM_REG_LR, LRs.top());
  LRs.pop();

  // Stop execution.
  Emu.stop();
  Running = false;
}

void SysTranslator::returnToEmulation() {
  if constexpr (PrintEmuInfo)
    Log.info() << "returning to " << Dyld.dumpAddr(Emu.readReg(UC_ARM_REG_LR))
               << Log.end();

  assert(!Running);
  Restart = true;
}

// Calling `uc_emu_start` inside `uc_emu_start` (e.g., inside a hook) is not
// very good idea. Instead, we need to call it when emulation completely stops
// (i.e., Unicorn returns from `uc_emu_start`). That's what this function is
// used for. All code that calls or could call `uc_emu_start` should be deferred
// using this function. See also
// <https://github.com/unicorn-engine/unicorn/issues/591>.
void SysTranslator::continueOutsideEmulation(function<void()> &&Cont) {
  assert(!Continue && "Only one continuation is supported.");
  Continue = true;
  Continuation = move(Cont);

  Emu.stop();
  Running = false;
}

// Note that we never return `true` from this handler, so that protected memory
// stays protected in Unicorn. If we returned `true`, Unicorn would fetch the
// memory, and it would get into the cache, effectively becoming unprotected.
bool SysTranslator::handleFetchProtMem(uc_mem_type Type, uint64_t Addr,
                                       int Size, int64_t Value) {
  // Handle return to kernel.
  if (Addr == Dyld.getKernelAddr()) {
    returnToKernel();

    Emu.ignoreNextError();
    return false;
  }

  // Check that the target address is in some loaded library.
  LibraryInfo LI(Dyld.lookup(Addr));
  if (!LI.Lib) {
    Log.error() << "non-library address fetched (" << Dyld.dumpAddr(Addr) << ")"
                << Log.end();
    return false;
  }
  if (LI.Lib->isDylib()) {
    Log.error() << "protected memory fetched in Dylib (" << Dyld.dumpAddr(Addr)
                << ")" << Log.end();
    return false;
  }
  bool Wrapper = LI.Lib->IsWrapper;

  // Log details.
  if constexpr (PrintEmuInfo) {
    Log.info() << "fetch prot. mem. at " << Dyld.dumpAddr(Addr, LI);
    if (!Wrapper)
      Log.infs() << " (not a wrapper)";
    Log.infs() << Log.end();
  }

  if (Wrapper) {
    // Read register R0 containing address of our structure with function
    // arguments and return value.
    uint32_t R0 = Emu.readReg(UC_ARM_REG_R0);

    continueOutsideEmulation([=]() {
      // Call the target function.
      auto *Func = reinterpret_cast<void (*)(uint32_t)>(Addr);
      Func(R0);

      returnToEmulation();
    });

    Emu.ignoreNextError();
    return false;
  }

  // If the target is not a wrapper DLL, we must find and call the corresponding
  // wrapper instead.
  filesystem::path DLLPath(*LI.LibPath);
  filesystem::path WrapperPath(
      filesystem::path("gen") /
      DLLPath.filename().replace_extension(".wrapper.dll"));
  LoadedLibrary *WrapperLib = Dyld.load(WrapperPath.string());
  if (!WrapperLib) {
    Log.error() << "cannot find wrapper DLL " << WrapperPath << Log.end();
    return false;
  }

  // Load `WrapperIndex`.
  uint64_t IdxAddr =
      WrapperLib->findSymbol(Dyld, "?Idx@@3UWrapperIndex@ipasim@@A");
  auto *Idx = reinterpret_cast<WrapperIndex *>(IdxAddr);

  uint64_t RVA = Addr - LI.Lib->StartAddress + DLLBase;

  // Find Dylib with the corresponding wrapper.
  auto Entry = Idx->Map.find(RVA);
  if (Entry != Idx->Map.end()) {
    const string &Dylib = Idx->Dylibs[Entry->second];
    LoadedLibrary *WrapperDylib = Dyld.load(Dylib);
    if (!WrapperDylib) {
      Log.error() << "cannot load wrapper Dylib " << Dylib << Log.end();
      return false;
    }

    // Find the correct wrapper using its alias.
    Addr = WrapperDylib->findSymbol(
        Dyld, WrapsPrefix.S + DLLPath.stem().string() + "_" + to_string(RVA));
    if (!Addr) {
      Log.error() << "cannot find wrapper for 0x" << to_hex_string(RVA)
                  << " in " << *LI.LibPath << Log.end();
      return false;
    }

    if constexpr (PrintEmuInfo)
      Log.info() << "found wrapper at " << Dyld.dumpAddr(Addr) << Log.end();

    // Note that doing just `Emu.writeReg(UC_ARM_REG_PC, Addr);` instead of all
    // this didn't work in Release mode for some reason.
    Emu.stop();
    Running = false;
    Restart = true;
    RestartFromLRs = true;
    LRs.push(Addr);

    Emu.ignoreNextError();
    return false;
  }

  // If there's no corresponding wrapper, maybe this is a simple Objective-C
  // method and we can translate it dynamically.
  ObjCMethod M = LI.Lib->getMachO().findMethod(Addr);
  if (!M) {
    Log.error() << "cannot find Objective-C method for "
                << Dyld.dumpAddr(Addr, LI) << Log.end();
    return false;
  }

  if constexpr (PrintEmuInfo)
    Log.info() << "dynamically handling method " << Dyld.dumpAddr(Addr, LI, M)
               << Log.end();

  // Handle return value.
  TypeDecoder TD(M.getType());
  bool Returns;
  switch (TD.getNextTypeSize()) {
  case 0:
    Returns = false;
    break;
  case 4:
    Returns = true;
    break;
  default:
    Log.error() << "unsupported return type of " << Dyld.dumpAddr(Addr, LI, M)
                << Log.end();
    return false;
  }

  // Process function arguments.
  auto DC = make_unique<DynamicCaller>(Emu);
  while (TD.hasNext()) {
    size_t Size = TD.getNextTypeSize();
    if (Size == TypeDecoder::InvalidSize)
      return false;
    DC->loadArg(Size);
  }

  continueOutsideEmulation([=, DCP = DC.release()]() {
    unique_ptr<DynamicCaller> DC(DCP);

    // Call the function.
    if (!DC->call(Returns, Addr))
      return;

    returnToEmulation();
  });

  Emu.ignoreNextError();
  return false;
}

void SysTranslator::handleCode(uint64_t Addr, uint32_t Size) {
  auto *R13 = reinterpret_cast<uint32_t *>(Emu.readReg(UC_ARM_REG_R13));
  Log.info() << "executing at " << Dyld.dumpAddr(Addr) << " [R0 = 0x"
             << to_hex_string(Emu.readReg(UC_ARM_REG_R0)) << ", R1 = 0x"
             << to_hex_string(Emu.readReg(UC_ARM_REG_R1)) << ", R7 = 0x"
             << to_hex_string(Emu.readReg(UC_ARM_REG_R7)) << ", R12 = 0x"
             << to_hex_string(Emu.readReg(UC_ARM_REG_R12)) << ", R13 = 0x"
             << to_hex_string(Emu.readReg(UC_ARM_REG_R13)) << ", [R13] = 0x"
             << to_hex_string(R13[0]) << ", [R13+4] = 0x"
             << to_hex_string(R13[1]) << ", [R13+8] = 0x"
             << to_hex_string(R13[2]) << ", R14 = 0x"
             << to_hex_string(Emu.readReg(UC_ARM_REG_R14)) << "]" << Log.end();
}

bool SysTranslator::handleMemWrite(uc_mem_type Type, uint64_t Addr, int Size,
                                   int64_t Value) {
  Log.info() << "writing [" << Dyld.dumpAddr(Addr)
             << "] := " << Dyld.dumpAddr(Value) << " (" << Size << ")"
             << Log.end();
  return true;
}

// TODO: Maybe this happens when the emulated app accesses some non-directly
// dependent DLL and we should load it as a whole.
bool SysTranslator::handleMemUnmapped(uc_mem_type Type, uint64_t Addr, int Size,
                                      int64_t Value) {
  if constexpr (PrintEmuInfo)
    Log.info() << "unmapped memory manipulation at " << Dyld.dumpAddr(Addr)
               << " (" << Size << ")" << Log.end();

  // Map the memory, so that emulation can continue.
  Addr = DynamicLoader::alignToPageSize(Addr);
  Size = DynamicLoader::roundToPageSize(Size);
  Emu.mapMemory(Addr, Size, UC_PROT_READ | UC_PROT_WRITE);

  return true;
}

void SysTranslator::handleTrampoline(void *Ret, void **Args, void *Data) {
  auto *Tr = reinterpret_cast<Trampoline *>(Data);

  if constexpr (PrintEmuInfo) {
    Log.info() << "handling trampoline (arguments: " << Tr->ArgC;
    if (Tr->Returns)
      Log.infs() << ", returns)" << Log.end();
    else
      Log.infs() << ", void)" << Log.end();
  }

  // Pass arguments.
  uc_arm_reg RegId = UC_ARM_REG_R0;
  for (size_t I = 0, ArgC = Tr->ArgC; I != ArgC; ++I)
    Emu.writeReg(RegId++, *reinterpret_cast<uint32_t *>(Args[I]));

  // Call the function.
  execute(Tr->Addr);

  // Extract return value.
  if (Tr->Returns)
    *reinterpret_cast<ffi_arg *>(Ret) = Emu.readReg(UC_ARM_REG_R0);
}

void SysTranslator::handleTrampolineStatic(ffi_cif *, void *Ret, void **Args,
                                           void *Data) {
  IpaSim.Sys.handleTrampoline(Ret, Args, Data);
}

// If `FP` points to emulated code, returns address of wrapper that should be
// called instead. Otherwise, returns `FP` unchanged.
void *SysTranslator::translate(void *FP) {
  uint64_t Addr = reinterpret_cast<uint64_t>(FP);
  LibraryInfo LI(Dyld.lookup(Addr));

  auto *Dylib = dynamic_cast<LoadedDylib *>(LI.Lib);
  if (!Dylib)
    return FP;

  ObjCMethod M = Dylib->getMachO().findMethod(Addr);
  if (!M) {
    Log.error("callback not found");
    return nullptr;
  }

  // We have found metadata of the callback method. Now, for simple methods,
  // it's actually quite simple to translate i386 -> ARM calls dynamically,
  // so that's what we do here.
  // TODO: Generate wrappers for callbacks, too (see README of
  // `HeadersAnalyzer` for more details).
  if constexpr (PrintEmuInfo)
    Log.info() << "dynamically handling callback " << Dyld.dumpAddr(Addr, LI, M)
               << Log.end();

  // First, handle the return value.
  TypeDecoder TD(M.getType());
  bool Returns;
  switch (TD.getNextTypeSize()) {
  case 0:
    Returns = false;
    break;
  case 4:
    Returns = true;
    break;
  default:
    Log.error("unsupported return type of callback");
    return nullptr;
  }

  // Next, process function arguments.
  size_t ArgC = 0;
  while (TD.hasNext()) {
    switch (TD.getNextTypeSize()) {
    case TypeDecoder::InvalidSize:
      return nullptr;
    case 4: {
      if (ArgC > 3) {
        Log.error("callback has too many arguments");
        return nullptr;
      }
      ++ArgC;
      break;
    }
    default:
      Log.error("unsupported callback argument type");
      return nullptr;
    }
  }

  // Now, create trampoline.
  return createTrampoline(FP, ArgC, Returns);
}

void *SysTranslator::translate(void *FP, size_t ArgC, bool Returns) {
  using namespace LIEF::MachO;

  uint64_t Addr = reinterpret_cast<uint64_t>(FP);
  LibraryInfo LI(IpaSim.Dyld.lookup(Addr));

  if (LI.Lib) {
    auto *Dylib = dynamic_cast<LoadedDylib *>(LI.Lib);
    if (!Dylib)
      return FP;

    // `FP` is a Dylib wrapper. We can skip it, we just need to find what it
    // wraps.
    if (Dylib->IsWrapper)
      for (Symbol &Symbol : Dylib->lookup(Addr)) {
        // Find special symbol name.
        if (!startsWith(Symbol.name(), WrapsPrefix))
          continue;

        // Parse the special name.
        const char *Postfix = Symbol.name().c_str() + WrapsPrefix.Len;
        const char *Underscore = strchr(Postfix, '_');
        if (!Underscore) {
          Log.error() << "invalid special symbol " << Symbol.name()
                      << Log.end();
          continue;
        }
        uint64_t RVA = atol(Underscore + 1);
        string DLLName = string(Postfix, Underscore - Postfix) + ".dll";

        // Load the wrapped library.
        LoadedLibrary *Lib = Dyld.load(DLLName);
        if (!Lib) {
          Log.error() << "couldn't load DLL for symbol " << Symbol.name()
                      << Log.end();
          continue;
        }
        if (RVA >= Lib->Size) {
          Log.error() << "RVA out of bounds for symbol " << Symbol.name()
                      << Log.end();
          continue;
        }

        Addr = Lib->StartAddress + RVA - DLLBase;
        if constexpr (PrintEmuInfo)
          Log.info() << "skipped wrapper for symbol " << Symbol.name() << " ("
                     << Dyld.dumpAddr(Addr) << ")" << Log.end();
        return reinterpret_cast<void *>(Addr);
      }
  }

  return createTrampoline(FP, ArgC, Returns);
}

void *SysTranslator::createTrampoline(void *FP, size_t ArgC, bool Returns) {
  assert(ArgC <= 4);

  // TODO: Don't create different trampolines for the same `FP`.
  auto *Tr = new Trampoline;
  Tr->Returns = Returns;
  Tr->ArgC = ArgC;
  Tr->Addr = reinterpret_cast<uint64_t>(FP);

  void *Ptr;
  // TODO: `Closure` nor `Tr` are never deallocated.
  auto *Closure = reinterpret_cast<ffi_closure *>(
      ffi_closure_alloc(sizeof(ffi_closure), &Ptr));
  if (!Closure) {
    Log.error("couldn't allocate closure");
    return nullptr;
  }
  static ffi_type *ArgTypes[4] = {&ffi_type_uint32, &ffi_type_uint32,
                                  &ffi_type_uint32, &ffi_type_uint32};
  if (ffi_prep_cif(&Tr->CIF, FFI_MS_CDECL, Tr->ArgC,
                   Tr->Returns ? &ffi_type_uint32 : &ffi_type_void,
                   ArgTypes) != FFI_OK) {
    Log.error("couldn't prepare CIF");
    return nullptr;
  }
  if (ffi_prep_closure_loc(Closure, &Tr->CIF, handleTrampolineStatic, Tr,
                           Ptr) != FFI_OK) {
    Log.error("couldn't prepare closure");
    return nullptr;
  }
  return Ptr;
}

// =============================================================================
// DynamicCaller
// =============================================================================

void DynamicCaller::loadArg(size_t Size) {
  for (size_t I = 0; I != Size; I += 4) {
    if (RegId <= UC_ARM_REG_R3)
      // We have some registers left, use them.
      Args.push_back(Emu.readReg(RegId++));
    else {
      // Otherwise, use stack.
      Args.push_back(*reinterpret_cast<uint32_t *>(SP));
      SP += 4;
    }
  }
}

bool DynamicCaller::call(bool Returns, uint32_t Addr) {
#define CASE(N)                                                                \
  case N:                                                                      \
    call<N>(Returns, Addr);                                                    \
    break

  switch (Args.size()) {
    CASE(0);
    CASE(1);
    CASE(2);
    CASE(3);
    CASE(4);
    CASE(5);
    CASE(6);
  default:
    Log.error("function has too many arguments");
    return false;
  }
  return true;

#undef CASE
}

// =============================================================================
// TypeDecoder
// =============================================================================

size_t TypeDecoder::getNextTypeSizeImpl() {
  switch (*T) {
  case 'v': // void
    return 0;
  case 'c': // char
  case '@': // id
  case '#': // Class
  case ':': // SEL
  case 'i': // int
  case 'I': // unsigned int
  case 'f': // float
    return 4;
  case '^': // pointer to type
    ++T;
    getNextTypeSizeImpl(); // Skip the underlying type, it's not important.
    return 4;
  case '{': { // struct
    // Skip name of the struct.
    for (++T; *T != '='; ++T)
      if (!*T) {
        Log.error("struct type ended unexpectedly");
        return InvalidSize;
      }
    ++T;

    // Parse type recursively (note that the struct can be also empty).
    size_t TotalSize = 0;
    while (*T != '}') {
      size_t Size = getNextTypeSize();
      if (Size == InvalidSize)
        return InvalidSize;
      TotalSize += Size;
    }

    return TotalSize;
  }
  default:
    Log.error("unsupported type encoding");
    return InvalidSize;
  }
}

size_t TypeDecoder::getNextTypeSize() {
  size_t Result = getNextTypeSizeImpl();

  // Skip digits.
  for (++T; '0' <= *T && *T <= '9'; ++T)
    ;

  return Result;
}
