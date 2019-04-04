// DynamicLoader.cpp

#include "ipasim/DynamicLoader.hpp"

#include "ipasim/Common.hpp"
#include "ipasim/IpaSimulator.hpp"
#include "ipasim/WrapperIndex.hpp"

#include <ffi.h>
#include <filesystem>
#include <psapi.h> // for `GetModuleInformation`
#include <winrt/Windows.ApplicationModel.h>
#include <winrt/Windows.Storage.h>

using namespace ipasim;
using namespace std;
using namespace winrt;
using namespace Windows::ApplicationModel;
using namespace Windows::Storage;

bool BinaryPath::isFileValid() const {
  if (Relative) {
    return Package::Current()
               .InstalledLocation()
               .TryGetItemAsync(to_hstring(Path))
               .get() != nullptr;
  }
  try {
    StorageFile File =
        StorageFile::GetFileFromPathAsync(to_hstring(Path)).get();
    return true;
  } catch (...) {
    return false;
  }
}

DynamicLoader::DynamicLoader()
    : Emu(*this), Running(false), Restart(false), Continue(false) {
  // Map "kernel" page.
  void *KernelPtr = _aligned_malloc(PageSize, PageSize);
  KernelAddr = reinterpret_cast<uint64_t>(KernelPtr);
  Emu.mapMemory(KernelAddr, PageSize, UC_PROT_NONE);
}

LoadedLibrary *DynamicLoader::load(const string &Path) {
  BinaryPath BP(resolvePath(Path));

  auto I = LIs.find(BP.Path);
  if (I != LIs.end())
    return I->second.get();

  // Check that file exists.
  if (!BP.isFileValid()) {
    Log.error() << "invalid file: " << BP.Path << Log.end();
    return nullptr;
  }

  Log.info() << "loading library " << BP.Path << "...\n";

  LoadedLibrary *L;
  if (LIEF::MachO::is_macho(BP.Path))
    L = loadMachO(BP.Path);
  else if (LIEF::PE::is_pe(BP.Path))
    L = loadPE(BP.Path);
  else {
    Log.error() << "invalid binary type: " << BP.Path << Log.end();
    return nullptr;
  }

  // Recognize wrapper DLLs.
  if (L)
    L->IsWrapperDLL = BP.Relative && startsWith(BP.Path, "gen\\") &&
                      endsWith(BP.Path, ".wrapper.dll");

  return L;
}

// Inspired by `ImageLoaderMachO::segmentsCanSlide`.
bool DynamicLoader::canSegmentsSlide(LIEF::MachO::Binary &Bin) {
  using namespace LIEF::MachO;

  auto FType = Bin.header().file_type();
  return FType == FILE_TYPES::MH_DYLIB || FType == FILE_TYPES::MH_BUNDLE ||
         (FType == FILE_TYPES::MH_EXECUTE && Bin.is_pie());
}

BinaryPath DynamicLoader::resolvePath(const string &Path) {
  if (!Path.empty() && Path[0] == '/') {
    // This path is something like
    // `/System/Library/Frameworks/Foundation.framework/Foundation`.
    return BinaryPath{filesystem::path("gen" + Path).make_preferred().string(),
                      /* Relative */ true};
  }

  // TODO: Handle also `.ipa`-relative paths.
  return BinaryPath{Path, filesystem::path(Path).is_relative()};
}

LoadedLibrary *DynamicLoader::loadMachO(const string &Path) {
  using namespace LIEF::MachO;

  auto LL = make_unique<LoadedDylib>(Parser::parse(Path));
  LoadedDylib *LLP = LL.get();

  // TODO: Select the correct binary more intelligently.
  Binary &Bin = LL->Bin;

  LIs[Path] = move(LL);

  // Check header.
  Header &Hdr = Bin.header();
  if (Hdr.cpu_type() != CPU_TYPES::CPU_TYPE_ARM)
    Log.error("expected ARM binary");
  // Ensure that segments are continuous (required by `relocateSegment`).
  if (Hdr.has(HEADER_FLAGS::MH_SPLIT_SEGS))
    Log.error("MH_SPLIT_SEGS not supported");
  if (!canSegmentsSlide(Bin))
    Log.error("the binary is not slideable");

  // Compute total size of all segments. Note that in Mach-O, segments must
  // slide together (see `ImageLoaderMachO::segmentsMustSlideTogether`).
  // Inspired by `ImageLoaderMachO::assignSegmentAddresses`.
  uint64_t LowAddr = (uint64_t)(-1);
  uint64_t HighAddr = 0;
  for (SegmentCommand &Seg : Bin.segments()) {
    uint64_t SegLow = Seg.virtual_address();
    // Round to page size (as required by unicorn and what even dyld does).
    uint64_t SegHigh = roundToPageSize(SegLow + Seg.virtual_size());
    if ((SegLow < HighAddr && SegLow >= LowAddr) ||
        (SegHigh > LowAddr && SegHigh <= HighAddr)) {
      Log.error("overlapping segments (after rounding to pagesize)");
    }
    if (SegLow < LowAddr) {
      LowAddr = SegLow;
    }
    if (SegHigh > HighAddr) {
      HighAddr = SegHigh;
    }
  }

  // Allocate space for the segments.
  uint64_t Size = HighAddr - LowAddr;
  uintptr_t Addr = (uintptr_t)_aligned_malloc(Size, PageSize);
  if (!Addr)
    Log.error("couldn't allocate memory for segments");
  uint64_t Slide = Addr - LowAddr;
  LLP->StartAddress = Slide;
  LLP->Size = Size;

  // Load segments. Inspired by `ImageLoaderMachO::mapSegments`.
  for (SegmentCommand &Seg : Bin.segments()) {
    // Convert protection.
    uint32_t VMProt = Seg.init_protection();
    uc_prot Perms = UC_PROT_NONE;
    if (VMProt & (uint32_t)VM_PROTECTIONS::VM_PROT_READ) {
      Perms |= UC_PROT_READ;
    }
    if (VMProt & (uint32_t)VM_PROTECTIONS::VM_PROT_WRITE) {
      Perms |= UC_PROT_WRITE;
    }
    if (VMProt & (uint32_t)VM_PROTECTIONS::VM_PROT_EXECUTE) {
      Perms |= UC_PROT_EXEC;
    }

    uint64_t VAddr = Seg.virtual_address() + Slide;
    // Emulated virtual address is actually equal to the "real" virtual
    // address.
    uint8_t *Mem = reinterpret_cast<uint8_t *>(VAddr);
    uint64_t VSize = Seg.virtual_size();

    if (Perms == UC_PROT_NONE) {
      // No protection means we don't have to copy any data, we just map it.
      Emu.mapMemory(VAddr, VSize, Perms);
    } else {
      // TODO: Memory-map the segment instead of copying it.
      auto &Buff = Seg.content();
      // TODO: Copy to the end of the allocated space if flag `SG_HIGHVM` is
      // present.
      memcpy(Mem, Buff.data(), Buff.size());
      Emu.mapMemory(VAddr, VSize, Perms);

      // Clear the remaining memory.
      if (Buff.size() < VSize)
        memset(Mem + Buff.size(), 0, VSize - Buff.size());
    }

    // Relocate addresses. Inspired by `ImageLoaderMachOClassic::rebase`.
    if (Slide > 0) {
      for (Relocation &Rel : Seg.relocations()) {
        if (Rel.is_pc_relative() ||
            Rel.origin() != RELOCATION_ORIGINS::ORIGIN_DYLDINFO ||
            Rel.size() != 32 || (Rel.address() & R_SCATTERED) != 0)
          Log.error("unsupported relocation");

        // Find base address for this relocation. Inspired by
        // `ImageLoaderMachOClassic::getRelocBase`.
        uint64_t RelBase = LowAddr + Slide;

        uint64_t RelAddr = RelBase + Rel.address();

        // TODO: Implement what `ImageLoader::containsAddress` does.
        if (RelAddr > VAddr + VSize || RelAddr < VAddr)
          Log.error("relocation target out of range");

        uint32_t *Val = (uint32_t *)RelAddr;
        // We actively leave NULL pointers untouched. Technically it would be
        // correct to slide them because the PAGEZERO segment slid, too. But
        // programs probably wouldn't be happy if their NULLs were non-zero.
        // TODO: Solve this as the original dyld does. Maybe by always mapping
        // PAGEZERO to address 0 or something like that.
        if (*Val != 0)
          *Val = *Val + Slide;
      }
    }
  }

  // Load referenced libraries. See also #22.
  for (DylibCommand &Lib : Bin.libraries())
    load(Lib.name());

  // Bind external symbols.
  for (BindingInfo &BInfo : Bin.dyld_info().bindings()) {
    // Check binding's kind.
    if ((BInfo.binding_class() != BINDING_CLASS::BIND_CLASS_STANDARD &&
         BInfo.binding_class() != BINDING_CLASS::BIND_CLASS_LAZY) ||
        BInfo.binding_type() != BIND_TYPES::BIND_TYPE_POINTER ||
        BInfo.addend()) {
      Log.error("unsupported binding info");
      continue;
    }
    if (!BInfo.has_library()) {
      Log.error("flat-namespace symbols are not supported yet");
      continue;
    }

    // Find symbol's library.
    string LibName(BInfo.library().name());
    LoadedLibrary *Lib = load(LibName);
    if (!Lib) {
      Log.error("symbol's library couldn't be loaded");
      continue;
    }

    // Find symbol's address.
    string SymName(BInfo.symbol().name());
    uint64_t SymAddr = Lib->findSymbol(*this, SymName);
    if (!SymAddr) {
      Log.error() << "external symbol " << SymName << " from library "
                  << LibName << " couldn't be resolved" << Log.end();
      continue;
    }

    // Bind it.
    uint64_t TargetAddr = BInfo.address() + Slide;
    LLP->checkInRange(TargetAddr);
    *reinterpret_cast<uint32_t *>(TargetAddr) = SymAddr;
  }

  return LLP;
}

LoadedLibrary *DynamicLoader::loadPE(const string &Path) {
  using namespace LIEF::PE;

  // Mark the library as found.
  auto LL = make_unique<LoadedDll>();
  LoadedDll *LLP = LL.get();
  LIs[Path] = move(LL);

  // Load it into memory.
  HMODULE Lib = LoadPackagedLibrary(to_hstring(Path).c_str(), 0);
  if (!Lib) {
    Log.error() << "couldn't load DLL: " << Path << Log.appendWinError();
    LIs.erase(Path);
    return nullptr;
  }
  LLP->Ptr = Lib;

  // Find out where it lies in memory.
  MODULEINFO Info;
  if (!GetModuleInformation(GetCurrentProcess(), Lib, &Info, sizeof(Info))) {
    Log.winError("couldn't load module information");
    return nullptr;
  }
  if (uint64_t Hdr = LLP->findSymbol(*this, "_mh_dylib_header")) {
    // Map libraries that act as `.dylib`s without their PE headers.
    LLP->StartAddress = Hdr;
    LLP->Size =
        Info.SizeOfImage - (Hdr - reinterpret_cast<uint64_t>(Info.lpBaseOfDll));
    LLP->MachOPoser = true;
  } else {
    // Map other libraries in their entirety.
    LLP->StartAddress = reinterpret_cast<uint64_t>(Info.lpBaseOfDll);
    LLP->Size = Info.SizeOfImage;
    LLP->MachOPoser = false;
  }

  // Load the library into Unicorn engine.
  uint64_t StartAddr = alignToPageSize(LLP->StartAddress);
  uint64_t Size = roundToPageSize(LLP->Size);
  Emu.mapMemory(StartAddr, Size, UC_PROT_READ | UC_PROT_WRITE);

  return LLP;
}

void DynamicLoader::execute(LoadedLibrary *Lib) {
  auto *Dylib = dynamic_cast<LoadedDylib *>(Lib);
  if (!Dylib) {
    Log.error("we can only execute Dylibs right now");
    return;
  }

  // Initialize the stack.
  size_t StackSize = 8 * 1024 * 1024; // 8 MiB
  void *StackPtr = _aligned_malloc(StackSize, PageSize);
  uint64_t StackAddr = reinterpret_cast<uint64_t>(StackPtr);
  Emu.mapMemory(StackAddr, StackSize, UC_PROT_READ | UC_PROT_WRITE);
  // Reserve 12 bytes on the stack, so that our instruction logger can read
  // them.
  Emu.writeReg(UC_ARM_REG_SP, StackAddr + StackSize - 12);

  // Install hooks. Hook `catchFetchProtMem` handles calls across platform
  // boundaries (iOS -> Windows). It works thanks to mapping Windows DLLs as
  // non-executable.
  Emu.hook(UC_HOOK_MEM_FETCH_PROT, catchFetchProtMem, this);
  // Hook `catchCode` logs execution for debugging purposes.
  Emu.hook(UC_HOOK_CODE, catchCode, this);
  // Hook `catchMemWrite` logs all memory writes.
  Emu.hook(UC_HOOK_MEM_WRITE, catchMemWrite, this);
  // Hook `catchMemUnmapped` allows through reading and writing to unmapped
  // memory (probably heap or other external objects).
  Emu.hook(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED,
           catchMemUnmapped, this);

  // TODO: Do this also for all non-wrapper Dylibs (i.e., Dylibs that come with
  // the `.ipa` file).
  // TODO: Call also other (user) C++ initializers.
  // Initialize the binary with our Objective-C runtime. This simulates what
  // `dyld_initializer.cpp` does.
  uint64_t Hdr = Dylib->findSymbol(*this, "__mh_execute_header");
  call("libdyld.dll", "_dyld_initialize", reinterpret_cast<void *>(Hdr));
  call("libobjc.dll", "_objc_init");

  // Start at entry point.
  execute(Dylib->Bin.entrypoint() + Dylib->StartAddress);
}

void DynamicLoader::execute(uint64_t Addr) {
  Log.info() << "starting emulation at " << dumpAddr(Addr) << Log.end();

  // Save LR.
  LRs.push(Emu.readReg(UC_ARM_REG_LR));

  // Point return address to kernel.
  Emu.writeReg(UC_ARM_REG_LR, KernelAddr);

  // Start execution.
  for (;;) {
    Running = true;
    Emu.start(Addr);
    assert(!Running && "Flag `Running` was not updated correctly.");

    if (Continue) {
      Continue = false;
      Continuation();
    }

    if (Restart) {
      // If restarting, continue where we left off.
      Restart = false;
      Addr = Emu.readReg(UC_ARM_REG_LR);
    } else
      break;
  }
}

void DynamicLoader::returnToKernel() {
  // Restore LR.
  Emu.writeReg(UC_ARM_REG_LR, LRs.top());
  LRs.pop();

  // Stop execution.
  Emu.stop();
  Running = false;
}

void DynamicLoader::returnToEmulation() {
  // Log details about the return.
  Log.info() << "returning to " << dumpAddr(Emu.readReg(UC_ARM_REG_LR))
             << Log.end();

  assert(!Running);
  Restart = true;
}

bool DynamicLoader::catchFetchProtMem(uc_engine *UC, uc_mem_type Type,
                                      uint64_t Addr, int Size, int64_t Value,
                                      void *Data) {
  return reinterpret_cast<DynamicLoader *>(Data)->handleFetchProtMem(
      Type, Addr, Size, Value);
}

bool DynamicLoader::handleFetchProtMem(uc_mem_type Type, uint64_t Addr,
                                       int Size, int64_t Value) {
  // Check that the target address is in some loaded library.
  AddrInfo AI(lookup(Addr));
  if (!AI.Lib) {
    // Handle return to kernel.
    if (Addr == KernelAddr) {
      Log.info() << "executing kernel at 0x" << to_hex_string(Addr)
                 << " (as protected)" << Log.end();
      returnToKernel();
      return true;
    }

    Log.error("unmapped address fetched");
    return false;
  }

  // If the target is not a wrapper DLL, we must find and call the corresponding
  // wrapper instead.
  bool Wrapper = AI.Lib->IsWrapperDLL;
  if (!Wrapper) {
    filesystem::path WrapperPath(filesystem::path("gen") /
                                 filesystem::path(*AI.LibPath)
                                     .filename()
                                     .replace_extension(".wrapper.dll"));
    LoadedLibrary *WrapperLib = load(WrapperPath.string());
    if (!WrapperLib)
      return false;

    // Load `WrapperIndex`.
    uint64_t IdxAddr =
        WrapperLib->findSymbol(*this, "?Idx@@3UWrapperIndex@ipasim@@A");
    auto *Idx = reinterpret_cast<WrapperIndex *>(IdxAddr);

    // TODO: Add real base address instead of hardcoded 0x1000.
    uint64_t RVA = Addr - AI.Lib->StartAddress + 0x1000;

    // Find Dylib with the corresponding wrapper.
    auto Entry = Idx->Map.find(RVA);
    if (Entry == Idx->Map.end()) {
      // If there's no corresponding wrapper, maybe this is a simple Objective-C
      // method and we can translate it dynamically.
      if (const char *T = AI.Lib->getMethodType(Addr)) {
        Log.info() << "dynamically handling method of type " << T << Log.end();

        // Handle return value.
        TypeDecoder TD(*this, T);
        bool Returns;
        switch (TD.getNextTypeSize()) {
        case 0:
          Returns = false;
          break;
        case 4:
          Returns = true;
          break;
        default:
          Log.error("unsupported return type");
          return false;
        }

        // Process function arguments.
        // TODO: Use `unique_ptr`.
        shared_ptr<DynamicCaller> DC(new DynamicCaller(*this));
        while (TD.hasNext()) {
          size_t Size = TD.getNextTypeSize();
          if (Size == TypeDecoder::InvalidSize)
            return false;
          DC->loadArg(Size);
        }

        continueOutsideEmulation([=]() {
          // Call the function.
          if (!DC->call(Returns, Addr))
            return;

          returnToEmulation();
        });
        return true;
      }

      Log.error() << "cannot find RVA 0x" << to_hex_string(RVA)
                  << " in WrapperIndex of " << WrapperPath.string()
                  << Log.end();
      return false;
    }
    const string &Dylib = Idx->Dylibs[Entry->second];
    LoadedLibrary *WrapperDylib = load(Dylib);
    if (!WrapperDylib)
      return false;

    // Find the correct wrapper using its alias.
    Addr = WrapperDylib->findSymbol(*this, "$__ipaSim_wraps_" + to_string(RVA));
    if (!Addr) {
      Log.error() << "cannot find wrapper for 0x" << to_hex_string(RVA)
                  << " in " << *AI.LibPath << Log.end();
      return false;
    }

    AI = lookup(Addr);
    assert(AI.Lib &&
           "Symbol found in library wasn't found there in reverse lookup.");
  }

  // Log details.
  Log.info() << "fetch prot. mem. at " << dumpAddr(Addr, AI);
  if (!Wrapper)
    Log.infs() << " (not a wrapper)";
  Log.infs() << Log.end();

  // If the target is not a wrapper, we simply jump to it, no need to translate
  // anything.
  if (!Wrapper) {
    Emu.writeReg(UC_ARM_REG_PC, Addr);
    return true;
  }

  // Read register R0 containing address of our structure with function
  // arguments and return value.
  uint32_t R0 = Emu.readReg(UC_ARM_REG_R0);

  continueOutsideEmulation([=]() {
    // Call the target function.
    auto *Func = reinterpret_cast<void (*)(uint32_t)>(Addr);
    Func(R0);

    returnToEmulation();
  });
  return true;
}

void DynamicLoader::catchCode(uc_engine *UC, uint64_t Addr, uint32_t Size,
                              void *Data) {
  reinterpret_cast<DynamicLoader *>(Data)->handleCode(Addr, Size);
}

void DynamicLoader::handleCode(uint64_t Addr, uint32_t Size) {
  AddrInfo AI(inspect(Addr));
  if (!AI.Lib) {
    // Handle return to kernel.
    // TODO: This shouldn't happen since kernel is non-executable but it does.
    // It's the same bug as described below.
    if (Addr == KernelAddr) {
      Log.info() << "executing kernel at 0x" << to_hex_string(Addr)
                 << Log.end();
      returnToKernel();
      return;
    }

    Log.error("unmapped address executed");
    return;
  }

  // There is a bug that sometimes protected memory accesses are not caught by
  // Unicorn Engine.
  // TODO: Fix that bug, maybe.
  // See also <https://github.com/unicorn-engine/unicorn/issues/888>.
  if (!dynamic_cast<LoadedDylib *>(load(*AI.LibPath))) {
    // TODO: Stop execution if this returns false.
    handleFetchProtMem(UC_MEM_FETCH_PROT, Addr, Size, 0);
    return;
  }

#if 1
  auto *R13 = reinterpret_cast<uint32_t *>(Emu.readReg(UC_ARM_REG_R13));
  Log.info() << "executing at " << dumpAddr(Addr, AI) << " [R0 = 0x"
             << to_hex_string(Emu.readReg(UC_ARM_REG_R0)) << ", R1 = 0x"
             << to_hex_string(Emu.readReg(UC_ARM_REG_R1)) << ", R7 = 0x"
             << to_hex_string(Emu.readReg(UC_ARM_REG_R7)) << ", R12 = 0x"
             << to_hex_string(Emu.readReg(UC_ARM_REG_R12)) << ", R13 = 0x"
             << to_hex_string(Emu.readReg(UC_ARM_REG_R13)) << ", [R13] = 0x"
             << to_hex_string(R13[0]) << ", [R13+4] = 0x"
             << to_hex_string(R13[1]) << ", [R13+8] = 0x"
             << to_hex_string(R13[2]) << ", R14 = 0x"
             << to_hex_string(Emu.readReg(UC_ARM_REG_R14)) << "]" << Log.end();
#endif
}

bool DynamicLoader::catchMemWrite(uc_engine *UC, uc_mem_type Type,
                                  uint64_t Addr, int Size, int64_t Value,
                                  void *Data) {
  return reinterpret_cast<DynamicLoader *>(Data)->handleMemWrite(Type, Addr,
                                                                 Size, Value);
}

bool DynamicLoader::handleMemWrite(uc_mem_type Type, uint64_t Addr, int Size,
                                   int64_t Value) {
#if 1
  Log.info() << "writing [" << dumpAddr(Addr) << "] := " << dumpAddr(Value)
             << " (" << Size << ")" << Log.end();
#endif
  return true;
}

bool DynamicLoader::catchMemUnmapped(uc_engine *UC, uc_mem_type Type,
                                     uint64_t Addr, int Size, int64_t Value,
                                     void *Data) {
  return reinterpret_cast<DynamicLoader *>(Data)->handleMemUnmapped(
      Type, Addr, Size, Value);
}

// TODO: Maybe this happens when the emulated app accesses some non-directly
// dependent DLL and we should load it as a whole.
bool DynamicLoader::handleMemUnmapped(uc_mem_type Type, uint64_t Addr, int Size,
                                      int64_t Value) {
  Log.info() << "unmapped memory manipulation at " << dumpAddr(Addr) << " ("
             << Size << ")" << Log.end();

  // Map the memory, so that emulation can continue.
  Addr = alignToPageSize(Addr);
  Size = roundToPageSize(Size);
  Emu.mapMemory(Addr, Size, UC_PROT_READ | UC_PROT_WRITE);

  return true;
}

AddrInfo DynamicLoader::lookup(uint64_t Addr) {
  for (auto &LI : LIs) {
    LoadedLibrary *LL = LI.second.get();
    if (LL->isInRange(Addr))
      return {&LI.first, LL, string()};
  }
  return {nullptr, nullptr, string()};
}

// TODO: Find symbol name and also use this function to implement
// `src/objc/dladdr.mm`.
AddrInfo DynamicLoader::inspect(uint64_t Addr) { return lookup(Addr); }

// Calling `uc_emu_start` inside `emu_start` (e.g., inside a hook) is not very
// good idea. Instead, we need to call it when emulation completely stops (i.e.,
// Unicorn returns from `uc_emu_start`). That's what this function is used for.
// All code that calls or could call `uc_emu_start` should be deferred using
// this function. See also
// <https://github.com/unicorn-engine/unicorn/issues/591>.
void DynamicLoader::continueOutsideEmulation(function<void()> Cont) {
  assert(!Continue && "Only one continuation is supported.");
  Continue = true;
  Continuation = Cont;

  Emu.stop();
  Running = false;
}

DebugStream::Handler DynamicLoader::dumpAddr(uint64_t Addr,
                                             const AddrInfo &AI) {
  return [Addr, &AI](DebugStream &S) {
    if (!AI.Lib) {
      S << "0x" << to_hex_string(Addr);
    } else {
      uint64_t RVA = Addr - AI.Lib->StartAddress;
      S << *AI.LibPath << "+0x" << to_hex_string(RVA);
    }
  };
}

DebugStream::Handler DynamicLoader::dumpAddr(uint64_t Addr) {
  return [this, Addr](DebugStream &S) {
    if (Addr == KernelAddr) {
      S << "kernel!0x" << to_hex_string(Addr);
    } else {
      AddrInfo AI(lookup(Addr));
      dumpAddr(Addr, AI)(S);
    }
  };
}

namespace {

struct Trampoline {
  ffi_cif CIF;
  bool Returns;
  size_t ArgC;
  uint64_t Addr;
};

} // namespace

void DynamicLoader::handleTrampoline(void *Ret, void **Args, void *Data) {
  auto *Tr = reinterpret_cast<Trampoline *>(Data);
  Log.info() << "handling trampoline (arguments: " << Tr->ArgC;
  if (Tr->Returns)
    Log.infs() << ", returns)" << Log.end();
  else
    Log.infs() << ", void)" << Log.end();

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

static void ipaSim_handleTrampoline(ffi_cif *, void *Ret, void **Args,
                                    void *Data) {
  IpaSim.Dyld.handleTrampoline(Ret, Args, Data);
}

// If `Addr` points to emulated code, returns address of wrapper that should be
// called instead. Otherwise, returns `Addr` unchanged.
void *DynamicLoader::translate(void *Addr) {
  uint64_t AddrVal = reinterpret_cast<uint64_t>(Addr);
  AddrInfo AI(lookup(AddrVal));
  if (auto *Dylib = dynamic_cast<LoadedDylib *>(AI.Lib)) {
    // The address points to Dylib.

    if (const char *T = Dylib->getMethodType(AddrVal)) {
      // We have found metadata of the callback method. Now, for simple methods,
      // it's actually quite simple to translate i386 -> ARM calls dynamically,
      // so that's what we do here.
      // TODO: Generate wrappers for callbacks, too (see README of
      // `HeadersAnalyzer` for more details).
      Log.info() << "dynamically handling callback of type " << T << Log.end();

      // First, handle the return value.
      TypeDecoder TD(*this, T);
      auto *Tr = new Trampoline;
      switch (TD.getNextTypeSize()) {
      case 0:
        Tr->Returns = false;
        break;
      case 4:
        Tr->Returns = true;
        break;
      default:
        Log.error("unsupported return type of callback");
        return nullptr;
      }

      // Next, process function arguments.
      Tr->ArgC = 0;
      while (TD.hasNext()) {
        switch (TD.getNextTypeSize()) {
        case TypeDecoder::InvalidSize:
          return nullptr;
        case 4: {
          if (Tr->ArgC > 3) {
            Log.error("callback has too many arguments");
            return nullptr;
          }
          ++Tr->ArgC;
          break;
        }
        default:
          Log.error("unsupported callback argument type");
          return nullptr;
        }
      }

      // Now, create trampoline.
      Tr->Addr = AddrVal;
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
      if (ffi_prep_closure_loc(Closure, &Tr->CIF, ipaSim_handleTrampoline, Tr,
                               Ptr) != FFI_OK) {
        Log.error("couldn't prepare closure");
        return nullptr;
      }
      return Ptr;
    }

    Log.error("callback not found");
    return nullptr;
  }

  return Addr;
}

// =============================================================================
// DynamicCaller
// =============================================================================

void DynamicLoader::DynamicCaller::loadArg(size_t Size) {
  for (size_t I = 0; I != Size; I += 4) {
    if (RegId <= UC_ARM_REG_R3)
      // We have some registers left, use them.
      Args.push_back(Dyld.Emu.readReg(RegId++));
    else {
      // Otherwise, use stack.
      // TODO: Don't read SP every time.
      uint32_t SP = Dyld.Emu.readReg(UC_ARM_REG_SP);
      SP = SP + (Args.size() - 4) * 4;
      Args.push_back(*reinterpret_cast<uint32_t *>(SP));
    }
  }
}

bool DynamicLoader::DynamicCaller::call(bool Returns, uint32_t Addr) {
#define CASE(N)                                                                \
  case N:                                                                      \
    call0<N>(Returns, Addr);                                                   \
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

size_t DynamicLoader::TypeDecoder::getNextTypeSizeImpl() {
  switch (*T) {
  case 'v': // void
    return 0;
  case 'c': // char
  case '@': // id
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

size_t DynamicLoader::TypeDecoder::getNextTypeSize() {
  size_t Result = getNextTypeSizeImpl();

  // Skip digits.
  for (++T; '0' <= *T && *T <= '9'; ++T)
    ;

  return Result;
}
