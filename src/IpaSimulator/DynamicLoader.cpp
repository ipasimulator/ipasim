// DynamicLoader.cpp

#include "ipasim/DynamicLoader.hpp"

#include "ipasim/Common.hpp"
#include "ipasim/IpaSimulator.hpp"
#include "ipasim/IpaSimulator/Config.hpp"

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

DynamicLoader::DynamicLoader(Emulator &Emu) : Emu(Emu) {
  // Map "kernel" page.
  void *KernelPtr =
      _aligned_malloc(DynamicLoader::PageSize, DynamicLoader::PageSize);
  KernelAddr = reinterpret_cast<uint64_t>(KernelPtr);
  Emu.mapMemory(KernelAddr, DynamicLoader::PageSize, UC_PROT_NONE);
}

LoadedLibrary *DynamicLoader::load(const string &Path) {
  BinaryPath BP(resolvePath(Path));

  auto I = LLs.find(BP.Path);
  if (I != LLs.end())
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

void DynamicLoader::registerMachO(const void *Hdr) {
  auto HdrPtr = reinterpret_cast<uintptr_t>(Hdr);

  // Do nothing if already registered.
  if (!HdrSet.insert(HdrPtr).second)
    return;
  Hdrs.push_back(Hdr);

  // Fix some bindings.
  size_t Count;
  if (auto *FB = MachO(Hdr).getSectionData<uintptr_t **>(MachO::DataSegment,
                                                         "__fixbind", &Count))
    for (auto *EndFB = FB + Count; FB != EndFB; ++FB)
      if (*FB)
        **FB = reinterpret_cast<uintptr_t *>(***FB);

  // Call registered handlers.
  handleMachOs(Hdrs.size() - 1, 0);
}

void DynamicLoader::handleMachOs(size_t HdrOffset, size_t HandlerOffset) {
  // Handle Dylibs in reverse order, so that dependencies are resolved first,
  // before libraries that depend on them.
  vector<const char *> Paths;
  Paths.reserve(Hdrs.size() - HdrOffset);
  vector<const void *> Headers;
  Headers.reserve(Hdrs.size() - HdrOffset);
  for (ptrdiff_t I = Hdrs.size() - 1, End = HdrOffset - 1; I != End; --I) {
    // TODO: Find out paths from `LLs`.
    Paths.push_back(nullptr);
    Headers.push_back(Hdrs[I]);
  }

  for (auto I = Handlers.begin() + HandlerOffset, End = Handlers.end();
       I != End; ++I) {
    MachOHandler &Handler = *I;
    Handler.Mapped(Headers.size(), Paths.data(), Headers.data());
    for (ptrdiff_t I = Hdrs.size() - 1, End = HdrOffset - 1; I != End; --I)
      // TODO: Find out path from `LLs`.
      Handler.Init(nullptr, Hdrs[I]);
  }
}

void DynamicLoader::registerHandler(_dyld_objc_notify_mapped Mapped,
                                    _dyld_objc_notify_init Init,
                                    _dyld_objc_notify_unmapped Unmapped) {
  Handlers.push_back(MachOHandler{Mapped, Init, Unmapped});
  handleMachOs(0, Handlers.size() - 1);
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

  LLs[Path] = move(LL);

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
  LLs[Path] = move(LL);

  // Load it into memory.
  HMODULE Lib = LoadPackagedLibrary(to_hstring(Path).c_str(), 0);
  if (!Lib) {
    Log.error() << "couldn't load DLL: " << Path << Log.appendWinError();
    LLs.erase(Path);
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

AddrInfo DynamicLoader::lookup(uint64_t Addr) {
  for (auto &LI : LLs) {
    LoadedLibrary *LL = LI.second.get();
    if (LL->isInRange(Addr))
      return {&LI.first, LL, string()};
  }
  return {nullptr, nullptr, string()};
}

// TODO: Find symbol name and also use this function to implement
// `src/objc/dladdr.mm`.
AddrInfo DynamicLoader::inspect(uint64_t Addr) { return lookup(Addr); }

DebugStream::Handler DynamicLoader::dumpAddr(uint64_t Addr) {
  return [this, Addr](DebugStream &S) {
    if (Addr == KernelAddr)
      S << "kernel!0x" << to_hex_string(Addr);
    else {
      AddrInfo AI(lookup(Addr));
      S << dumpAddr(Addr, AI);
    }
  };
}

static DebugStream::Handler dumpAddrImpl(uint64_t Addr, const AddrInfo &AI) {
  return [Addr, &AI](DebugStream &S) {
    uint64_t RVA = Addr - AI.Lib->StartAddress;
    S << *AI.LibPath << "+0x" << to_hex_string(RVA);
  };
}

DebugStream::Handler DynamicLoader::dumpAddr(uint64_t Addr,
                                             const AddrInfo &AI) {
  return [this, Addr, &AI](DebugStream &S) {
    if (!AI.Lib) {
      S << "0x" << to_hex_string(Addr);
      return;
    }
    if (AI.Lib->hasMachO())
      if (ObjCMethod M = AI.Lib->getMachO().findMethod(Addr)) {
        S << dumpAddr(Addr, AI, M);
        return;
      }
    S << dumpAddrImpl(Addr, AI);
  };
}

DebugStream::Handler DynamicLoader::dumpAddr(uint64_t Addr, const AddrInfo &AI,
                                             ObjCMethod M) {
  return [Addr, &AI, M](DebugStream &S) {
    S << M << "!" << dumpAddrImpl(Addr, AI);
  };
}
