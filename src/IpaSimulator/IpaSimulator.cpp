#include "IpaSimulator.hpp"

#include <psapi.h> // for `GetModuleInformation`
#include <winrt/Windows.ApplicationModel.h>
#include <winrt/Windows.Storage.h>
#include <winrt/Windows.UI.Popups.h>
#include <winrt/base.h>

#include <filesystem>
#include <map>

using namespace std;
using namespace winrt;
using namespace Windows::ApplicationModel;
using namespace Windows::Storage;
using namespace Windows::UI::Popups;

// Binary operators on enums. Taken from
// <https://stackoverflow.com/a/23152590/9080566>.
template <class T> inline T operator~(T a) { return (T) ~(int)a; }
template <class T> inline T operator|(T a, T b) { return (T)((int)a | (int)b); }
template <class T> inline T operator&(T a, T b) { return (T)((int)a & (int)b); }
template <class T> inline T operator^(T a, T b) { return (T)((int)a ^ (int)b); }
template <class T> inline T &operator|=(T &a, T b) {
  return (T &)((int &)a |= (int)b);
}
template <class T> inline T &operator&=(T &a, T b) {
  return (T &)((int &)a &= (int)b);
}
template <class T> inline T &operator^=(T &a, T b) {
  return (T &)((int &)a ^= (int)b);
}

static const uint8_t *bytes(const void *Ptr) {
  return reinterpret_cast<const uint8_t *>(Ptr);
}
static size_t getDylibSize(const void *Ptr) {
  using namespace LIEF::MachO;

  // Compute lib size by summing `vmsize`s of all `LC_SEGMENT` commands.
  size_t Size = 0;
  auto Header = reinterpret_cast<const mach_header *>(Ptr);
  auto Cmd = reinterpret_cast<const load_command *>(Header + 1);
  for (size_t I = 0; I != Header->ncmds; ++I) {
    if (Cmd->cmd == (uint32_t)LOAD_COMMAND_TYPES::LC_SEGMENT) {
      auto Seg = reinterpret_cast<const segment_command_32 *>(Cmd);
      Size += Seg->vmsize;
    }

    // Move to the next `load_command`.
    Cmd = reinterpret_cast<const load_command *>(bytes(Cmd) + Cmd->cmdsize);
  }
  return Size;
}

void LoadedLibrary::checkInRange(uint64_t Addr) {
  // TODO: Do more flexible error reporting here.
  if (Addr > StartAddress + Size || Addr < StartAddress)
    throw "address out of range";
}

uint64_t LoadedDylib::findSymbol(DynamicLoader &DL, const string &Name) {
  using namespace LIEF::MachO;

  if (!Bin.has_symbol(Name)) {
    // Try also re-exported libraries.
    for (DylibCommand &Lib : Bin.libraries()) {
      if (Lib.command() == LOAD_COMMAND_TYPES::LC_REEXPORT_DYLIB) {
        LoadedLibrary *LL = DL.load(Lib.name());

        // If the target library is DLL, it doesn't have underscore prefixes, so
        // we need to remove it.
        uint64_t SymAddr;
        if (!LL->hasUnderscorePrefix() && Name[0] == '_')
          SymAddr = LL->findSymbol(DL, Name.substr(1));
        else
          SymAddr = LL->findSymbol(DL, Name);

        if (SymAddr)
          return SymAddr;
      }
    }
    return 0;
  }
  return StartAddress + Bin.get_symbol(Name).value();
}

uint64_t LoadedDll::findSymbol(DynamicLoader &DL, const string &Name) {
  return (uint64_t)GetProcAddress(Ptr, Name.c_str());
}

static bool isFileValid(const BinaryPath &BP) {
  if (BP.Relative) {
    return Package::Current()
               .InstalledLocation()
               .TryGetItemAsync(to_hstring(BP.Path))
               .get() != nullptr;
  }
  try {
    StorageFile File =
        StorageFile::GetFileFromPathAsync(to_hstring(BP.Path)).get();
    return true;
  } catch (...) {
    return false;
  }
}

LoadedLibrary *DynamicLoader::load(const string &Path) {
  BinaryPath BP(resolvePath(Path));

  auto I = LIs.find(BP.Path);
  if (I != LIs.end())
    return I->second.get();

  // Check that file exists.
  if (!isFileValid(BP)) {
    error("invalid file: " + BP.Path);
    return nullptr;
  }

  if (LIEF::MachO::is_macho(BP.Path))
    return loadMachO(BP.Path);
  else if (LIEF::PE::is_pe(BP.Path))
    return loadPE(BP.Path);
  else
    error("invalid binary type: " + BP.Path);

  return nullptr;
}

// Reports non-fatal error to the user.
void DynamicLoader::error(const string &Msg, bool AppendLastError) {
  hstring HS(to_hstring("Error occurred: " + Msg));
  if (AppendLastError) {
    hresult_error Err(HRESULT_FROM_WIN32(GetLastError()));
    HS = HS + L"\n" + Err.message();
  }
  MessageDialog Dlg(HS);
  Dlg.ShowAsync();

  // Also output the error to debugging console.
  HS = HS + L"\n";
  OutputDebugStringW(HS.c_str());
}
// Inspired by `ImageLoaderMachO::segmentsCanSlide`.
bool DynamicLoader::canSegmentsSlide(LIEF::MachO::Binary &Bin) {
  using namespace LIEF::MachO;

  auto FType = Bin.header().file_type();
  return FType == FILE_TYPES::MH_DYLIB || FType == FILE_TYPES::MH_BUNDLE ||
         (FType == FILE_TYPES::MH_EXECUTE && Bin.is_pie());
}
void DynamicLoader::mapMemory(uint64_t Addr, uint64_t Size, uc_prot Perms,
                              uint8_t *Mem) {
  if (uc_mem_map_ptr(UC, Addr, Size, Perms, Mem))
    error("error while mapping memory into Unicorn Engine");
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
    error("expected ARM binary");
  // Ensure that segments are continuous (required by `relocateSegment`).
  if (Hdr.has(HEADER_FLAGS::MH_SPLIT_SEGS))
    error("MH_SPLIT_SEGS not supported");
  if (!canSegmentsSlide(Bin))
    error("the binary is not slideable");

  // Compute total size of all segments. Note that in Mach-O, segments must
  // slide together (see `ImageLoaderMachO::segmentsMustSlideTogether`).
  // Inspired by `ImageLoaderMachO::assignSegmentAddresses`.
  uint64_t LowAddr = (uint64_t)(-1);
  uint64_t HighAddr = 0;
  for (SegmentCommand &Seg : Bin.segments()) {
    uint64_t SegLow = Seg.virtual_address();
    // Round to page size (as required by unicorn and what even dyld does).
    uint64_t SegHigh =
        ((SegLow + Seg.virtual_size()) + PageSize - 1) & (-PageSize);
    if ((SegLow < HighAddr && SegLow >= LowAddr) ||
        (SegHigh > LowAddr && SegHigh <= HighAddr)) {
      error("overlapping segments (after rounding to pagesize)");
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
    error("couldn't allocate memory for segments");
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

    uint64_t VAddr = unsigned(Seg.virtual_address()) + Slide;
    // Emulated virtual address is actually equal to the "real" virtual
    // address.
    uint8_t *Mem = (uint8_t *)VAddr;
    uint64_t VSize = Seg.virtual_size();

    if (Perms == UC_PROT_NONE) {
      // No protection means we don't have to copy any data, we just map it.
      mapMemory(VAddr, VSize, Perms, Mem);
    } else {
      // TODO: Memory-map the segment instead of copying it.
      auto &Buff = Seg.content();
      // TODO: Copy to the end of the allocated space if flag `SG_HIGHVM` is
      // present.
      memcpy(Mem, Buff.data(), Buff.size());
      mapMemory(VAddr, VSize, Perms, Mem);

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
          error("unsupported relocation");

        // Find base address for this relocation. Inspired by
        // `ImageLoaderMachOClassic::getRelocBase`.
        uint64_t RelBase = unsigned(LowAddr) + Slide;

        uint64_t RelAddr = RelBase + Rel.address();

        // TODO: Implement what `ImageLoader::containsAddress` does.
        if (RelAddr > VAddr + VSize || RelAddr < VAddr)
          error("relocation target out of range");

        uint32_t *Val = (uint32_t *)RelAddr;
        // We actively leave NULL pointers untouched. Technically it would be
        // correct to slide them because the PAGEZERO segment slid, too. But
        // programs probably wouldn't be happy if their NULLs were non-zero.
        // TODO: Solve this as the original dyld does. Maybe by always mapping
        // PAGEZERO to address 0 or something like that.
        if (*Val != 0)
          *Val = unsigned(*Val) + Slide;
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
      error("unsupported binding info");
      continue;
    }
    if (!BInfo.has_library()) {
      error("flat-namespace symbols are not supported yet");
      continue;
    }

    // Find symbol's library.
    string LibName(BInfo.library().name());
    LoadedLibrary *Lib = load(LibName);
    if (!Lib) {
      error("symbol's library couldn't be loaded");
      continue;
    }

    // Find symbol's address.
    string SymName(BInfo.symbol().name());
    uint64_t SymAddr = Lib->findSymbol(*this, SymName);
    if (!SymAddr) {
      error("external symbol couldn't be resolved");
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
    error("couldn't load DLL: " + Path, /* AppendLastError */ true);
    LIs.erase(Path);
    return nullptr;
  }
  LLP->Ptr = Lib;

  // Find out where it lies in memory.
  if (uint64_t Hdr = LLP->findSymbol(*this, "_mh_dylib_header")) {
    // Map libraries that act as `.dylib`s without their PE headers.
    LLP->StartAddress = Hdr;
    LLP->Size = getDylibSize(reinterpret_cast<const void *>(Hdr));
  } else {
    // Map other libraries in their entirety.
    MODULEINFO Info;
    if (!GetModuleInformation(GetCurrentProcess(), Lib, &Info, sizeof(Info))) {
      error("couldn't load module information", /* AppendLastError */ true);
      return nullptr;
    }
    LLP->StartAddress = (uint64_t)Info.lpBaseOfDll;
    LLP->Size = Info.SizeOfImage;
  }

  return LLP;
}

extern "C" __declspec(dllexport) void start() {
  // Initialize Unicorn Engine.
  uc_engine *UC;
  uc_open(UC_ARCH_ARM, UC_MODE_ARM, &UC); // TODO: Handle errors.

  // Load test binary `ToDo`.
  filesystem::path Dir(Package::Current().InstalledLocation().Path().c_str());
  DynamicLoader Dyld(UC);
  Dyld.load((Dir / "ToDo").string());

  // Let the user know we're done. This is here for testing purposes only.
  MessageDialog Dlg(L"Done.");
  Dlg.ShowAsync();
}
