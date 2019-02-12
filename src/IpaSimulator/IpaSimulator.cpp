#include <LIEF/LIEF.hpp>
#include <unicorn/unicorn.h>
#include <winrt/Windows.ApplicationModel.h>
#include <winrt/Windows.Storage.h>
#include <winrt/Windows.UI.Popups.h>
#include <winrt/base.h>

#include <filesystem>
#include <map>

using namespace LIEF::MachO;
using namespace std;
using namespace winrt;
// TODO: Use newer `cppwinrt` and remove this `using namespace`.
using namespace winrt::impl; // For `to_hstring`.
using namespace Windows::ApplicationModel;
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

struct LibraryInfo {
  uint64_t LowAddr, HighAddr;
};

class DynamicLoader {
public:
  DynamicLoader(uc_engine *UC) : UC(UC) {}
  void load(const string &Path) {
    // TODO: Add binary to `LIs`.

    unique_ptr<FatBinary> Fat(Parser::parse(Path));

    // TODO: Select the correct binary more intelligently.
    Binary &Bin = Fat->at(0);

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
    uintptr_t Addr = (uintptr_t)_aligned_malloc(HighAddr - LowAddr, PageSize);
    if (!Addr)
      error("couldn't allocate memory for segments");
    uint64_t Slide = Addr - LowAddr;

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

    // Bind external symbols.
    for (BindingInfo &BInfo : Bin.dyld_info().bindings()) {
      // Check binding's kind.
      if ((BInfo.binding_class() != BINDING_CLASS::BIND_CLASS_STANDARD &&
           BInfo.binding_class() != BINDING_CLASS::BIND_CLASS_LAZY) ||
          BInfo.binding_type() != BIND_TYPES::BIND_TYPE_POINTER ||
          BInfo.addend())
        error("unsupported binding info");

      // Load referenced library.
      DylibCommand &Lib = BInfo.library();
      // TODO: Method `load` is not ready for this yet.
      //load(Lib.name());
    }
  }

private:
  // Reports non-fatal error to the user.
  void error(const string &Msg) {
    MessageDialog Dlg(to_hstring("Error occured: " + Msg));
    Dlg.ShowAsync();
  }
  // Inspired by `ImageLoaderMachO::segmentsCanSlide`.
  bool canSegmentsSlide(Binary &Bin) {
    auto FType = Bin.header().file_type();
    return FType == FILE_TYPES::MH_DYLIB || FType == FILE_TYPES::MH_BUNDLE ||
           (FType == FILE_TYPES::MH_EXECUTE && Bin.is_pie());
  }
  void mapMemory(uint64_t Addr, uint64_t Size, uc_prot Perms, uint8_t *Mem) {
    if (uc_mem_map_ptr(UC, Addr, Size, Perms, Mem))
      error("error while mapping memory into Unicorn Engine");
  }

  static constexpr int PageSize = 4096;
  static constexpr int R_SCATTERED = 0x80000000; // From `<mach-o/reloc.h>`.
  uc_engine *const UC;
  map<string, LibraryInfo> LIs;
};

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
