#include <LIEF/LIEF.hpp>
#include <unicorn/unicorn.h>
#include <winrt/Windows.ApplicationModel.h>
#include <winrt/Windows.Storage.h>
#include <winrt/Windows.UI.Popups.h>
#include <winrt/base.h>

#include <filesystem>

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

class DynamicLoader {
public:
  DynamicLoader(uc_engine *uc) : uc(uc) {}
  void load(const string &path) {
    unique_ptr<FatBinary> fat(Parser::parse(path));

    // TODO: Select the correct binary more intelligently.
    Binary &bin = fat->at(0);

    // Check header.
    Header &hdr = bin.header();
    if (hdr.cpu_type() != CPU_TYPES::CPU_TYPE_ARM)
      error("expected ARM binary");
    // Ensure that segments are continuous (required by `relocateSegment`).
    if (hdr.has(HEADER_FLAGS::MH_SPLIT_SEGS))
      error("MH_SPLIT_SEGS not supported");
    if (!canSegmentsSlide(bin))
      error("the binary is not slideable");

    // Compute total size of all segments. Note that in Mach-O, segments must
    // slide together (see `ImageLoaderMachO::segmentsMustSlideTogether`).
    // Inspired by `ImageLoaderMachO::assignSegmentAddresses`.
    uint64_t lowAddr = (uint64_t)(-1);
    uint64_t highAddr = 0;
    for (SegmentCommand &seg : bin.segments()) {
      uint64_t segLow = seg.virtual_address();
      // Round to page size (as required by unicorn and what even dyld does).
      uint64_t segHigh =
          ((segLow + seg.virtual_size()) + pageSize - 1) & (-pageSize);
      if (segLow < highAddr) {
        error("overlapping segments (after rounding to pagesize)");
      }
      if (segLow < lowAddr) {
        lowAddr = segLow;
      }
      if (segHigh > highAddr) {
        highAddr = segHigh;
      }
    }

    // Allocate space for the segments.
    uintptr_t addr = (uintptr_t)_aligned_malloc(highAddr - lowAddr, pageSize);
    if (!addr)
      error("couldn't allocate memory for segments");
    uint64_t slide = addr - lowAddr;

    // Load segments. Inspired by `ImageLoaderMachO::mapSegments`.
    for (SegmentCommand &seg : bin.segments()) {
      // Convert protection.
      uint32_t vmprot = seg.init_protection();
      uc_prot perms = UC_PROT_NONE;
      if (vmprot & (uint32_t)VM_PROTECTIONS::VM_PROT_READ) {
        perms |= UC_PROT_READ;
      }
      if (vmprot & (uint32_t)VM_PROTECTIONS::VM_PROT_WRITE) {
        perms |= UC_PROT_WRITE;
      }
      if (vmprot & (uint32_t)VM_PROTECTIONS::VM_PROT_EXECUTE) {
        perms |= UC_PROT_EXEC;
      }

      uint64_t vaddr = unsigned(seg.virtual_address()) + slide;
      // Emulated virtual address is actually equal to the "real" virtual
      // address.
      uint8_t *mem = (uint8_t *)vaddr;
      uint64_t vsize = seg.virtual_size();

      if (perms == UC_PROT_NONE) {
        // No protection means we don't have to copy any data, we just map it.
        mapMemory(vaddr, vsize, perms, mem);
      } else {
        // TODO: Memory-map the segment instead of copying it.
        auto &buff = seg.content();
        // TODO: Copy to the end of the allocated space if flag `SG_HIGHVM` is
        // present.
        memcpy(mem, buff.data(), buff.size());
        mapMemory(vaddr, vsize, perms, mem);

        // Clear the remaining memory.
        if (buff.size() < vsize)
          memset(mem + buff.size(), 0, vsize - buff.size());
      }
    }
  }

private:
  // Reports non-fatal error to the user.
  void error(const string &msg) {
    MessageDialog dlg(to_hstring("Error occured: " + msg));
    dlg.ShowAsync();
  }
  // Inspired by `ImageLoaderMachO::segmentsCanSlide`.
  bool canSegmentsSlide(Binary &bin) {
    auto ftype = bin.header().file_type();
    return ftype == FILE_TYPES::MH_DYLIB || ftype == FILE_TYPES::MH_BUNDLE ||
           (ftype == FILE_TYPES::MH_EXECUTE && bin.is_pie());
  }
  void mapMemory(uint64_t addr, uint64_t size, uc_prot perms, uint8_t *mem) {
    if (uc_mem_map_ptr(uc, addr, size, perms, mem))
      error("error while mapping memory into Unicorn Engine");
  }

  static constexpr int pageSize = 4096;
  uc_engine *const uc;
};

extern "C" __declspec(dllexport) void start() {
  // Initialize Unicorn Engine.
  uc_engine *uc;
  uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc); // TODO: Handle errors.

  // Load test binary `ToDo`.
  filesystem::path dir(Package::Current().InstalledLocation().Path().c_str());
  DynamicLoader dyld(uc);
  dyld.load((dir / "ToDo").string());

  // Let the user know we're done. This is here for testing purposes only.
  MessageDialog dlg(L"Done.");
  dlg.ShowAsync();
}
