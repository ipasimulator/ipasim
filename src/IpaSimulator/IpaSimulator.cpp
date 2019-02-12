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

class DynamicLoader {
public:
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
    uint64_t lowAddr = (uint64_t)(-1);
    uint64_t highAddr = 0;
    for (SegmentCommand &seg : bin.segments()) {
      uint64_t segLow = seg.virtual_address();
      // Round to page size (as required by unicorn and what even dyld does).
      uint64_t segHigh = ((segLow + seg.virtual_size()) + 4095) & (-4096);
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

    // TODO: Actually load the binary into memory.
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
};

extern "C" __declspec(dllexport) void start() {
  // Initialize Unicorn Engine.
  uc_engine *uc;
  uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc); // TODO: Handle errors.

  // Load test binary `ToDo`.
  filesystem::path dir(Package::Current().InstalledLocation().Path().c_str());
  DynamicLoader dyld;
  dyld.load((dir / "ToDo").string());

  // Let the user know we're done. This is here for testing purposes only.
  MessageDialog dlg(L"Done.");
  dlg.ShowAsync();
}
