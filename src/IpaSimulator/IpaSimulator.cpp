#include <LIEF/LIEF.hpp>
#include <unicorn/unicorn.h>
#include <winrt/Windows.ApplicationModel.h>
#include <winrt/Windows.Storage.h>

#include <filesystem>

using namespace LIEF::MachO;
using namespace std;
using namespace winrt;
using namespace Windows::ApplicationModel;

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
    // We slide the binary, that's why this is required.
    if (hdr.file_type() == FILE_TYPES::MH_EXECUTE &&
        !hdr.has(HEADER_FLAGS::MH_PIE))
      error("executables must be position-independent");

    // TODO: Actually load the binary into memory.
  }

private:
  void error(const string &msg) {
    // TODO: Report it.
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
}
