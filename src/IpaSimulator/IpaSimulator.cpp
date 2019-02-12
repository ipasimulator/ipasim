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

    // TODO: Actually load the binary into memory.
  }
};

__declspec(dllexport) void main() {
  // Initialize Unicorn Engine.
  uc_engine *uc;
  uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc); // TODO: Handle errors.

  // Load test binary `ToDo`.
  filesystem::path dir(Package::Current().InstalledLocation().Path().c_str());
  DynamicLoader dyld;
  dyld.load((dir / "ToDo").string());
}
