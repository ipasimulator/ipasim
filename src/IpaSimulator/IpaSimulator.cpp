// IpaSimulator.cpp

#include "ipasim/IpaSimulator.hpp"

#include "ipasim/DynamicLoader.hpp"
#include "ipasim/LoadedLibrary.hpp"

#include <string>
#include <winrt/Windows.ApplicationModel.Activation.h>

using namespace ipasim;
using namespace std;
using namespace winrt;
using namespace Windows::ApplicationModel::Activation;

// TODO: This Emu-Dyld circular reference is not very cool.
IpaSimulator::IpaSimulator() : Emu(Dyld), Dyld(Emu), Sys(Dyld, Emu) {}

IpaSimulator ipasim::IpaSim;
DebugLogger ipasim::Log;

#define IPASIM_API extern "C" __declspec(dllexport)

IPASIM_API void ipaSim_start(const hstring &Path,
                             const LaunchActivatedEventArgs &LaunchArgs) {
  // Load the binary.
  IpaSim.MainBinary = to_string(Path);
  LoadedLibrary *App = IpaSim.Dyld.load(IpaSim.MainBinary);
  if (!App)
    return;

  // Execute it.
  IpaSim.Sys.execute(App);

  // Call `UIApplicationLaunched`.
  LoadedLibrary *UIKit = IpaSim.Dyld.load("UIKit.dll");
  uint64_t LaunchAddr = UIKit->findSymbol(IpaSim.Dyld, "UIApplicationLaunched");
  auto *LaunchFunc = reinterpret_cast<void (*)(void *)>(LaunchAddr);
  // `get_abi` converts C++/WinRT object to its C++/CX equivalent.
  LaunchFunc(get_abi(LaunchArgs));
}
IPASIM_API void *ipaSim_translate(void *Addr) {
  return IpaSim.Sys.translate(Addr);
}
IPASIM_API void ipaSim_translate4(uint32_t *Addr) {
  Addr[1] = reinterpret_cast<uint32_t>(
      IpaSim.Sys.translate(reinterpret_cast<void *>(Addr[1])));
}
IPASIM_API const char *ipaSim_processPath() {
  return IpaSim.MainBinary.c_str();
}
IPASIM_API void ipaSim_callBack1(void *FP, void *Arg0) {
  IpaSim.Sys.callBack(FP, Arg0);
}
IPASIM_API void ipaSim_callBack2(void *FP, void *Arg0, void *Arg1) {
  IpaSim.Sys.callBack(FP, Arg0, Arg1);
}
IPASIM_API void *ipaSim_callBack1r(void *FP, void *Arg0) {
  return IpaSim.Sys.callBackR(FP, Arg0);
}
IPASIM_API void *ipaSim_callBack3r(void *FP, void *Arg0, void *Arg1,
                                   void *Arg2) {
  return IpaSim.Sys.callBackR(FP, Arg0, Arg1, Arg2);
}
