// IpaSimulator.cpp

#include "ipasim/IpaSimulator.hpp"

#include "ipasim/DynamicLoader.hpp"
#include "ipasim/LoadedLibrary.hpp"

#include <string>

using namespace ipasim;
using namespace std;
using namespace winrt;
using namespace Windows::ApplicationModel::Activation;

// TODO: This Emu-Dyld circular reference is not very cool.
IpaSimulator::IpaSimulator() : Emu(Dyld), Dyld(Emu), Sys(Dyld, Emu) {}

bool ipasim::start(const hstring &Path,
                   const LaunchActivatedEventArgs &LaunchArgs) {
  try {
    // Load the binary.
    IpaSim.MainBinary = to_string(Path);
    LoadedLibrary *App = IpaSim.Dyld.load(IpaSim.MainBinary);
    if (!App)
      return false;

    // Execute it.
    IpaSim.Sys.execute(App);

    // Call `UIApplicationLaunched`. `get_abi` converts C++/WinRT object to its
    // C++/CX equivalent.
    IpaSim.Sys.call("UIKit.dll", "UIApplicationLaunched", get_abi(LaunchArgs));
  } catch (const FatalError &) {
    return false;
  }
  return true;
}
TextBlockProvider &ipasim::logText() { return IpaSim.LogText; }

IpaSimulator ipasim::IpaSim;
Logger<LogStream> ipasim::Log = Logger<LogStream>(
    LogStream(DebugStream(), TextBlockStream(false, IpaSim.LogText)),
    LogStream(DebugStream(), TextBlockStream(true, IpaSim.LogText)));

IPASIM_API void *ipaSim_translate(void *Addr) {
  return IpaSim.Sys.translate(Addr);
}
IPASIM_API void ipaSim_translate4(uint32_t *Addr) {
  Addr[1] = reinterpret_cast<uint32_t>(
      IpaSim.Sys.translate(reinterpret_cast<void *>(Addr[1])));
}
IPASIM_API void *ipaSim_translateC(void *Addr, size_t ArgC) {
  return IpaSim.Sys.translate(Addr, ArgC);
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
IPASIM_API void ipaSim_register(void *Hdr) { IpaSim.Dyld.registerMachO(Hdr); }
IPASIM_API void
_dyld_objc_notify_register(_dyld_objc_notify_mapped Mapped,
                           _dyld_objc_notify_init Init,
                           _dyld_objc_notify_unmapped Unmapped) {
  IpaSim.Dyld.registerHandler(Mapped, Init, Unmapped);
}
