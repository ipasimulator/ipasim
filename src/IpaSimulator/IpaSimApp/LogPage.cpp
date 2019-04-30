#include "pch.h"

#include "LogPage.h"
#if __has_include("LogPage.g.cpp")
#include "LogPage.g.cpp"
#endif

#include "ipasim/IpaSimulator.hpp"

using namespace winrt;
using namespace Windows::UI::Xaml;

namespace winrt::IpaSimApp::implementation {

LogPage::LogPage() {
  InitializeComponent();
  ipasim::logText().init(logText());
}

} // namespace winrt::IpaSimApp::implementation
