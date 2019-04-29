#include "pch.h"

#include "MainPage.h"

using namespace winrt;
using namespace Windows::UI::Xaml;

namespace winrt::IpaSimApp::implementation {

MainPage::MainPage() : loaded_(false) { InitializeComponent(); }

bool MainPage::Loaded() { return loaded_; }

void MainPage::Loaded(bool value) {
  loaded_ = value;
  if (value)
    statusText().Text(L"Done.");
  else
    statusText().Text(L"Loading...");
}

} // namespace winrt::IpaSimApp::implementation
