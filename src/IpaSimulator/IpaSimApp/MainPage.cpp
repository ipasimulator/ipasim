#include "pch.h"
#include "MainPage.h"

using namespace winrt;
using namespace Windows::UI::Xaml;

namespace winrt::IpaSimApp::implementation
{
    MainPage::MainPage()
    {
        InitializeComponent();
    }

    int32_t MainPage::MyProperty()
    {
        throw hresult_not_implemented();
    }

    void MainPage::MyProperty(int32_t /* value */)
    {
        throw hresult_not_implemented();
    }
}
