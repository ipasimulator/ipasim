//
// Declaration of the MainPage class.
//

#pragma once

#include "MainPage.g.h"

namespace winrt::IpaSimApp::implementation
{
    struct MainPage : MainPageT<MainPage>
    {
        MainPage();

        int32_t MyProperty();
        void MyProperty(int32_t value);
    };
}

namespace winrt::IpaSimApp::factory_implementation
{
    struct MainPage : MainPageT<MainPage, implementation::MainPage>
    {
    };
}
