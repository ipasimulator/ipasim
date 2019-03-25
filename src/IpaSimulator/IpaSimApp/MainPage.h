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

        bool Loaded();
        void Loaded(bool value);

    private:
        bool loaded_;
    };
}

namespace winrt::IpaSimApp::factory_implementation
{
    struct MainPage : MainPageT<MainPage, implementation::MainPage>
    {
    };
}
