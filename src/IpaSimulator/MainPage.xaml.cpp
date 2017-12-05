//
// MainPage.xaml.cpp
// Implementation of the MainPage class.
//

#include "pch.h"
#include "MainPage.xaml.h"
#include <LIEF/LIEF.hpp>

using namespace IpaSimulator;

using namespace Platform;
using namespace Windows::Foundation;
using namespace Windows::Foundation::Collections;
using namespace Windows::UI::Xaml;
using namespace Windows::UI::Xaml::Controls;
using namespace Windows::UI::Xaml::Controls::Primitives;
using namespace Windows::UI::Xaml::Data;
using namespace Windows::UI::Xaml::Input;
using namespace Windows::UI::Xaml::Media;
using namespace Windows::UI::Xaml::Navigation;
using namespace std;

MainPage::MainPage()
{
    InitializeComponent();

    LIEF::MachO::FatBinary* bin = LIEF::MachO::Parser::parse("test.ipa");
    cout << *bin << endl;
    delete bin;
}
