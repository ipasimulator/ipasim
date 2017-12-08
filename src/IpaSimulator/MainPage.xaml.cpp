//
// MainPage.xaml.cpp
// Implementation of the MainPage class.
//

#include "pch.h"
#include "MainPage.xaml.h"
#include <LIEF/LIEF.hpp>
#include <LIEF/filesystem/filesystem.h>
#include <sstream>

using namespace IpaSimulator;
using namespace Platform;
using namespace Windows::Foundation;
using namespace Windows::Foundation::Collections;
using namespace Windows::Storage;
using namespace Windows::UI::Xaml;
using namespace Windows::UI::Xaml::Controls;
using namespace Windows::UI::Xaml::Controls::Primitives;
using namespace Windows::UI::Xaml::Data;
using namespace Windows::UI::Xaml::Input;
using namespace Windows::UI::Xaml::Media;
using namespace Windows::UI::Xaml::Navigation;
using namespace std;
using namespace LIEF::MachO;

MainPage::MainPage()
{
	InitializeComponent();

    filesystem::path dir(ApplicationData::Current->TemporaryFolder->Path->Data());
    filesystem::path file("todo.ipa");
    filesystem::path full = dir / file;
    FatBinary* bin = Parser::parse(full.str());
    ostringstream str;
    str << bin << endl;
    OutputDebugStringA(str.str().c_str());
    delete bin;
}
