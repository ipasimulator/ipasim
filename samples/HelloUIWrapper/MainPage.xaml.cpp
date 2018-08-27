//
// MainPage.xaml.cpp
// Implementation of the MainPage class.
//

#include "pch.h"
#include "MainPage.xaml.h"

using namespace HelloUIWrapper;

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

// The Blank Page item template is documented at https://go.microsoft.com/fwlink/?LinkId=402352&clcid=0x409

MainPage::MainPage()
{
	InitializeComponent();

    // Let's try to load `HelloUI.exe`.
    HMODULE lib = LoadPackagedLibrary(L"HelloUI.exe", 0);
    if (lib) {
        OutputDebugStringA("Success!");
        FreeLibrary(lib);
    }
    else {
        OutputDebugStringA((string("Error: ") + to_string(GetLastError())).c_str());
    }
}
