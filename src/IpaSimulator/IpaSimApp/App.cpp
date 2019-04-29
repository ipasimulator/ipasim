//
// App.xaml.cpp
// Implementation of the App class.
//

#include "pch.h"

#include "App.h"
#include "MainPage.h"

using namespace std;
using namespace winrt;
using namespace Windows::ApplicationModel;
using namespace Windows::ApplicationModel::Activation;
using namespace Windows::ApplicationModel::Core;
using namespace Windows::Foundation;
using namespace Windows::Storage;
using namespace Windows::Storage::AccessCache;
using namespace Windows::Storage::Pickers;
using namespace Windows::UI::Core;
using namespace Windows::UI::Popups;
using namespace Windows::UI::ViewManagement;
using namespace Windows::UI::Xaml;
using namespace Windows::UI::Xaml::Controls;
using namespace Windows::UI::Xaml::Navigation;
using namespace IpaSimApp;
using namespace IpaSimApp::implementation;

/// <summary>
/// Initializes the singleton application object.  This is the first line of
/// authored code executed, and as such is the logical equivalent of main() or
/// WinMain().
/// </summary>
App::App() {
  InitializeComponent();
  Suspending({this, &App::OnSuspending});

#if defined _DEBUG &&                                                          \
    !defined DISABLE_XAML_GENERATED_BREAK_ON_UNHANDLED_EXCEPTION
  UnhandledException(
      [this](IInspectable const &, UnhandledExceptionEventArgs const &e) {
        if (IsDebuggerPresent()) {
          auto errorMessage = e.Message();
          __debugbreak();
        }
      });
#endif
}

static bool endsWith(const std::string &S, const std::string &Suffix) {
  return !S.compare(S.length() - Suffix.length(), Suffix.length(), Suffix);
}

static IAsyncOperation<StorageFolder> copyFolder(StorageFolder Source,
                                                 StorageFolder Target) {
  StorageFolder Dest = co_await Target.CreateFolderAsync(
      Source.Name(), CreationCollisionOption::ReplaceExisting);
  for (StorageFile File : co_await Source.GetFilesAsync())
    co_await File.CopyAsync(Dest, File.Name(),
                            NameCollisionOption::ReplaceExisting);
  for (StorageFolder Folder : co_await Source.GetFoldersAsync())
    co_await copyFolder(Folder, Dest);
  co_return Dest;
}

// TODO: Move these into `IpaSimLibrary` when possible.
static IAsyncAction startCore(LaunchActivatedEventArgs LaunchArgs) {
  // Ask user for folder containing the binary.
  FolderPicker FP;
  FP.FileTypeFilter().Append(L"*");
  StorageFolder Folder(co_await FP.PickSingleFolderAsync());
  if (!Folder) {
    OutputDebugStringA("Error: no folder selected.");
    co_return;
  }
  // TODO: This is not used right now.
  StorageApplicationPermissions::FutureAccessList().AddOrReplace(
      L"PickedFolderToken", Folder);

  // Find binary in the folder.
  string FolderName(to_string(Folder.Name()));
  if (!endsWith(FolderName, ".app")) {
    OutputDebugStringA("Error: wrong folder selected.");
    co_return;
  }
  string BinaryName(FolderName.substr(0, FolderName.length() - 4));
  IStorageItem Bin(co_await Folder.TryGetItemAsync(to_hstring(BinaryName)));
  if (!Bin) {
    OutputDebugStringA("Error: cannot find binary.");
    co_return;
  }

  // Copy the folder into app's data.
  // TODO: Without this, files inside the folder cannot be opened by standard
  // C++ means (e.g., `fstream`). But maybe we could workaround that.
  // TODO: Delete old files first.
  Folder = co_await copyFolder(Folder,
                               ApplicationData::Current().LocalCacheFolder());
  Bin = co_await Folder.GetFileAsync(Bin.Name());

  // Execute the main logic which is stored inside `IpaSimLibrary`.
  // TODO: Link this instead of loading it dynamically.
  HMODULE lib = check_pointer(LoadPackagedLibrary(L"libIpaSimLibrary.dll", 0));
  FARPROC startFunc = check_pointer(GetProcAddress(lib, "ipaSim_start"));
  bool Result =
      ((bool (*)(const hstring &, const LaunchActivatedEventArgs &))startFunc)(
          Bin.Path(), LaunchArgs);
  check_bool(FreeLibrary(lib));

  // Change status from "Loading..." to "Done.".
  if (auto F = Window::Current().Content().try_as<Frame>())
    if (auto Page = F.Content().try_as<IpaSimApp::MainPage>())
      Page.Loaded(true);

  if (!Result) {
    MessageDialog MD(L"A fatal error occured.");
    co_await MD.ShowAsync();
  }
}
static IAsyncAction start(LaunchActivatedEventArgs LaunchArgs) {
  // Only start the emulation if it hasn't already been started, i.e., no
  // secondary view was created.
  auto Views = CoreApplication::Views();
  if (Views.Size() == 2)
    return;

  CoreDispatcher MainDispatcher =
      CoreApplication::GetCurrentView().Dispatcher();

  // Create a new window.
  CoreApplicationView View = CoreApplication::CreateNewView();
  co_await resume_foreground(View.Dispatcher());

  // Show the "Loading..." screen.
  Frame F;
  F.Navigate(xaml_typename<IpaSimApp::MainPage>(), nullptr);
  Window::Current().Content(F);
  Window::Current().Activate();

  int32_t ViewId = ApplicationView::GetForCurrentView().Id();

  // Activate the new window.
  co_await resume_foreground(MainDispatcher);
  if (!co_await ApplicationViewSwitcher::TryShowAsStandaloneAsync(ViewId)) {
    // TODO: Log an error.
    return;
  }

  co_await startCore(LaunchArgs);
}

/// <summary>
/// Invoked when the application is launched normally by the end user.  Other
/// entry points will be used such as when the application is launched to open a
/// specific file.
/// </summary>
/// <param name="e">Details about the launch request and process.</param>
void App::OnLaunched(LaunchActivatedEventArgs const &e) {
  Frame rootFrame{nullptr};
  auto content = Window::Current().Content();
  if (content) {
    rootFrame = content.try_as<Frame>();
  }

  // Do not repeat app initialization when the Window already has content,
  // just ensure that the window is active
  if (rootFrame == nullptr) {
    // Create a Frame to act as the navigation context and associate it with
    // a SuspensionManager key
    rootFrame = Frame();

    rootFrame.NavigationFailed({this, &App::OnNavigationFailed});

    if (e.PreviousExecutionState() == ApplicationExecutionState::Terminated) {
      // Restore the saved session state only when appropriate, scheduling the
      // final launch steps after the restore is complete
    }

    if (e.PrelaunchActivated() == false) {
      if (rootFrame.Content() == nullptr) {
        // When the navigation stack isn't restored navigate to the first page,
        // configuring the new page by passing required information as a
        // navigation parameter
        rootFrame.Navigate(xaml_typename<IpaSimApp::MainPage>(),
                           box_value(e.Arguments()));
      }
      // Place the frame in the current Window
      Window::Current().Content(rootFrame);
      // Ensure the current window is active
      Window::Current().Activate();
    }
  } else {
    if (e.PrelaunchActivated() == false) {
      if (rootFrame.Content() == nullptr) {
        // When the navigation stack isn't restored navigate to the first page,
        // configuring the new page by passing required information as a
        // navigation parameter
        rootFrame.Navigate(xaml_typename<IpaSimApp::MainPage>(),
                           box_value(e.Arguments()));
      }
      // Ensure the current window is active
      Window::Current().Activate();
    }
  }

  start(e);
}

/// <summary>
/// Invoked when application execution is being suspended.  Application state is
/// saved without knowing whether the application will be terminated or resumed
/// with the contents of memory still intact.
/// </summary>
/// <param name="sender">The source of the suspend request.</param>
/// <param name="e">Details about the suspend request.</param>
void App::OnSuspending([[maybe_unused]] IInspectable const &sender,
                       [[maybe_unused]] SuspendingEventArgs const &e) {
  // Save application state and stop any background activity
}

/// <summary>
/// Invoked when Navigation to a certain page fails
/// </summary>
/// <param name="sender">The Frame which failed navigation</param>
/// <param name="e">Details about the navigation failure</param>
void App::OnNavigationFailed(IInspectable const &,
                             NavigationFailedEventArgs const &e) {
  throw hresult_error(E_FAIL, hstring(L"Failed to load Page ") +
                                  e.SourcePageType().Name);
}
