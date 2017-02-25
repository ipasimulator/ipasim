using MiscUtil.Conversion;
using MiscUtil.IO;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text.RegularExpressions;
using Windows.ApplicationModel;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.Storage;
using Windows.Storage.Pickers;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Navigation;

namespace JJones.IPASimulator.WinApp
{
    public sealed partial class MainPage : Page
    {
        public MainPage()
        {
            InitializeComponent();
        }

        private async void loadIPAButton_Click(object sender, RoutedEventArgs e)
        {
            var picker = new FileOpenPicker();
            picker.FileTypeFilter.Add(".ipa");
            picker.FileTypeFilter.Add(".zip");
            picker.SuggestedStartLocation = PickerLocationId.Downloads;
            picker.ViewMode = PickerViewMode.List;
            var file = await picker.PickSingleFileAsync();
            if (file != null)
            {
                var folder = await ApplicationData.Current.LocalCacheFolder.CreateFolderAsync("IPAs", CreationCollisionOption.OpenIfExists);
                file = await file.CopyAsync(folder, "Application.ipa", NameCollisionOption.ReplaceExisting);

                using (var archive = ZipFile.OpenRead(file.Path))
                {
                    var appRegex = new Regex(@"Payload/([^/]+)\.app/\1", RegexOptions.IgnoreCase);
                    var appEntry = archive.Entries.FirstOrDefault(z => appRegex.IsMatch(z.FullName));
                    using (var str = appEntry.Open())
                    using (var rdr = new EndianBinaryReader(EndianBitConverter.Big, str))
                    {
                        var magic = rdr.ReadUInt32();
                        if (magic == 0xCAFEBABE)
                        {
                            var nfat_arch = rdr.ReadUInt32();

                        }
                    }
                }
            }
        }
        private async void loadDllButton_Click(object sender, RoutedEventArgs e)
        {
            var picker = new FileOpenPicker();
            picker.FileTypeFilter.Add(".dll");
            picker.SuggestedStartLocation = PickerLocationId.Downloads;
            picker.ViewMode = PickerViewMode.List;
            var file = await picker.PickSingleFileAsync();
            if (file != null)
            {
                var folder = await ApplicationData.Current.LocalCacheFolder.CreateFolderAsync("DLLs", CreationCollisionOption.OpenIfExists);
                file = await file.CopyAsync(folder, "Application.dll", NameCollisionOption.ReplaceExisting);
            }
        }
    }
}
