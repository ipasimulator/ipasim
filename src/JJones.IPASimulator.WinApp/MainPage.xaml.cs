using JJones.IPASimulator.Model.IO;
using JJones.IPASimulator.Model.MachO;
using JJones.IPASimulator.Model.MachO.Commands;
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
using UnicornManaged;
using UnicornManaged.Const;
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
                    using (var rdr = new MachOReader(new SeekableStream(new CountingStream(str))))
                    {
                        if (!rdr.TryReadHeader())
                        {
                            return;
                        }

                        // Finds the correct arch:
                        for (var i = 0; i < rdr.NFatArch; i++)
                        {
                            var arch = rdr.ReadFatArch();
                            if (arch.CpuType == CpuType.ARM && arch.CpuSubtype == (uint)CpuArmSubtype.v7)
                            {
                                rdr.SeekArch(arch);
                                break;
                            }
                        }

                        if (!rdr.TryReadMachHeader())
                        {
                            return;
                        }

                        for (var i = 0; i < rdr.MachHeader.NCmds; i++)
                        {
                            var lcmd = rdr.ReadLoadCommand();
                            switch (lcmd.Type)
                            {
                                case LoadCommandType.Segment:
                                    {
                                        var cmd = rdr.ReadSegmentCommand(lcmd);
                                        for (var j = 0; j < cmd.NSects; j++)
                                        {
                                            var sect = rdr.ReadSection();
                                        }
                                        break;
                                    }
                                case LoadCommandType.DyldInfo:
                                case LoadCommandType.DyldInfoOnly:
                                    {
                                        var cmd = rdr.ReadDyldInfoComand(lcmd);
                                        break;
                                    }
                                case LoadCommandType.Symtab:
                                    {
                                        var cmd = rdr.ReadSymtabCommand(lcmd);
                                        break;
                                    }
                                case LoadCommandType.DySymtab:
                                    {
                                        var cmd = rdr.ReadDySymtabCommand(lcmd);
                                        break;
                                    }
                                case LoadCommandType.LoadDyLinker:
                                    {
                                        var cmd = rdr.ReadDyLinkerCommand(lcmd);
                                        break;
                                    }
                                default:
                                    {
                                        rdr.SkipCommand(lcmd);
                                        break;
                                    }
                            }
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
        private void unicornButton_Click(object sender, RoutedEventArgs e)
        {
            var uni = new Unicorn(Common.UC_ARCH_ARM, Common.UC_MODE_ARM);

        }
    }
}
