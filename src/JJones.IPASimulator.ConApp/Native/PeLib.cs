using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace JJones.IPASimulator.ConApp.Native
{
    static class PeLib
    {
        [DllImport("Native/PeLib.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr PeLib_openFile([MarshalAs(UnmanagedType.LPStr)] string pcFilename);
        [DllImport("Native/PeLib.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr PeFile_peHeader(IntPtr pef);
        [DllImport("Native/PeLib.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr PeFile_mzHeader(IntPtr pef);
    }
}
