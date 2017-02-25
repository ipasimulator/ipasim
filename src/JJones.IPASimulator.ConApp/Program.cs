using ELFSharp.MachO;
using JJones.IPASimulator.ConApp.Native;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JJones.IPASimulator.ConApp
{
    class Program
    {
        static void Main(string[] args)
        {
            var file = PeLib.PeLib_openFile("output.exe");
            var mzHeader = PeLib.PeFile_mzHeader(file);
            var peHeader = PeLib.PeFile_peHeader(file);
        }
    }
}
