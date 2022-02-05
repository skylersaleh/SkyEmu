/*_________
 /         \ tinyfiledialogsTest.cs v3.8.3 [Nov 1, 2020] zlib licence
 |tiny file| C# bindings created [2015]
 | dialogs | Copyright (c) 2014 - 2020 Guillaume Vareille http://ysengrin.com
 \____  ___/ http://tinyfiledialogs.sourceforge.net
      \|     git clone http://git.code.sf.net/p/tinyfiledialogs/code tinyfd
         ____________________________________________
	    |                                            |
	    |   email: tinyfiledialogs at ysengrin.com   |
	    |____________________________________________|

If you like tinyfiledialogs, please upvote my stackoverflow answer
https://stackoverflow.com/a/47651444

- License -
 This software is provided 'as-is', without any express or implied
 warranty.  In no event will the authors be held liable for any damages
 arising from the use of this software.
 Permission is granted to anyone to use this software for any purpose,
 including commercial applications, and to alter it and redistribute it
 freely, subject to the following restrictions:
 1. The origin of this software must not be misrepresented; you must not
 claim that you wrote the original software.  If you use this software
 in a product, an acknowledgment in the product documentation would be
 appreciated but is not required.
 2. Altered source versions must be plainly marked as such, and must not be
 misrepresented as being the original software.
 3. This notice may not be removed or altered from any source distribution.
*/

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

class tinyfd
{
    public const string mDllLocation = "C:\\Users\\frogs\\yomspace2015\\yomlibs\\tinyfd\\extras_dll_cs_lua_fortran\\tinyfiledialogs32.dll";

    [DllImport(mDllLocation, CallingConvention = CallingConvention.Cdecl)] public static extern void tinyfd_beep();

    // cross platform UTF8
    [DllImport(mDllLocation, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern int tinyfd_notifyPopup(string aTitle, string aMessage, string aIconType);
    [DllImport(mDllLocation, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern int tinyfd_messageBox(string aTitle, string aMessage, string aDialogTyle, string aIconType, int aDefaultButton);
    [DllImport(mDllLocation, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr tinyfd_inputBox(string aTitle, string aMessage, string aDefaultInput);
    [DllImport(mDllLocation, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr tinyfd_saveFileDialog(string aTitle, string aDefaultPathAndFile, int aNumOfFilterPatterns, string[] aFilterPatterns, string aSingleFilterDescription);
    [DllImport(mDllLocation, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr tinyfd_openFileDialog(string aTitle, string aDefaultPathAndFile, int aNumOfFilterPatterns, string[] aFilterPatterns, string aSingleFilterDescription, int aAllowMultipleSelects);
    [DllImport(mDllLocation, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr tinyfd_selectFolderDialog(string aTitle, string aDefaultPathAndFile);
    [DllImport(mDllLocation, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr tinyfd_colorChooser(string aTitle, string aDefaultHexRGB, byte[] aDefaultRGB, byte[] aoResultRGB);

    // windows only utf16
    [DllImport(mDllLocation, CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern int tinyfd_notifyPopupW(string aTitle, string aMessage, string aIconType);
    [DllImport(mDllLocation, CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern int tinyfd_messageBoxW(string aTitle, string aMessage, string aDialogTyle, string aIconType, int aDefaultButton);
    [DllImport(mDllLocation, CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr tinyfd_inputBoxW(string aTitle, string aMessage, string aDefaultInput);
    [DllImport(mDllLocation, CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr tinyfd_saveFileDialogW(string aTitle, string aDefaultPathAndFile, int aNumOfFilterPatterns, string[] aFilterPatterns, string aSingleFilterDescription);
    [DllImport(mDllLocation, CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr tinyfd_openFileDialogW(string aTitle, string aDefaultPathAndFile, int aNumOfFilterPatterns, string[] aFilterPatterns, string aSingleFilterDescription, int aAllowMultipleSelects);
    [DllImport(mDllLocation, CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr tinyfd_selectFolderDialogW(string aTitle, string aDefaultPathAndFile);
    [DllImport(mDllLocation, CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr tinyfd_colorChooserW(string aTitle, string aDefaultHexRGB, byte[] aDefaultRGB, byte[] aoResultRGB);

    // cross platform
    [DllImport(mDllLocation, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr tinyfd_getGlobalChar(string aCharVariableName);
    [DllImport(mDllLocation, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern int tinyfd_getGlobalInt(string aIntVariableName);
    [DllImport(mDllLocation, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern int tinyfd_setGlobalInt(string aIntVariableName, int aValue);

    // ******** a complicated way to access tinyfd's global variables
    // [DllImport("kernel32.dll", SetLastError = true)] internal static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    // [DllImport("kernel32.dll", SetLastError = true)] internal static extern IntPtr LoadLibrary(string lpszLib);
}

namespace ConsoleApplication1
{
    class tinyfiledialogsTest
    {
        private static string stringFromAnsi(IntPtr ptr) // for UTF-8/char
        {
            return System.Runtime.InteropServices.Marshal.PtrToStringAnsi(ptr);
        }

        private static string stringFromUni(IntPtr ptr) // for UTF-16/wchar_t
        {
            return System.Runtime.InteropServices.Marshal.PtrToStringUni(ptr);
        }

        static void Main(string[] args)
        {
            // ******** a simple way to access tinyfd's global variables
            IntPtr lTheVersionText = tinyfd.tinyfd_getGlobalChar("tinyfd_version");
            string lTheVersionString = stringFromAnsi(lTheVersionText);
            tinyfd.tinyfd_messageBox("tinyfd_version", lTheVersionString, "ok", "info", 1);

            // cross platform utf-8
            IntPtr lTheInputText = tinyfd.tinyfd_inputBox("input box", "gimme a string", "A text to input");
            string lTheInputString = stringFromAnsi(lTheInputText);
            int lala = tinyfd.tinyfd_messageBox("a message box char", lTheInputString, "ok", "warning", 1);

            // windows only utf-16
            IntPtr lAnotherInputTextW = tinyfd.tinyfd_inputBoxW("input box", "gimme another string", "Another text to input");
            string lAnotherInputString = stringFromUni(lAnotherInputTextW);
            int lili = tinyfd.tinyfd_messageBoxW("a message box wchar_t", lAnotherInputString, "ok", "info", 1);

            tinyfd.tinyfd_notifyPopupW("there is no warning (even if it is a warning icon)", lTheVersionString, "warning");

            tinyfd.tinyfd_beep();

            // ******** a complicated way to access tinyfd's global variables (uncomment the 2 lines in the class tinyfd above)
            // IntPtr tinyfd_DLL = tinyfd.LoadLibrary(tinyfd.mDllLocation);
            // if (tinyfd_DLL != IntPtr.Zero)
            // {
            //    IntPtr lVersionAddr = tinyfd.GetProcAddress(tinyfd_DLL, "tinyfd_version");
            //    string lVersion = stringFromAnsi(lVersionAddr);
            //    IntPtr lForceConsoleAddr = tinyfd.GetProcAddress(tinyfd_DLL, "tinyfd_forceConsole");
            //    if (lForceConsoleAddr != IntPtr.Zero)
            //    {
            //        int lForceConsoleValue = Marshal.ReadInt32(lForceConsoleAddr);
            //        tinyfd.tinyfd_notifyPopup(lVersion, lForceConsoleValue.ToString(), "info");
            //        Marshal.WriteInt32(lForceConsoleAddr, 0);
            //    }
            // }
        }
    }
}
