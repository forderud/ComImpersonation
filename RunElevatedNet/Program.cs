﻿using System;
using System.Runtime.InteropServices;
using NetFwTypeLib;

namespace RunElevatedNet
{
    /** COM Elevation Moniker sample code in C#. */
    class Program
    {
        static int Main(string[] args)
        {
            if (args.Length < 1)
            {
                System.Console.WriteLine("ERROR: COM class-id argument missing");
                return 1;
            }

            // COM class to instantiate
            Type comCls = Type.GetTypeFromProgID(args[0]); // e.g. HNetCfg.FwPolicy2

            System.Console.WriteLine("Creating a non-elevated (regular) COM class instance...");
            object objRegular = Activator.CreateInstance(comCls); // non-elevated
            System.Console.WriteLine("[success]");

            System.Console.WriteLine("Creating an elevated (admin) COM class instance...");
            Guid unknownGuid = Guid.Parse("00000000-0000-0000-C000-000000000046");
            object objElevated = CoCreateInstanceAsAdmin((IntPtr)0, comCls, unknownGuid); // elevated
            System.Console.WriteLine("[success]");

            return 0;
        }


        [StructLayout(LayoutKind.Sequential)]
        struct BIND_OPTS3
        {
            public uint cbStruct;
            uint grfFlags;
            uint grfMode;
            uint dwTickCountDeadline;
            uint dwTrackFlags;
            public uint dwClassContext;
            uint locale;
            object pServerInfo; // will be passing null, so type doesn't matter
            public IntPtr hwnd;
        }

        [DllImport("ole32", CharSet = CharSet.Unicode, ExactSpelling = true, PreserveSig = false)]
        [return: MarshalAs(UnmanagedType.Interface)]
        static extern object CoGetObject(string pszName, [In] ref BIND_OPTS3 pBindOptions, [In] [MarshalAs(UnmanagedType.LPStruct)] Guid riid);


        /** C# port of COM Elevation Moniker sample in https://docs.microsoft.com/en-us/windows/win32/com/the-com-elevation-moniker */
        [return: MarshalAs(UnmanagedType.Interface)]
        static object CoCreateInstanceAsAdmin(IntPtr parentWindow, Type comClass, Guid comInterface)
        {
            // B formatting directive: returns {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} 
            var monikerName = "Elevation:Administrator!new:" + comClass.GUID.ToString("B");

            var bo = new BIND_OPTS3();
            bo.cbStruct = (uint)Marshal.SizeOf(bo);
            bo.hwnd = parentWindow;
            bo.dwClassContext = 4; // CLSCTX_LOCAL_SERVER

            var obj = CoGetObject(monikerName, ref bo, comInterface);
            return obj;
        }
    }
}