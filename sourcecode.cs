// Copyright 2024 @x-coconut
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System.Security.Principal;
using System.Diagnostics;
using System.Management; // dotnet add package System.Management
using System.Runtime.InteropServices;
using System.Net;
using System.Net.NetworkInformation;
using Microsoft.Win32.TaskScheduler; // dotnet add package TaskScheduler
using Microsoft.Win32;
using System.ServiceProcess; // dotnet add package System.ServiceProcess.ServiceController
using CredentialManagement; // dotnet add package CredentialManagement
using System.Security.AccessControl;

class buildReview
{
    // queries the registry
    static void HKLM_Reg_Query(string path, string name)
    {
        try
        {   // queries HKLM
            using (RegistryKey? key = Registry.LocalMachine.OpenSubKey(path))
            {
                if (key != null)
                {
                    object? value = key.GetValue(name);
                    if (value != null)
                    {
                        // if multiple values are held in that reg key
                        if (value is string[])
                        {
                            string[] valueArray = (string[])value;
                            Console.WriteLine($"{name} is Set to: (Path: {path})");
                            foreach (string item in valueArray)
                            {
                                Console.WriteLine($"  - {item}");
                            }
                        }
                        else
                        {
                            Console.WriteLine($"{name} is Set to: {value} (Path: {path})");
                        }

                    }
                    else
                    {
                        Console.WriteLine($"{name} Does Not Exist or Has no Value (Path: {path})");
                    }
                }
                else
                {
                    Console.WriteLine($"Registry Path Does Not Exist (Path: {path})");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error Accessing Registry: {ex.Message}\n (Name: {name}, Path: {path})");
        }
    }

    // run processes
    static string? Run_Process(string command, string arguments)
    {
        try
        {
            // Create new process - needed to execute external commands
            Process process = new Process();

            process.StartInfo.FileName = command; //command to run
            process.StartInfo.Arguments = arguments; // more of the command to run
            process.StartInfo.RedirectStandardOutput = true; // captures output from command
            process.StartInfo.UseShellExecute = false; // allow output to be redirected
            process.StartInfo.CreateNoWindow = true; // run process without a new window

            // Start the process
            process.Start();

            // Read the output
            string output = process.StandardOutput.ReadToEnd();

            // Wait for the process to exit - so can check exit code
            process.WaitForExit();

            if (process.ExitCode == 0)
            {
                return output;
            }
            else
            {
                return null;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error Creating Process: {ex.Message}");
            return null;
        }

    }

    // retrieves the value of a setting in the secedit report
    static string? Get_Value_From_Secedit(string linePrefix, string tempFilePath)
    {
        try
        {
            // Check if the file exists
            if (File.Exists(tempFilePath))
            {

                // Read the file line by line
                string[] lines = File.ReadAllLines(tempFilePath);

                // Search for the line that starts with the given prefix
                foreach (string line in lines)
                {
                    if (line.StartsWith(linePrefix, StringComparison.OrdinalIgnoreCase))
                    {
                        // Find the position of = in the line
                        int equalsIndex = line.IndexOf('=');
                        if (equalsIndex != -1 && equalsIndex < line.Length - 1)
                        {
                            // Return the part of the line after the =
                            return line.Substring(equalsIndex + 1).Trim();
                        }
                    }
                }
                Console.WriteLine($"Setting Not Found: {linePrefix}");
                return null;

            }
            else
            {
                Console.WriteLine("Secedit Report Not Found");
                return null;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error Reading Secedit Report " + ex.Message);
            return null;
        }
    }

    // checks if current user is admin
    static bool Admin()
    {
        try
        {
            // get current user
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            // check if in administrators group
            if (principal.IsInRole(WindowsBuiltInRole.Administrator))
            {
                Console.WriteLine("You Have Administrator Privileges\n");
                return true;
            }
            else
            {
                Console.WriteLine("You Are Not an Administrator, Some Checks Will Fail\n");
                return false;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error Checking if Administrator: {ex.Message}");
            return false;
        }

    }

    // generates a report using secedit  - saves in a temporary file
    static string Generate_Secedit_Report()
    {
        try
        {
            // get temp file path
            string tempFilePath = Path.GetTempFileName();
            // generate secedit report
            string? result = Run_Process("secedit.exe", $"/export /cfg \"{tempFilePath}\"");
            return tempFilePath;
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error Creating Secedit Report: " + ex.Message);
            return "error";
        }
    }

    // lists missing updates/patches
    static void Missing_Updates()
    {
        // check missing patches/updates
        string script = @"
                        $UpdateSession = New-Object -ComObject Microsoft.Update.Session 
                        $UpdateSearcher = $UpdateSession.CreateUpdateSearcher() 
                        $Updates = @($UpdateSearcher.Search('IsHidden=0 and IsInstalled=0').Updates) 
                        $Updates | Select-Object Title
                        ";
        Console.WriteLine("Missing Updates:\n");

        string? missing_updates = Run_Process("powershell.exe", $"-NoProfile -ExecutionPolicy Bypass -Command \"{script}\"");

        if (missing_updates != null)
        {
            // Split the output by '\n' to get each line of updates
            var updates = missing_updates.Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
            int count = 0;
            foreach (var update in updates.Skip(3))
            {
                Console.WriteLine(update.Trim());
                count += 1;
            }
            Console.WriteLine();
            if (count == 0)
            {
                Console.WriteLine("No Updates Found\n");
            }
        }
        else
        {
            Console.WriteLine("Error Checking Missing Updates\n");
        }
    }

    // lists installed programs
    static void Installed_Programs()
    {
        Console.WriteLine("Installed Programs:\n");

        try
        {
            // query WMI
            ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT Name, Version, Vendor FROM Win32_Product");
            ManagementObjectCollection products = searcher.Get();

            // display column names
            Console.WriteLine("{0,-65} {1,-20} {2,-30}", "Name", "Version", "Vendor");
            Console.WriteLine();

            // display each program
            foreach (ManagementObject product in products)
            {
                string? name = product["Name"].ToString();
                string? version = product["Version"].ToString();
                string? vendor = product["Vendor"].ToString();

                Console.WriteLine("{0,-65} {1,-20} {2,-30}", name, version, vendor);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error Checking Installed Programs: " + ex.Message);
        }
    }

    // lists smb/network shares
    static void Network_Shares()
    {
        // display column names
        Console.WriteLine("Network shares:\n");
        Console.WriteLine("{0,-20} {1,-20} {2,-30}", "Name", "Description", "Path");
        Console.WriteLine();

        try
        {
            // query WMI
            ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Share");

            // display each share
            foreach (ManagementObject share in searcher.Get())
            {
                string? shareName = share["Name"].ToString();
                string? shareDescription = share["Description"].ToString();
                string? sharePath = share["Path"].ToString();

                Console.WriteLine("{0,-20} {1,-20} {2,-30}", shareName, shareDescription, sharePath);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error Checking Network Shares: {ex.Message}");
        }
    }

    // gets build-in admins details
    static void Built_in_Admin()
    {
        Console.WriteLine("Built-in Admin User:\n");
        try
        {
            // SID of the built-in Administrator account always ends with "-500"
            string adminSidSuffix = "-500";
            string query = $"SELECT * FROM Win32_UserAccount WHERE SID LIKE '%{adminSidSuffix}' AND LocalAccount=True";

            // query WMI
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);
            ManagementObjectCollection results = searcher.Get();

            foreach (ManagementObject result in results)
            {
                Console.WriteLine($"Username: {result["Name"]}");
                Console.WriteLine($"SID: {result["SID"]}");
                Console.WriteLine($"Password Required: {result["PasswordRequired"]}");
                Console.WriteLine($"Password Expires: {result["PasswordExpires"]}");
                Console.WriteLine($"Password Changeable: {result["PasswordChangeable"]}");
                Console.WriteLine($"Disabled: {result["Disabled"]}");

                // get last pwd change date/time
                string? user_info = Run_Process("net", $"user {result["Name"]}");
                if (user_info != null)
                {
                    string[] lines = user_info.Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
                    foreach (var line in lines)
                    {
                        if (line.TrimStart().StartsWith("Password last set", StringComparison.OrdinalIgnoreCase))
                        {
                            int startIndex = 17; // length of "password last set"
                            string date = line.Substring(startIndex).Trim();
                            Console.WriteLine($"Password Last Set: {date}");
                        }
                    }
                }


                Console.WriteLine();
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error Checking Built-in Administrator: " + ex.Message);
        }
    }

    // checks if LAPS installed - by checking for dll file
    static void LAPS()
    {
        string filePath = @"C:\Program Files\LAPS\CSE\AdmPwd.dll";
        bool fileExists = File.Exists(filePath);

        if (fileExists)
        {
            Console.WriteLine($"LAPS is Installed - {filePath} Found\n");
        }
        else
        {
            Console.WriteLine($"LAPS is Not Installed - {filePath} Not Found\n");
        }
    }

    // check credentials stored in credential manager - same as running cmdkey /list
    static void Credential_Manager()
    {
        Console.WriteLine("Logons Stored in the Credential Manager:\n");
        try
        {
            var credSet = new CredentialSet();

            // load credentials from Windows Credential Manager
            credSet.Load();

            // display each credential
            foreach (var cred in credSet)
            {
                Console.WriteLine($"Target: {cred.Target}");
                Console.WriteLine($"Type: {cred.Type}");
                if (cred.Username != null)
                {
                    Console.WriteLine($"Username: {cred.Username}");
                }
                Console.WriteLine($"Last Write Time: {cred.LastWriteTime}");
                Console.WriteLine();

            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error Checking Credential Manager: {ex.Message}");
        }
    }

    // lists running services
    static void Running_Services()
    {
        try
        {
            // query WMI
            string query = "SELECT * FROM Win32_Service";
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);
            ManagementObjectCollection services = searcher.Get();

            // display column names
            Console.WriteLine("{0,-60} {1,-20}\n", "Display Name", "Start Name");
            // display services
            foreach (ManagementObject service in services)
            {
                // check if service running
                if (service["State"].ToString() == "Running")
                {
                    Console.WriteLine("{0,-60} {1,-20}", service["DisplayName"], service["StartName"]);
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error Checking Running Services: {ex.Message}");
        }
    }

    // checks for unquoted service paths
    static void Unquoted_Service_Paths()
    {
        // get all services installed on the system
        ServiceController[] services = ServiceController.GetServices();

        int count = 0;
        foreach (ServiceController service in services)
        {
            string serviceName = service.ServiceName;
            try
            {
                // get image path from registry
                string registryPath = $@"System\CurrentControlSet\Services\{serviceName}";
                using (RegistryKey? key = Registry.LocalMachine.OpenSubKey(registryPath))
                {
                    if (key != null)
                    {
                        object? imagePathObj = key.GetValue("ImagePath");
                        if (imagePathObj != null)
                        {
                            string? imagePath = imagePathObj.ToString();

                            // Check if the path is unquoted and contains spaces
                            if (imagePath != null)
                            {

                                // remove arguments from the paths
                                int index = imagePath.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
                                if (index != -1)
                                {
                                    imagePath = imagePath.Substring(0, index + 4);
                                }

                                // check it doesnt start with a " and has a space in it
                                if (!imagePath.StartsWith("\"") && imagePath.Contains(" "))
                                {
                                    Console.WriteLine($"Service: {service.ServiceName}");
                                    Console.WriteLine($"Display Name: {service.DisplayName}");
                                    Console.WriteLine($"Path: {imagePath}");

                                    // run sc qc on service
                                    string? scqc_result = Run_Process("sc", $"qc {service.ServiceName}");
                                    if (scqc_result != null)
                                    {
                                        Console.WriteLine($"sc qc Output:\n{scqc_result}");
                                    }
                                    else
                                    {
                                        Console.WriteLine($"Error Running sc qc for {service.ServiceName}");
                                    }


                                    Console.WriteLine();
                                    count += 1;
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error Checking Service '{serviceName}': {ex.Message}");
            }
        }
        if (count == 0)
        {
            Console.WriteLine("No Unquoted Serviced Paths Found");
        }
    }

    // checks DEP config
    static void Check_DEP()
    {
        try
        {
            // query WMI
            ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem");

            foreach (ManagementObject obj in searcher.Get())
            {
                if (obj["DataExecutionPrevention_SupportPolicy"] != null)
                {
                    Console.WriteLine($"DataExecutionPrevention_SupportPolicy={obj["DataExecutionPrevention_SupportPolicy"]}");
                }
                else
                {
                    Console.WriteLine("DataExecutionPrevention_SupportPolicy Not Found");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error Checking DEP: {ex.Message}");
        }
    }

    // list .NET versions
    static void Legacy_Dotnet()
    {
        string directoryPath = @"C:\Windows\Microsoft.NET\Framework64";

        try
        {
            // check directory exists
            if (Directory.Exists(directoryPath))
            {
                // get subdirectories
                string[] directories = Directory.GetDirectories(directoryPath);

                Console.WriteLine($".NET Versions in {directoryPath}:\nVersions Should Not be Lower Than 4.0\n");
                foreach (string dir in directories)
                {
                    string directoryName = Path.GetFileName(dir);
                    Console.WriteLine(directoryName);
                }
                Console.WriteLine();
            }
            else
            {
                Console.WriteLine($"{directoryPath} Does Not Exist - Cannot Check Legacy .NET Verisons\n");
            }
        }
        catch (Exception ex)
        {
            // Handle any errors that occur during the directory listing
            Console.WriteLine($"Error Checking .NET Versions: {ex.Message}");
        }
    }

    // checks powershell language mode and if v2 works
    static void Check_Powershell()
    {
        // check language mode
        Console.WriteLine("Checking PowerShell Language Mode - Should Not be Set to 'FullLanguage'");
        string? lang_mode = Run_Process("powershell.exe", "-NoProfile -ExecutionPolicy Bypass -Command \"$ExecutionContext.SessionState.LanguageMode\"");

        if (lang_mode != null)
        {
            // split the output by \n to get each line
            var modes = lang_mode.Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
            int count = 0;
            foreach (var mode in modes)
            {
                Console.WriteLine($"PowerShell Language Mode: {mode.Trim()}");
                count += 1;
            }
            Console.WriteLine();
            if (count == 0)
            {
                Console.WriteLine("Language Mode Not Found\n");
            }
        }
        else
        {
            Console.WriteLine("Error Checking PowerShell Language Mode\n");
        }


        // check powershell v2
        Console.WriteLine("Checking for PowerShell v2");
        string? output = Run_Process("cmd.exe", "/C powershell -version 2 -Command \"Get-Command Get-HotFix\"");
        if (output == null)
        {
            Console.WriteLine("PowerShell v2 is Either Not Enabled or Something Went Wrong");
        }
        else
        {
            Console.WriteLine("PowerShell v2 is Enabled");
        }
        Console.WriteLine();

    }

    // check if amsi enabled
    static void AMSI_Checks()
    {
        Console.WriteLine("Checking AMSI detection in powershell");
        string? output = Run_Process("cmd.exe", "/C powershell 'AmsiUtils'");
        if (output == null)
        {
            Console.WriteLine("AMSI is Either Enabled or Something Went Wrong\n");
        }
        else
        {
            Console.WriteLine("AMSI is Not Enabled\n");
        }
    }

    // lists drive encryption info
    static void Drive_Encryption()
    {
        Console.WriteLine(@"Checking Drive Encryption:
    Conversion Status should be 'Fully Encrypted'
    Percentage Encrypted should be '100.0%'
    Encryption Method should be 'XTS-AES 128' or stronger
    Protection Status should be 'Protection On'
    ");
        string? drives_output = Run_Process("powershell.exe", "-NoProfile -ExecutionPolicy Bypass -Command \"manage-bde.exe -status\"");
        if (drives_output != null)
        {
            // split the output by '\n' to get each line
            var drives = drives_output.Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
            int count = 0;
            foreach (var drive in drives.Skip(5))
            {
                Console.WriteLine(drive);
                count += 1;
            }
            Console.WriteLine();
            if (count == 0)
            {
                Console.WriteLine("No Drives Found\n");
            }
        }
        else
        {
            Console.WriteLine("Error Checking Drive Encryption\n");
        }
    }

    // lists startup programs
    static void Startup_Programs()
    {
        Console.WriteLine("Startup Programs:\n");
        try
        {
            // query WMI
            var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_StartupCommand");

            foreach (ManagementObject startupCommand in searcher.Get())
            {
                // Print out the properties of each startup command
                Console.WriteLine($"    Name: {startupCommand["Name"]}");
                Console.WriteLine($"    Command: {startupCommand["Command"]}");
                Console.WriteLine();
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error Checking Startup Programs {ex.Message}\n");
        }
    }

    // lists all tasks scheduled - that aren't \Microsoft
    static void Scheduled_Tasks()
    {
        try
        {
            Console.WriteLine(@"Scheduled Tasks (Excluding \Microsoft Path):" + "\n");
            using TaskService taskService = new TaskService();
            foreach (Microsoft.Win32.TaskScheduler.Task task in taskService.AllTasks)
            {
                // exclude tasks in the \Microsoft folder
                if (!task.Path.StartsWith(@"\Microsoft", StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine($"{task.Name}");
                    Console.WriteLine($"    Path: {task.Path}");
                    Console.WriteLine($"    State: {task.State}");
                    Console.WriteLine($"    Next Run Time: {task.NextRunTime}");
                    Console.WriteLine($"    Last Run Time: {task.LastRunTime}");
                    if (!string.IsNullOrEmpty(task.Definition.Principal.UserId))
                    {
                        Console.WriteLine($"    User: {task.Definition.Principal.UserId}"); // user which the task runs as
                    }
                    Console.WriteLine();
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error Checking Scheduled Tasks: {ex.Message}");
        }
    }

    // check C: drive permissions
    static void C_Perms()
    {
        string directoryPath = @"C:\";
        Console.WriteLine($"Checking Permissions C:\\");
        try
        {
            // get directory access control rules
            DirectoryInfo dirInfo = new DirectoryInfo(directoryPath);
            DirectorySecurity directorySecurity = dirInfo.GetAccessControl();

            foreach (FileSystemAccessRule rule in directorySecurity.GetAccessRules(true, true, typeof(System.Security.Principal.NTAccount)))
            {
                Console.WriteLine($"Identity: {rule.IdentityReference.Value}");
                Console.WriteLine($"Access Control Type: {rule.AccessControlType}");
                Console.WriteLine($"Permissions: {rule.FileSystemRights}");
                Console.WriteLine();
            }
        }
        catch (UnauthorizedAccessException ex)
        {
            Console.WriteLine($"Access Denied: {ex.Message}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error Checking C:\\ Permissions: {ex.Message}");
        }
    }

    // check if windows 8.3 shortnames are enabled
    static void Shortnames()
    {
        Console.WriteLine("Checking Windows 8.3 Name Creation - Should be Disabled");
        string? results = Run_Process("powershell.exe", "-NoProfile -ExecutionPolicy Bypass -Command \"fsutil 8dot3name query C:\"");
        if (results != null)
        {
            var lines = results.Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
            int count = 0;
            foreach (var line in lines)
            {
                Console.WriteLine(line);
                count += 1;
            }
            Console.WriteLine();
            if (count == 0)
            {
                Console.WriteLine("No Information Found\n");
            }
        }
        else
        {
            Console.WriteLine("Error Checking Windows 8.3 Shortnames\n");
        }
    }

    // check error reporting and telemetry
    static void Error_Reporting_Telemetry()
    {
        Console.WriteLine("Checking Error Reporting and Telemetry:\n");

        // reg query Disabled
        Console.WriteLine("Checking Windows Error Reporting (Disabled Registry Value) - Should be Set to 1");
        HKLM_Reg_Query(@"Software\Policies\Microsoft\Windows\Windows Error Reporting", "Disabled");
        Console.WriteLine();

        // reg query AllowTelemetry
        Console.WriteLine("Checking Telemetry/Diagnostic Data (AllowTelemetry Registry Value) - Should be Set to 0");
        HKLM_Reg_Query(@"Software\Policies\Microsoft\Windows\DataCollection", "AllowTelemetry");
        Console.WriteLine();

        // reg query SpynetReporting
        Console.WriteLine("Checking Microsoft Defender MAPS (SpynetReporting Registry Value) - Should be Set to 1");
        HKLM_Reg_Query(@"Software\Policies\Microsoft\Windows Defender\Spynet", "SpynetReporting");
        Console.WriteLine();

        // reg query NoInternetOpenWith
        Console.WriteLine("Checking Internet File Association Service (NoInternetOpenWith Registry Value) - Should be Set to 1");
        HKLM_Reg_Query(@"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoInternetOpenWith");
        Console.WriteLine();
    }

    // list record names in dns cache
    static void DNS_cache()
    {
        Console.WriteLine("Checking DNS Cache");

        string? cache = Run_Process("cmd.exe", "/c ipconfig /displaydns");
        if (cache != null)
        {
            // split the into lines (on `\n`)
            string[] lines = cache.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.RemoveEmptyEntries);

            int count = 0;
            foreach (string line in lines)
            {
                // check line starts with "Record Name"
                if (line.TrimStart().StartsWith("Record Name"))
                {
                    // print text after colon
                    string[] parts = line.Split(':');
                    if (parts.Length > 1)
                    {
                        string recordName = parts[1].Trim();
                        Console.WriteLine($"Record Name: {recordName}");
                        count += 1;
                    }
                }
            }
            if (count == 0)
            {
                Console.WriteLine("No Records Found");
            }
            Console.WriteLine();
        }
        else
        {
            Console.WriteLine("Error Checking DNS Cache\n");
        }
    }

    // check netBIOS over TCP/IP
    static void NetBios_TCPIP()
    {
        Console.WriteLine("NetBIOS Over TCP/IP Settings - Should be Disbaled");
        try
        {
            // query WMI
            var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE");

            foreach (ManagementObject obj in searcher.Get())
            {
                var netbiosOption = obj["TcpipNetbiosOptions"];
                var adapterName = obj["Description"].ToString();

                Console.WriteLine($"Adapter: {adapterName}");

                if (netbiosOption != null)
                {
                    int optionValue = Convert.ToInt32(netbiosOption);

                    switch (optionValue)
                    {
                        case 0:
                            Console.WriteLine("NetBIOS Over TCP/IP: Default (Use DHCP setting)");
                            break;
                        case 1:
                            Console.WriteLine("NetBIOS Over TCP/IP: Enabled");
                            break;
                        case 2:
                            Console.WriteLine("NetBIOS Over TCP/IP: Disabled");
                            break;
                        default:
                            Console.WriteLine("NetBIOS Over TCP/IP: Unknown setting");
                            break;
                    }
                }
                else
                {
                    Console.WriteLine("Error Checking NetBIOS Over TCP/IP Setting.");
                }
                Console.WriteLine();
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error Checking NetBIOS Over TCP/IP: {ex.Message}");
        }
    }

    // query registry to check for NBT-NS poisoning
    static void NBT_NS()
    {
        Console.WriteLine($"Checking NetbiosOptions - Should be Set to 0x00000002");
        string basePath = @"System\CurrentControlSet\services\NetBT\Parameters\Interfaces";

        using (RegistryKey? baseKey = Registry.LocalMachine.OpenSubKey(basePath))
        {
            if (baseKey != null)
            {
                // get subkeys
                string[] subkeyNames = baseKey.GetSubKeyNames();

                // check NetbiosOptions for each subkey
                foreach (string subkey in subkeyNames)
                {
                    string fullPath = $"{basePath}\\{subkey}";
                    HKLM_Reg_Query(fullPath, "NetbiosOptions");
                }
            }
            else
            {
                Console.WriteLine($"Base Registry Path Does Not Exist (Path: {basePath}).");
            }
            Console.WriteLine();
        }
    }

    //lists all listening TCP and UDP connections
    static void TCP_UDP()
    {
        Console.WriteLine("Checking Network Connections\n");
        try
        {
            // get TCP connections
            IPGlobalProperties properties = IPGlobalProperties.GetIPGlobalProperties();
            TcpConnectionInformation[] tcpConnections = properties.GetActiveTcpConnections();

            // get TCP listeners
            IPEndPoint[] tcpListeners = properties.GetActiveTcpListeners();

            // get  UDP listeners
            IPEndPoint[] udpListeners = properties.GetActiveUdpListeners();

            Console.WriteLine("TCP Connections:");
            foreach (TcpConnectionInformation connection in tcpConnections)
            {
                Console.WriteLine($"    {connection.LocalEndPoint} <--> {connection.RemoteEndPoint} : {connection.State}");
            }

            Console.WriteLine("\nTCP Listening Ports:");
            foreach (IPEndPoint endPoint in tcpListeners)
            {
                Console.WriteLine($"    {endPoint.Address}:{endPoint.Port}");
            }

            Console.WriteLine("\nUDP Listening Ports:");
            foreach (IPEndPoint endPoint in udpListeners)
            {
                Console.WriteLine($"    {endPoint.Address}:{endPoint.Port}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error Getting Connections: " + ex.Message);
        }
        Console.WriteLine();
    }

    // does a ping to check internet connection
    static void Check_Ping()
    {
        string ipAddress = "8.8.8.8";
        Console.WriteLine($"Pinging {ipAddress}:");
        bool succeeded = false;
        try
        {
            using (Ping ping = new Ping())
            {
                PingReply reply = ping.Send(ipAddress, 3000);

                if (reply.Status == IPStatus.Success)
                {
                    succeeded = true;
                    Console.WriteLine($"Ping to {ipAddress} Succeeded\n");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error During Ping: " + ex.Message + "\n");
        }
        if (!succeeded)
        {
            Console.WriteLine($"Ping to {ipAddress} Failed\n");
        }
    }

    // checks NTP config
    static void NTP()
    {
        Console.WriteLine("Checking Network Time Protocol Configurations");
        string? results = Run_Process("cmd.exe", "/c net time");
        if (results != null)
        {
            Console.WriteLine(results + "\n");
        }
        else
        {
            Console.WriteLine("Error Checking NTP Configuration - Can be Caused if it is Not Configured \n");
        }
    }

    // checks the local pwd policy - uses secedit report
    static void Password_Policy(string seceditFile)
    {
        Console.WriteLine("Checking Password Policy\n");
        try
        {
            string[] settings = ["MinimumPasswordAge", "MaximumPasswordAge", "MinimumPasswordLength", "PasswordComplexity", "PasswordHistorySize", "LockoutBadCount", "ResetLockoutCount", "LockoutDuration"];
            string[] output = ["Minimum Password Age (days)", "Maximum Password Age (days)", "Minimum Password Length", "Password Must Meet Complexity Requirements (0: Disabled, 1: Enabled)", "Length of Password History Kept", "Lockout Threashold", "Reset Account Lockout Counter After", "Lockout Duration"];

            for (int i = 0; i < settings.Length; i++)
            {
                Console.WriteLine($"    Checking {settings[i]}");

                string? value = Get_Value_From_Secedit(settings[i], seceditFile);
                if (value != null)
                {
                    Console.WriteLine($"    {output[i]}: {value}\n");
                }
                else
                {
                    Console.WriteLine("    Error Getting Setting\n");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error Getting Password Policy: " + ex.Message + "\n");
        }
    }

    // checks audit policy - uses secedit report
    static void Audit_Policy(string seceditFile)
    {
        Console.WriteLine("Checking Audit Policy\n");
        try
        {
            Console.WriteLine("    0: No Auditing\n    1: Audit Successful Events\n    2: Audit Failed Events\n    3: Audit Successful and Failed Events\n");

            string[] categories = ["AuditAccountLogon", "AuditAccountManage", "AuditDSAccess", "AuditLogonEvents", "AuditObjectAccess", "AuditPolicyChange", "AuditPrivilegeUse", "AuditProcessTracking", "AuditSystemEvents"];
            string[] recommended = ["3", "3", "2", "3", "3", "3", "3", "0 (optional)", "3"];
            for (int i = 0; i < categories.Length; i++)
            {
                Console.WriteLine($"    Checking {categories[i]} - Should be Set to {recommended[i]}");

                string? value = Get_Value_From_Secedit(categories[i], seceditFile);
                if (value != null)
                {
                    Console.WriteLine($"    {categories[i]}: {value}\n");
                }
                else
                {
                    Console.WriteLine("    Error Getting Setting\n");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error Checking Audit Policy: " + ex.Message + "\n");
        }

    }

    // reviews some security options
    static void Review_Secops()
    {
        // network access security options settings - using reg query
        Console.WriteLine("Checking Network Access Registry Values - Should be Set to 1");
        HKLM_Reg_Query(@"System\CurrentControlSet\Control\Lsa", "RestrictAnonymous");
        HKLM_Reg_Query(@"System\CurrentControlSet\Control\Lsa", "RestrictAnonymousSAM");
        HKLM_Reg_Query(@"System\CurrentControlSet\Control\Lsa", "DisableDomainCreds");
        Console.WriteLine();
        Console.WriteLine("Network Access Settings Related to Registy Access Have the Following Values");
        HKLM_Reg_Query(@"SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\", "Machine");
        HKLM_Reg_Query(@"SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\", "Machine");
        Console.WriteLine();

        Console.WriteLine("Checking System Can't be Shut Down Without Proper Authentication (ShutdownWithoutLogon Registry Value) - Should be Set to 0");
        HKLM_Reg_Query(@"Software\Microsoft\Windows\CurrentVersion\Policies\System", "ShutdownWithoutLogon");
        Console.WriteLine();

        // reg query NoConnectedUser
        Console.WriteLine("Checking Block Microsoft Accounts (NoConnectedUser Registry Value) - Should be Set to 3");
        HKLM_Reg_Query(@"Software\Microsoft\Windows\CurrentVersion\Policies\System", "NoConnectedUser");
        Console.WriteLine();

        // reg query CrashOnAuditFail
        Console.WriteLine("Checking CrashOnAuditFail Registry Value - Should be Set to 1");
        HKLM_Reg_Query(@"System\CurrentControlSet\Control\Lsa", "CrashOnAuditFail");
        Console.WriteLine();

        // reg query RequireSignOrSeal
        Console.WriteLine("Checking RequireSignOrSeal Registry Value - Should be Set to 1");
        HKLM_Reg_Query(@"System\CurrentControlSet\Services\Netlogon\Parameters", "RequireSignOrSeal");
        Console.WriteLine();

        // reg query DisableCAD
        Console.WriteLine("Checking DisableCAD (CTRL+ALT+DEL) Registry Value - Should be Set to 0");
        HKLM_Reg_Query(@"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableCAD");
        Console.WriteLine();

        // reg query DontDisplayLastUserName
        Console.WriteLine("Checking DontDisplayLastUserName Registry Value - Should be Set to 0");
        HKLM_Reg_Query(@"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DontDisplayLastUserName");
        Console.WriteLine();

        // reg query NoLMHash
        Console.WriteLine("Checking NoLMHash (No Lan Manager Hash) Registry Value - Should be Set to 1");
        HKLM_Reg_Query(@"System\CurrentControlSet\Control\Lsa", "NoLMHash");
        Console.WriteLine();

        // reg query FilterAdministratorToken
        Console.WriteLine("Checking Admin Approval Mode (FilterAdministratorToken Registry Value) - Should be Set to 1");
        HKLM_Reg_Query(@"Software\Microsoft\Windows\CurrentVersion\Policies\System", "FilterAdministratorToken");
        Console.WriteLine();

        // reg query ConsentPromptBehaviorAdmin
        Console.WriteLine("Checking ConsentPromptBehaviorAdmin Registry Value - Should be Set to 1");
        HKLM_Reg_Query(@"Software\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin");
        Console.WriteLine();

        // reg query ClearPageFileAtShutdown
        Console.WriteLine("Checking ClearPageFileAtShutdown Registry Value - Should be Set to 1");
        HKLM_Reg_Query(@"System\CurrentControlSet\Control\Session Manager\Memory Management", "ClearPageFileAtShutdown");
        Console.WriteLine();

    }






    static void Main()
    {
        Console.WriteLine(@"   ______     _______      _________   _____  _____ 
  |_   _ \   |_   __ \    |_   ___  | |_   _||_   _|
    | |_) |    | |__) |     | |_  \_|   | | /\ | |  
    |  __'.    |  __ /      |  _|  _    | |/  \| |  
   _| |__) |  _| |  \ \_   _| |___/ |   |   /\   |  
  |_______/  |____| |___| |_________|   |__/  \__|
  
  Build Review and Enumeration for Windows");

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) // checks if the os in windows before running the windows specific code
        {

            Console.WriteLine("\n----- 1 - PREREQUISITES -----\n");

            // check if user is admin
            bool admin = Admin();

            // generate secedit report
            bool secedit = false;
            string seceditFile = "";
            if (admin)
            {
                Console.WriteLine("Generating Report Using Secedit");
                seceditFile = Generate_Secedit_Report();
                if (seceditFile != "error")
                {
                    secedit = true;
                    Console.WriteLine("Report Generated Successfully\n");
                }
                else
                {
                    Console.WriteLine("Error Generating Report, Some Checks Will Fail\n");
                }
            }
            else
            {
                Console.WriteLine("Could Not Generate Report Using Secedit as You do Not Have Administrator Privileges - Some Checks Will Fail\n");
            }

            // reg query LocalAccountTokenFilterPolicy
            Console.WriteLine("Checking LocalAccountTokenFilterPolicy Registry Value - Should be Set to 0x00000001");
            HKLM_Reg_Query(@"Software\Microsoft\Windows\CurrentVersion\Policies\System", "LocalAccountTokenFilterPolicy");
            Console.WriteLine();

            Console.WriteLine("\n----- 2 - PATCHING VERIFICATION -----\n");

            // check missing patches/updates
            Missing_Updates();

            // List installed programs
            Installed_Programs();

            Console.WriteLine("\n----- 3 - SMB SHARES -----\n");

            // list shares
            Network_Shares();

            Console.WriteLine("\n----- 4 - LOCAL ADMIN ACCOUNT SECURITY AND PASSWORD MANAGEMENT -----\n");

            // get details about built in admin account
            Built_in_Admin();

            // check if admin account can be locked out
            if (secedit)
            {
                Console.WriteLine("Checking for Account Lockout on Local Admin Account - Should be Set to 0");
                string? value = Get_Value_From_Secedit("AllowAdministratorLockout", seceditFile);
                if (value != null)
                {
                    Console.WriteLine($"AllowAdministratorLockout: {value}\n");
                }
                else
                {
                    Console.WriteLine("Error Getting Setting\n");
                }
            }
            else
            {
                Console.WriteLine("Cannot Check for Account Lockout on Local Admin Account as no Secedit Report Was Generated\n");
            }

            // check if LAPS is installed
            LAPS();

            // reg query CachedLogonsCount
            Console.WriteLine("Checking CachedLogonsCount Registry Value");
            HKLM_Reg_Query(@"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "CachedLogonsCount");
            Console.WriteLine();

            // check cached passwords (in credential manager) - same as running 'cmdkey /list' as far as I can tell
            Credential_Manager();

            Console.WriteLine("\n----- 5 - LOCAL SERVICES SECURITY REVIEW -----\n");

            // list running services
            Console.WriteLine("Running Services:\n");
            Running_Services();
            Console.WriteLine();

            // check for unquoted service paths
            Console.WriteLine("Unquoted Service Paths:\n");
            Unquoted_Service_Paths();
            Console.WriteLine();

            Console.WriteLine("\n----- 6 - DEP CONFIGURATION REVIEW -----\n");

            // check DEP config
            Console.WriteLine("Checking DEP configurations - Should be Set to 1");
            Check_DEP();
            Console.WriteLine();

            Console.WriteLine("\n----- 7 - POWERSHELL HARDENING AND LEGACY .NET REVIEW -----\n");

            // list .NET versions
            Legacy_Dotnet();

            // check powershell lang mode and for v2
            Check_Powershell();

            // reg query AmsiEnable
            Console.WriteLine("Checking AmsiEnable Registry Value - Should be Set to 1 ");
            HKLM_Reg_Query(@"Software\Microsoft\Windows Script\Settings", "AmsiEnable");
            Console.WriteLine();

            // further checks for amsi
            AMSI_Checks();

            // reg query ScriptBlockLogging 
            Console.WriteLine("Checking ScriptBlockLogging Registry Value - Should be Set to 1 ");
            HKLM_Reg_Query(@"Software\Policies\Microsoft\Windows\PowerShell", "ScriptBlockLogging ");
            Console.WriteLine();

            Console.WriteLine("\n----- 8 - COMPREHENSIVE SECURITY AUDITS AND CONFIGURATION CHECKS -----\n");

            // check drive encryption
            if (admin)
            {
                Drive_Encryption();
            }
            else
            {
                Console.WriteLine("Cannot Check Drive Encryption as You do Not Have Administrator Privileges\n");
            }

            // reg query RunAsPPL
            Console.WriteLine("Checking RunAsPPL Registry Value - Should be Set to 0x00000001");
            HKLM_Reg_Query(@"System\CurrentControlSet\Control\Lsa", "RunAsPPL");
            Console.WriteLine();

            // reg query CWDIllegalInDllSearch
            Console.WriteLine("Checking CWDIllegalInDllSearch Registry Value - Should be Set to 0xFFFFFFFF, 0x00000001, or 0x00000002");
            HKLM_Reg_Query(@"System\CurrentControlSet\Control\Session Manager", "CWDIllegalInDllSearch");
            Console.WriteLine();

            // list startup programs
            Startup_Programs();

            // list scheduled tasks
            Scheduled_Tasks();

            // check permissions on c drive - like icacls C:\
            C_Perms();

            // reg query RequireSecuritySignature
            Console.WriteLine("Checking RequireSecuritySignature Registry Values - Should be Set to 0x00000001");
            HKLM_Reg_Query(@"System\CurrentControlSet\Services\LanmanWorkstation\Parameters", "RequireSecuritySignature");
            HKLM_Reg_Query(@"System\CurrentControlSet\Services\LanmanServer\Parameters", "RequireSecuritySignature");
            Console.WriteLine();

            // check Windows 8.3 shortnames
            if (admin)
            {
                Shortnames();
            }
            else
            {
                Console.WriteLine("Cannot Check if Windows 8.3 Name Creation is Enabled as You do Not Have Administrator Privileges\n");
            }

            // logon banner - using reg query
            Console.WriteLine("Checking Logon Banner Registry Values - Should be Set");
            HKLM_Reg_Query(@"Software\Microsoft\Windows\CurrentVersion\Policies\System", "LegalNoticeText");
            HKLM_Reg_Query(@"Software\Microsoft\Windows\CurrentVersion\Policies\System", "LegalNoticeCaption");
            Console.WriteLine();

            // reg query 
            Console.WriteLine("Checking Network Level Authentication (UserAuthentication Registry Value) - Should be Set to 1");
            HKLM_Reg_Query(@"Software\Policies\Microsoft\Windows NT\Terminal Services", "UserAuthentication");
            Console.WriteLine();

            // check error reporting and telemetry
            Error_Reporting_Telemetry();

            // reg query ConsentPromptBehaviorUser
            Console.WriteLine("Checking ConsentPromptBehaviorUser Registry Value - Should be Set to 1");
            HKLM_Reg_Query(@"Software\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorUser");
            Console.WriteLine();

            Console.WriteLine("\n----- 9 - NETWORK CONFIGURATION AND SECURITY CHECKS -----\n");

            // reg query DisabledComponents (ipv6)
            Console.WriteLine("Checking DisabledComponents (IPv6) Registry Value - Should be Set to 0xFFFFFFFF");
            HKLM_Reg_Query(@"system\CurrentControlSet\Services\TCPIP6\Parameters", "DisabledComponents");
            Console.WriteLine();

            // check dns cache
            DNS_cache();

            // check netBIOS over TCP/IP
            NetBios_TCPIP();

            // reg query EnableMulticast
            Console.WriteLine("Checking EnableMulticast Registry Value - Should be Set to 0");
            HKLM_Reg_Query(@"Software\Policies\Microsoft\WindowsNT\DNSClient", "EnableMulticast");
            Console.WriteLine();

            // check for NBT-NS poisoning
            NBT_NS();

            // equivalent of netstat -ano - gets tcp and udp connections
            TCP_UDP();

            // ping 8.8.8.8
            Check_Ping();

            // check ntp config
            NTP();

            Console.WriteLine("\n----- 10 - LOCAL SECURITY POLICY CONFIGURATION AND REVIEW -----\n");

            // check pwd policy
            if (admin)
            {
                if (secedit)

                    Password_Policy(seceditFile);
                else
                {
                    Console.WriteLine("Cannot Check Password Policy as no Secedit Report Was Generated\n");
                }
            }
            else
            {
                Console.WriteLine("Cannot Check Password Policy as You do Not Have Administrator Privileges\n");
            }

            Console.WriteLine("\n----- 11 - AUDITING AND SECURITY OPTIONS IN LOCAL SECURITY POLICY -----\n");

            // reg query AuditPolicyChange
            Console.WriteLine("Checking Force Audit Policy (AuditPolicyChange Registry Value) - Should be Set to 1");
            HKLM_Reg_Query(@"Software\Policies\Microsoft\Windows\EventLog", "AuditPolicyChange");
            Console.WriteLine();

            // checks audit policy
            if (admin)
            {
                if (secedit)

                    Audit_Policy(seceditFile);
                else
                {
                    Console.WriteLine("Cannot Check Audit Policy as no Secedit Report Was Generated\n");
                }
            }
            else
            {
                Console.WriteLine("Cannot Check Audit Policy as You do Not Have Administrator Privileges\n");
            }

            Console.WriteLine("Checking Security Policy\n");

            // admin account status
            if (secedit)
            {
                Console.WriteLine("Checking Built-in Administrator Account Status - Should be Set to 0");
                string? value = Get_Value_From_Secedit("EnableAdminAccount", seceditFile);
                if (value != null)
                {
                    Console.WriteLine($"EnableAdminAccount: {value}\n");
                }
                else
                {
                    Console.WriteLine("Error Getting Setting\n");
                }
            }
            else
            {
                Console.WriteLine("Cannot Check Built-in Administrator Account Status as no Secedit Report Was Generated\n");
            }


            // guest account status
            if (secedit)
            {
                Console.WriteLine("Checking Built-in Guest Account Status - Should be Set to 0");
                string? value = Get_Value_From_Secedit("EnableGuestAccount", seceditFile);
                if (value != null)
                {
                    Console.WriteLine($"EnableGuestAccount: {value}\n");
                }
                else
                {
                    Console.WriteLine("Error Getting Setting\n");
                }
            }
            else
            {
                Console.WriteLine("Cannot Check Built-in Guest Account Status as no Secedit Report Was Generated\n");
            }

            // admin account name
            if (secedit)
            {
                Console.WriteLine("Checking Built-in Administrator Account Name - Should Not be Set to Administrator");
                string? value = Get_Value_From_Secedit("NewAdministratorName", seceditFile);
                if (value != null)
                {
                    Console.WriteLine($"NewAdministratorName: {value}\n");
                }
                else
                {
                    Console.WriteLine("Error Getting Setting\n");
                }
            }
            else
            {
                Console.WriteLine("Cannot Check Built-in Administrator Account Name as no Secedit Report Was Generated\n");
            }

            // guest account name
            if (secedit)
            {
                Console.WriteLine("Checking Built-in Guest Account Name - Should Not be Set to Guest");
                string? value = Get_Value_From_Secedit("NewGuestName", seceditFile);
                if (value != null)
                {
                    Console.WriteLine($"NewGuestName: {value}\n");
                }
                else
                {
                    Console.WriteLine("Error Getting Setting\n");
                }
            }
            else
            {
                Console.WriteLine("Cannot Check Built-in Guest Account Name as no Secedit Report Was Generated\n");
            }

            // checks some security options
            Review_Secops();

            // delete temp file 
            if (secedit)
            {
                if (File.Exists(seceditFile))
                {
                    File.Delete(seceditFile);
                }
                else
                {
                    Console.WriteLine($"Error Deleting Secedit File: {seceditFile}");
                }
            }

        }

        else
        {
            Console.WriteLine("The Operating System is Not Windows \n");
        }
    }
}
