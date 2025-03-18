# Documentation for Build Review and Enumeration for Windows (BREW)

This project is an automated tool to assist during Windows build reviews.

## Table of Contents
- [Development Environment](#development-environment)
- [Compiling the Code](#compiling-the-code)
- [Code Explanation](#code-explanation)
    - [*Main()*](#main)
    - [*HKLM_Reg_Query()*](#HKLM_Reg_Query)
    - [*Run_Process()*](#Run_Process)
    - [*Get_Value_From_Secedit()*](#GEt_Value_From_Secedit)
    - [*Admin()*](#Admin)
    - [*Generate_Secedit_Report()*](#Generate_Secedit_Report)
    - [*Missing_Updates()*](#Missing_Updates)
    - [*Installed_Programs()*](#Installed_Programs)
    - [*Network_Shares()*](#Network_Shares)
    - [*Built_in_Admin()*](#Built_in_Admin)
    - [*LAPS()*](#LAPS)
    - [*Credential_Manager()*](#Credential_Manager)
    - [*Running_Services()*](#Running_Services)
    - [*Unquoted_Service_Paths()*](#Unquoted_Service_Paths)
    - [*Check_DEP()*](#Check_DEP)
    - [*Legacy_Dotnet()*](#Legacy_Dotnet)
    - [*Check_Powershell()*](#Check_Powershell)
    - [*AMSI_Checks()*](#AMSI_Checks)
    - [*Drive_Encryption()*](#Drive_Encryption)
    - [*Startup_Programs()*](#Startup_Programs)
    - [*Scheduled_Tasks()*](#Scheduled_Tasks)
    - [*C_Perms()*](#C_Perms)
    - [*Shortnames()*](#Shortnames)
    - [*Error_Reporting_Telemetry()*](#Error_Reporting_Telemetry)
    - [*DNS_Cache()*](#DNS_Cache)
    - [*NetBios_TCPIP()*](#NetBios_TCPIP)
    - [*NBT_NS()*](#NBT_NS)
    - [*TCP_UDP()*](#TCP_UDP)
    - [*Check_Ping()*](#Check_Ping)
    - [*NTP()*](#NTP)
    - [*Password_Policy()*](#Password_Policy)
    - [*Audit_Policy()*](#Audit_Policy)
    - [*Review_Secops()*](#Review_Secops)


## Development Environment

During the development of this extension, the system which compiled on a Windows 10 system with [.Net](https://dotnet.microsoft.com/en-us/) 8.0.302.

The following packages were added:
- [CredentialManagement](https://www.nuget.org/packages/CredentialManagement) 1.0.2
- [Microsoft.Win32.TaskScheduler](https://www.nuget.org/packages/TaskScheduler) 8.0.0
- [System.Management](https://www.nuget.org/packages/System.Management/9.0.0-preview.7.24405.7) 8.0.0
- [System.ServiceProcess.ServiceController](https://www.nuget.org/packages/System.ServiceProcess.ServiceController/9.0.0-preview.7.24405.7) 2.11.0

These can be added by running the following commands inside the BREW directory:

```sh
$ dotnet add package CredentialManagement
$ dotnet add package TaskScheduler
$ dotnet add package System.Management
$ dotnet add package System.ServiceProcess.ServiceController
```

To run the compiled .exe file, the machine must be Windows x86_64. It does not need .NET. 

## Compiling the Code

The compiled, standalone .exe can be found in `/compiled.zip`.

If you wish to re-compile the code as a single .exe file with dependencies included inside this, run the following command:

```sh
$ dotnet publish -c Release -r win-x64 --self-contained
```

The .exe generated as a result can be found at `Build Review Tool/BREW/bin/Release/net8.0-windows/win-x64/publish/BREW.exe`.

## Code Explanation

The following functions are located in `Build Review Tool/BREW/sourcecode.cs`

<details>
<summary><h3><em><code>Main()</code></em></h3></summary>

This function controls when the other functions are executed. This function runs the *Admin()* and *Generate_Secedit_Report()* first and will only run certain other functions if these either one or both of these functions returned true if the function to be run depends on the ouput of either of these functions. At the end of this function, if a temporary file was created by the *Generate_Secedit_Report()* function, this file is deleted.
</details>

<details>
<summary><h3><em><code>HKLM_Reg_Query()</code></em></h3></summary>

This function takes the path to a registry key (inside `HKEY_LOCAL_MACHINE`) and its name. It checks if the path exists and if the registry key exists at that path. If the key and/or path doesn't exist, an error message is output. If the key does exist, its value is read and output. If the key holds multiple values, all of these are output.

</details>

<details>
<summary><h3><em><code>Run_Process()</code></em></h3></summary>

This function takes a processes command and arguments to run the process as parameters. It then runs this process without creating a new window and captures the output and exit code. If it executed sucessfully,the function returns the output from the process. If it did not execute successfully, the function returns null.

This function could be used to perform most of the necessary checks however it is only used if there is not another way to perform the check with C#.

</details>

<details>
<summary><h3><em><code>Get_Value_From_Secedit()</code></em></h3></summary>

This function takes the prefix of the line containing the setting to search and the tempory file path for the secedit report as parameters. It checks if the file exists and then finds the line that starts with the prefix passed as a parameter. It returns the value after the equals sign in that line. If there is an error or the setting isn't found, the function returns null.

</details>

<details>
<summary><h3><em><code>Admin()</code></em></h3></summary>

This function gets the current users account and checks if it is in the Administrator's group. It returns true if the user is an adminstrator. The function returns false if the user is not an administrator or an error occured.

</details>

<details>
<summary><h3><em><code>Generate_Secedit_Report()</code></em></h3></summary>

This function gets a filepath for a new temporary file. It then calls the *Run_Process()* function to generate a report containing the current security policy settings which is then saved to a temporary file. If this happens successfully, the temporary file path is returned. If there is an error, "error" is returned.

</details>

<details>
<summary><h3><em><code>Missing_Updates()</code></em></h3></summary>

This function uses the *Run_Process()* function to check for missing updates on the device. It checks if any updates were found outputs them if there are any. If there aren't any, it outputs "No Updates Found". If an error occurs, an error message is outputted. The program can hang during this function - opening Task Manager and/or sending a keyboard interrupt into the terminal seems to fix this.

</details>

<details>
<summary><h3><em><code>Installed_Programs()</code></em></h3></summary>

This function queries the Windows Management Instrumentation (WMI) to get the name, version and vendor for installed programs on the system and outputs this information. If an error occurs, the program outputs a suitable error message.

</details>

<details>
<summary><h3><em><code>Network_Shares()</code></em></h3></summary>

This function queries WMI to get the name, description and path for network shares on the system and outputs this information. If there is an error occurs, the program outputs a suitable error message.

</details>

<details>
<summary><h3><em><code>Built_in_Admin()</code></em></h3></summary>

This function queries WMI to get the name and SID for the built in administrator user (SID ending in 500). It also checks whether this account requires a password, whether the password expires, if the password can be changed and if the account is disabled. This function then uses the *Run_process()* function to run the `net user` command to check when this account's password was last set. The section of the string containing the date is then retrieved and outputted. If an error occurs, the program outputs a suitable error message.

</details>

<details>
<summary><h3><em><code>LAPS()</code></em></h3></summary>

This function checks if LAPS is installed as a service by checking if its associated DLL file exists. A suitable message is outputted to display the result of the check.

</details>

<details>
<summary><h3><em><code>Credential_Manager()</code></em></h3></summary>

This function makes use of the [Credential Management package](https://www.nuget.org/packages/CredentialManagement) to load saved credentials in Window's Credential Manager. The type, username and time it was changed for each saved credential are then outputted. If an error occurs, the program outputs a suitable error message.

</details>

<details>
<summary><h3><em><code>Running_Services()</code></em></h3></summary>

This function queries WMI to get the display name and the start name for running services and outputs this information. if an error occurs, the program outputs a suitable error message.

</details>

<details>
<summary><h3><em><code>Unquoted_Service_Paths()</code></em></h3></summary>

This function makes use of the [Service Controller package](https://www.nuget.org/packages/System.ServiceProcess.ServiceController/9.0.0-preview.7.24405.7) to get a list of services on the system. The function then uses each services name to query the registry and retrieve the services image path. The image path is unchecked to see if it is unquoted and contains spaces. For any unquoted service paths found, the service name, display name and path are all outputted. The *Run_Proccess* function is then used to run sc qc on the service to see its permisions and the result is outputted. If no unquoted service paths are found, a suitable message is outputted. If an error occurs, the program outputs a suitable error message.

</details>

<details>
<summary><h3><em><code>Check_DEP()</code></em></h3></summary>

This function queries WMI to find the value held in the DataExecutionPrevention_SupportPolicy setting. This value is outputted. If an error occurs, the program outputs a suitable error message.

</details>

<details>
<summary><h3><em><code>Legacy_Dotnet()</code></em></h3></summary>

This function lists the names of directories inside `C:\Windows\Microsoft.NET\Framework64` as these names correspond to the versions of .NET installed. If an error occurs, the program outputs a suitable error message.

</details>

<details>
<summary><h3><em><code>Check_Powershell()</code></em></h3></summary>

This function uses the *Run_Process()* function to run a PowerShell instance and check the language mode used. This language mode is then outputted. If an error occurs, the program outputs a suitable error message.

</details>

<details>
<summary><h3><em><code>AMSI_Checks()</code></em></h3></summary>

This function uses the *Run_Process()* function to check if AMSI is enabled. It runs the command 'AmsiUtils'. If this command runs without an error then AMSI is not enabled. If there is an error, AMSI may be enabled or there may be another cause of the error. The result of this check is outputted.

</details>

<details>
<summary><h3><em><code>Drive_Encryption()</code></em></h3></summary>

This function uses the *Run_Process()* function to run the command `manage-bde.exe -status`. This checks the encryption for all drives. The information found is outputted. If there is an error, the program outputs a suitable error message.

</details>

<details>
<summary><h3><em><code>Startup_Programs()</code></em></h3></summary>

This function queries WMI to find the name and command for startup programs and this information is oujtputted. If an error occurs, the program outputs a suitable error message.

</details>

<details>
<summary><h3><em><code>Scheduled_Tasks()</code></em></h3></summary>

This function uses the [Task Scheduler package](https://www.nuget.org/packages/TaskScheduler) to find the name, path, state, next run time and last run time for scheduled programs (excluding startup programs located inside the `/Microsoft` directory). It also gets the privilege the task runs with. If an error occurs, the program outputs a suitable error message.

</details>

<details>
<summary><h3><em><code>C_Perms()</code></em></h3></summary>

This function checks the access rules for `C:\`. For each user role, the access control type and permisisons are outputted. If an error occurs, the program outputs a suitable error message.

</details>

<details>
<summary><h3><em><code>Shortnames()</code></em></h3></summary>

This function uses the *Run_Process()* function to run the command `fsutil 8dot3name query C:`. The result of this is outputted. If an error occurs, the program outputs a suitable error message.

</details>

<details>
<summary><h3><em><code>Error_Reporting_Telemetry()</code></em></h3></summary>

This function uses the *HKLM_Reg_Query()* function to query reg keys related to error reporting and telemetry. The values held by these keys are outputted.

</details>

<details>
<summary><h3><em><code>DNS_cache()</code></em></h3></summary>

This function uses the *Run_Process()* function to run the command `ipconfig /displaydns`. Any lines of the captured result of this command that start with `Record Name` are outputted. If an error occurs, the program outputs a suitable error message.

</details>

<details>
<summary><h3><em><code>NetBios_TCPIP()</code></em></h3></summary>

This function queries WMI to find the TCPIPNetbiosOptions and adapter name for each adapter. The numerical value of the TCPIPNetbiosOptions setting is then translated to a string that explains what the value is set to. This information is then outputted. If an error occurs, the program outputs a suitable error message.

</details>

<details>
<summary><h3><em><code>NBT_NS()</code></em></h3></summary>

This function queries the registry to find all of the subkeys at `System\CurrentControlSet\services\NetBT\Parameters\Interfaces`. The function then passes the path to each subkey to the *HKLM_Reg_Query()* function to retrieve the value held at each subkey. These values are then outputted. If the base registry path cannot be found, the program outputs a suitable error message.

</details>

<details>
<summary><h3><em><code>TCP_UDP()</code></em></h3></summary>

This function gets the active TCP connections, TCP listeners and UDP listerners. For the TCP conections, the function outputs the local endpoint IP address, remote endpoint IP address and connection state. For the listeners, the program outputs the endpoint port and IP address. If an error occurs, the program outputs a suitable error message.

</details>

<details>
<summary><h3><em><code>Check_Ping()</code></em></h3></summary>

This function pings `8.8.8.8`. The program outputs whether this ping was successful. If an error occurs, the program outputs a suitable error message.

</details>

<details>
<summary><h3><em><code>NTP()</code></em></h3></summary>

This function uses the *Run_Process()* function to run the command `net time`. The result of this command is outputted. If an error occurs, the program outputs a suitable error message.

</details>

<details>
<summary><h3><em><code>Password_Policy()</code></em></h3></summary>

This function takes the filepath for the secedit report generated by the *Generate_Secedit_Report()* function as a parameter.It then uses the *Get_Value_From_Secedit()* function to check the values settings related to the password policy are set to. These values are then outputted. If an error occurss, the progrma outputs a suitable error message.

</details>

<details>
<summary><h3><em><code>Audit_Policy()</code></em></h3></summary>

This function takes the filepath for the secedit report generated by the *Generate_Secedit_Report()* function as a parameter.It then uses the *Get_Value_From_Secedit()* function to check the values settings related to the audit policy are set to. These values are then outputted. If an error occurss, the progrma outputs a suitable error message.

</details>

<details>
<summary><h3><em><code>Review_Secops()</code></em></h3></summary>

This function uses the *HKLM_Reg_Query()* function to query reg keys related to the security options settings. The values held by these keys are outputted.
</details>