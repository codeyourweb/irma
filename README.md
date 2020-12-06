# IRPAME - Incident Response - Primary Analysis & Malware Eradication

# About this project
I undertook this project initially in order to learn Go. Then little by little 
I tried to understand how to use the Win32 API and finally to read the process 
memory on a Windows system.
As time went by i thought that this program could be used in my sandboxes to 
analyze and trace malicious behaviors. Little by little, an emergency 
remediation tool was born. I don't guarantee it as a miracle solution but it 
can be used in many cases, whether in malware analysis or in case of emergency 
during an incident response. Do not hesitate to propose new features or to 
complete the source code. 

Translated with www.DeepL.com/Translator (free version)

## Installation 
Feel free to download compiled release of this software. If you want to compile 
from sources, it could be a little bit tricky cause it's stronly depends of 
_go-yara_ and CGO compilation. You'll find a detailed documentation [here](README.windows-compilation.md)

## Usage 
```
usage: irpame [-h|--help] [-y|--yara-rules "<value>"] [-d|--dump "<value>"]
              [-k|--kill] [-f|--faker] [-a|--aggressive] [-n|--notifications]

Arguments:

  -h  --help           Print help information
  -y  --yara-rules     Yara rules path (the program will look for *.yar files
                       recursively). Default: ./yara-signatures
  -d  --dump           Dump all running process to the specified directory
  -k  --kill           Kill suspicious process ID (without removing process
                       binary)
  -f  --faker          Spawn fake processes such as wireshark / procmon /
                       procdump / x64dbg
  -a  --aggressive     Aggressive mode - remove suscpicious process executable
                       / track and remove PPID / remove schedule task & regkey
                       persistence
  -n  --notifications  Use Windows notifications when a file or memory stream
                       match your YARA rules
