# IRMA - Incident Response - Minimal Analysis

## What is this project designed for?
IRMA is a lightweight tool made for live forensics on Windows Platform. It is 
focused on two main approaches:
* live analysis, quarantine and eradication of malware due to suspicious behaviour 
* logging and instant notifications for malware TTP's assesment on a sandbox platform

## How IRMA scan for malware behaviour?
IRMA is intended to work with user or administrator rights.
Based on your user privileges it can:
* implements the YARA library and regularly scan the workstation's files and memory
* search for execution context (parent process, regkey, scheduled task persistence)
Every suspect behaviour could be text logged, notified to the user, and/or eradicated 

## What does it scan?
Currently, IRMA is able to:
* list running processes and log for suspiscious actions
* list common persistence mecanisms (registry keys / scheduled tasks / startup folder links)
* perform YARA scan on files and memory
* dump / quarantine suspiscious artefacs
* spawn fake analysis processes to make the computer look like an analysis platform

## About this project
I undertook this project initially in order to learn Go. Then little by little 
I tried to understand how to use the Win32 API and finally to read the process 
memory on a Windows system.
As time went by i thought that this program could be used in my sandboxes to 
analyze and trace malicious behaviors. Little by little, an emergency 
remediation tool was born. I don't guarantee it as a miracle solution but it 
can be used in many cases, whether in malware analysis or in case of emergency 
during an incident response. Do not hesitate to propose new features or to 
complete the source code. 

### Installation 
Feel free to download compiled release of this software. If you want to compile 
from sources, it could be a little bit tricky cause it's stronly depends of 
_go-yara_ and CGO compilation. You'll find a detailed documentation [here](README.windows-compilation.md)

### Usage 
```
usage: irma [-h|--help] [-y|--yara-rules "<value>"] [-d|--dump "<value>"]
            [-q|--quarantine "<value>"] [-k|--kill] [-f|--faker]
            [-a|--aggressive] [-n|--notifications] [-v|--verbose]

Arguments:

  -h  --help           Print help information
  -y  --yara-rules     Yara rules path (the program will look for *.yar files
                       recursively). Default: ./yara-signatures
  -d  --dump           Dump all running process to the specified directory
  -q  --quarantine     Specify path to store matching artefacts in quarantine
                      (Base64/RC4 with key: irma
  -k  --kill           Kill suspicious process ID (without removing process
                       binary)
  -f  --faker          Spawn fake processes such as wireshark / procmon /
                       procdump / x64dbg
  -a  --aggressive     Aggressive mode - remove suscpicious process executable
                       / track and remove PPID / remove schedule task & regkey
                       persistence
  -n  --notifications  Use Windows notifications when a file or memory stream
                       match your YARA rules

## Future of IRMA
As i've already said, i've initially created IRMA to learn Go. After working on
system oriented analysis, i'll probably try to implement some network analysis.

Further versions may contains:
* The ability to create a proxy
* Complete or selected network packets dump
* SNORT/Suricata rules analysis
* Improved detection of system behaviors
* Transfer of analysis results to a SIEM
* Agent management platform - Command and control ability
