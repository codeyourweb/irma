[![Project Status](https://img.shields.io/badge/status-BETA-yellow?style=flat-square)]()

# IRMA - Incident Response - Minimal Analysis

## What is this project designed for?
_IRMA_ is a lightweight tool made for live forensics on Windows Platform. It is 
focused on three use cases:
* enpoint detection - live analysis, quarantine and eradication of malware on a workstation 
* live analysis & sandbox host - logging and instant notifications for malware TTP's assesment
* signatures quality test - scan your endpoint baseline and check for false positives

## How IRMA scan for malware behaviour?
_IRMA_ is intended to work with both user or administrator rights.
Based on your user privileges it can:
* implements the YARA library and regularly scan the workstation's files and memory
* search for execution context (parent process, regkey, scheduled task persistence)
Every suspect behaviour could be text logged, notified to the user, and/or eradicated 

## What does it scan?
Currently, _IRMA_ is able to:
* list running processes and log for suspiscious actions
* list common persistence mecanisms (registry keys / scheduled tasks / startup folder links)
* perform YARA scan on files and memory
* dump / quarantine suspiscious artefacs
* spawn fake analysis processes to make the computer look like an analysis platform

### Installation 
Feel free to download compiled release of this software. If you want to compile 
from sources, it could be a little bit tricky cause it's stronly depends of 
_go-yara_ and CGO compilation. You'll find a detailed documentation [here](README.windows-compilation.md)

### Usage 
```
usage: irma [-h|--help] [-y|--yara-rules "<value>"] [-d|--dump "<value>"]
            [-q|--quarantine "<value>"] [-k|--kill] [-f|--faker]
            [-n|--notifications] [-v|--verbose]

            Incident Response - Minimal Analysis

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
  -n  --notifications  Use Windows notifications when a file or memory stream
                       match your YARA rules
  -v  --verbose        Display every error and information messages
``` 

## About this project and future versions
I undertook this project initially in order to learn Go. Then little by little 
I tried to understand how to use the Win32 API and finally to read the process 
memory on a Windows system. Initially focused on system oriented live forensics, 
i plan to enhance _IRMA_ functionalities with network based detection & analysis.

Further versions may contains:
* The ability to create a proxy
* Complete or selected network packets dump
* SNORT/Suricata rules analysis
* Improved detection of system behaviors
* Transfer of analysis results to a SIEM
* Agent management platform - Command and control ability

Feel free to ask for new features or create pull request if your interested in 
this project.