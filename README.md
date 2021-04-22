# IRMA - Incident Response - Minimal Analysis

## What is this project designed for?
_IRMA_ is a lightweight tool made for live forensics on Windows Platform. It is 
focused on three use cases:
* enpoint detection - live analysis, quarantine and eradication of malware on a workstation 
* live analysis & sandbox host - logging and instant notifications for malware TTP's assessment
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
* dump / quarantine suspiscious artefacts
* spawn fake analysis processes to make the computer look like an analysis platform

### Installation 
Feel free to download compiled release of this software. If you want to compile 
from sources, it could be a little bit tricky cause it's stronly depends of 
_go-yara_ and CGO compilation. You'll find a detailed documentation [here](README.windows-compilation.md)

### Usage 
```
usage: irma [-h|--help] -c|--configuration "<value>" [-b|--builder "<value>"]

            Incident Response - Minimal Analysis

Arguments:

  -h  --help           Print help information
  -c  --configuration  yaml configuration file
  -b  --builder        create a standalone launcher executable with packed
                       rules and configuration.
``` 

### Scan according to your needs
_IRMA_ embeds a configuration file in order to define which files to scan, and 
where to scan them. 

``` 
irma.exe -c configuration.yaml
``` 

### EDR, rules and configuration packing
_IRMA_ builder mode lets you create a standalone, static compiled, self-extracting 
archive. It contains irma binary, configuration file, and signatures. Hence, this 
binary could be deployed on any other system and launch without additional 
configuration.

``` 
irma.exe -c configuration.yaml -b irma-sfx-binary.exe
``` 

## About this project and future versions
I undertook this project initially in order to learn Go. Then little by little 
I tried to understand how to use the Win32 API and finally to read the process 
memory on a Windows system. Initially focused on system oriented live forensics, 
I plan to enhance _IRMA_ functionalities with network based detection & analysis.

Further versions may contains:
* SNORT/Suricata rules analysis
* Transfer of analysis results to a SIEM
* Agent management platform - Command and control ability

Feel free to ask for new features or create pull request if your interested in 
this project.
