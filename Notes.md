# Detections for Cobalt Strike

## Windows Executable(S)
### Windows Events during execution
### Sysmon Events during execution
### ETW Events during execution

### PPID Spoofing Spawn
* detect-ppid-spoof.py detect the spawn with ppid spoofing.

### Memory Dump - Volatility 2
#### Yara
````
python vol.py -f /mnt/d/Compartida/170121.raw --profile=Win10x64_19041 yarascan -y /home/luisf/yaracobalt.yar
````
* https://github.com/lucky-luk3/cobaltstrike/blob/master/rules.yar -- DETECTED primary process and spawned.
### Malfind
````
python vol.py -f /mnt/d/Compartida/170121.raw --profile=Win10x64_19041 malfind
````
* False Positives
    * IpOverUsbSvc.e
    * MsMpEng.exe
    * SearchApp.exe
    * smartscreen.ex
    * OneDrive.exe
* DETECTED primary process and spawned.

### Netscan
````
python vol.py -f /mnt/d/Compartida/170121.raw --profile=Win10x64_19041 netscan
...
0x88840ab10010     TCPv4    192.168.129.128:49786          192.168.129.131:8081 CLOSED           -1
````
* Without good results

### psxview (finding hidden process)
* not hidden

### Handles - Mutex 
```
python vol.py -f /mnt/d/Compartida/170121.raw --profile=Win10x64_19041 handles -p 4224 -t Mutant
```
* Without results in spawned process
* In primary process
    ````
  Offset(V)             Pid             Handle             Access Type             Details
  ------------------ ------ ------------------ ------------------ ---------------- -------
  0xffff8884103bb750   4224              0x430           0x1f0001 Mutant           SM0:4224:304:WilStaging_02
  0xffff8884103bb8d0   4224              0x440           0x1f0001 Mutant           SM0:4224:120:WilError_03
    ````
### Handles - File
```
python vol.py -f /mnt/d/Compartida/170121.raw --profile=Win10x64_19041 handles -p 4224 -t File
Offset(V)             Pid             Handle             Access Type             Details
------------------ ------ ------------------ ------------------ ---------------- -------
0xffff888410372690   4224               0x40           0x100020 File             \Device\HarddiskVolume3\Users\luisf\Downloads
0xffff8884103745d0   4224               0xc4           0x100003 File             \Device\KsecDD
0xffff888410374760   4224               0xd4           0x100001 File             \Device\KsecDD
0xffff8884103748f0   4224               0xe4           0x100001 File             \Device\CNG
0xffff888410372370   4224              0x1c8           0x100080 File             \Device\Nsi
0xffff888410377640   4224              0x3e4           0x100001 File             \Device\HarddiskVolume3\Windows\System32\en-US\mswsock.dll.mui
```
* Both have handle to Download folder but only spawned "rundll32" process has a handle to "\Device\HarddiskVolume3\Windows\System32\en-US\rundll32.exe.mui"
* [idea] Search for process with handle to mswsock.dll (sockets) and suspicious locations.

### DLLs loaded
* All in system32