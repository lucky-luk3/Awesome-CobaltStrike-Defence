# Detections for Cobalt Strike
* Spawn session generates outbound connections from spawned process, inject not.
21/01/2021
* Inject in 1172 notepad.exe (x64)
* Spawn ppid spoofed 5632 rundll32.exe

## Technics
### PPID Spoofing + Process Hollowing
```
> ppid 6162
> spawnto x64 C:\Program Files\Internet Explorer\iexplore.exe
All that you launch ahead it will be executed with this ppid and this image.
> spawn x64 2
> spawnto x64 C:\ProgramFiles\Internet Explorer\iexplorer.exe
```

## Windows Executable(S)
### Windows Events during execution
Nothing
### Sysmon Events during execution
@timestamp	                    process_name	event_id	pipe_name	registry_key_path
Jan 24	 2021 @ 21:03:55.324	test.exe		3		
Jan 24	 2021 @ 21:02:55.502	test.exe		3		
Jan 24	 2021 @ 21:01:55.177	test.exe		3		
Jan 24	 2021 @ 21:00:55.083	test.exe		3		
Jan 24	 2021 @ 21:00:53.308	test.exe		12		                HKLM\System\CurrentControlSet\Services\Tcpip\Parameters	
Jan 24	 2021 @ 21:00:53.308	test.exe		12		                HKLM\System\CurrentControlSet\Services\Tcpip\Parameters	
Jan 24	 2021 @ 21:00:53.307	test.exe		12		                HKLM\System\CurrentControlSet\Services\Tcpip\Parameters	
Jan 24	 2021 @ 21:00:53.230	test.exe		18	        \MSSE-2613-server
Jan 24	 2021 @ 21:00:52.192	test.exe		17	        \MSSE-2613-server
Jan 24	 2021 @ 21:00:52.179	test.exe		1		
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

### ldrmodules
```
python vol.py -f /mnt/d/Compartida/170121.raw --profile=Win10x64_19041 ldrmodules -p 1524
Pid      Process              Base               InLoad InInit InMem MappedPath
-------- -------------------- ------------------ ------ ------ ----- ----------
    1524 rundll32.exe         0x000001f87e730000 False  False  False \Windows\System32\en-US\rundll32.exe.mui
    1524 rundll32.exe         0x000001f87e950000 False  False  False \Windows\System32\en-US\mswsock.dll.mui
    1524 rundll32.exe         0x00007ff848930000 True   True   True  \Windows\System32\imm32.dll
    1524 rundll32.exe         0x00007ff82cc30000 True   True   True  \Windows\System32\winrnr.dll
    1524 rundll32.exe         0x00007ff681b80000 True   False  True  \Windows\System32\rundll32.exe
    1524 rundll32.exe         0x00007ff846d90000 True   True   True  \Windows\System32\bcrypt.dll
    ....
```
It's weird that rundll32's pointer is not initiated. (ToDo)

## Inject session in target process
`inject <pid> x64/x86`  
```
Time                        process_name    process_target_name event_id    registry_key_path
Jan 21, 2021 @ 21:10:03.610 notepad.exe     -                   3           - 
Jan 21, 2021 @ 21:10:03.609 test.exe        -                   3           - 
Jan 21, 2021 @ 21:10:01.639 notepad.exe     -                   12          HKLM\System\CurrentControlSet\Services\Tcpip\Parameters
Jan 21, 2021 @ 21:10:01.638 notepad.exe     -                   12          HKLM\System\CurrentControlSet\Services\Tcpip\Parameters
Jan 21, 2021 @ 21:10:01.620 test.exe        notepad.exe         10          -  
```

