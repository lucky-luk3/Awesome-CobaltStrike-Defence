rule CS_encrypted_beacon_x86 {
    meta:
        author = "Etienne Maynier tek@randhome.io"

    strings:
        $s1 = { fc e8 ?? 00 00 00 }
        $s2 = { 8b [1-3] 83 c? 04 [0-1] 8b [1-2] 31 }

    condition:
        $s1 at 0 and $s2 in (0..200) and filesize < 300000
}

rule CS_encrypted_beacon_x86_64 {
    meta:
        author = "Etienne Maynier tek@randhome.io"

    strings:
        $s1 = { fc 48 83 e4 f0 eb 33 5d 8b 45 00 48 83 c5 04 8b }

    condition:
        $s1 at 0 and filesize < 300000
}

rule CS_beacon_v2 {
    meta:
		author = "Etienne Maynier tek@randhome.io"
        contributor = "Luis Fco Monge https://github.com/lucky-luk3"

    strings:
		//"\\.\pipe\MSSE-"
		$p1 = {5c 5c 2e 5c 70 69 70 65 5c 4d 53 53 45 2d}
		//"\\.\pipe\status"		
		$p2 = {5c 5c 2e 5c 70 69 70 65 5c 73 74 61 74 75 73 5f} 
		//"\pipe\msagent_"
		$p3 = {5c 70 69 70 65 5c 6d 73 61 67 65 6e 74 5f}
		//"\\.\pipe\postex_"		
		$p4 = {5c 5c 2e 5c 70 69 70 65 5c 70 6f 73 74 65 78 5f} 
		
		
		$s1 = "%02d/%02d/%02d %02d:%02d:%02d" ascii
		$s2 = "%s as %s\\%s: %d" ascii
		$s3 = "Started service %s on %s" ascii
		$s4 = "beacon.dll" ascii
		$s5 = "beacon.x64.dll" ascii
		$s6 = "ReflectiveLoader" ascii
		$s7 = { 2e 2f 2e 2f 2e 2c ?? ?? 2e 2c 2e 2f }
        $s8 = { 69 68 69 68 69 6b ?? ?? 69 6b 69 68 }
		$s9 = "%s (admin)" ascii
        $s10 = "Updater.dll" ascii
        $s11 = "LibTomMath" ascii
		$s12 = "Content-Type: application/octet-stream" ascii

    condition:
        (any of ($p*) or 6 of ($s*)) and filesize < 300000
}
