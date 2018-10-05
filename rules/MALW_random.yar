/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

import "pe"
import "elf"

rule single_load_rwe
{
    meta:
        description = "Flags binaries with a single LOAD segment marked as RWE."
        family = "Stager"
        filetype = "ELF"
        hash = "711a06265c71a7157ef1732c56e02a992e56e9d9383ca0f6d98cd96a30e37299"

    condition:
        elf.number_of_segments == 1 and
        elf.segments[0].type == elf.PT_LOAD and
        elf.segments[0].flags == elf.PF_R | elf.PF_W | elf.PF_X
}

rule fake_section_headers_conflicting_entry_point_address
{
    meta:
        description = "A fake sections header has been added to the binary."
        family = "Obfuscation"
        filetype = "ELF"
        hash = "a2301180df014f216d34cec8a6a6549638925ae21995779c2d7d2827256a8447"

    condition:
        elf.type == elf.ET_EXEC and
        elf.entry_point < filesize and // file scanning only
        elf.number_of_segments > 0 and
        elf.number_of_sections > 0 and
        not
        (
            for any i in (0..elf.number_of_segments):
            (
                (elf.segments[i].offset <= elf.entry_point) and
                ((elf.segments[i].offset + elf.segments[i].file_size) >= elf.entry_point) and
                for any j in (0..elf.number_of_sections):
                (
                    elf.sections[j].offset <= elf.entry_point and
                    ((elf.sections[j].offset + elf.sections[j].size) >= elf.entry_point) and
                    (elf.segments[i].virtual_address + (elf.entry_point - elf.segments[i].offset)) ==
                    (elf.sections[j].address + (elf.entry_point - elf.sections[j].offset))
                )
            )
        )
}

rule fake_dynamic_symbols
{
    meta:
        description = "A fake dynamic symbol table has been added to the binary"
        family = "Obfuscation"
        filetype = "ELF"
        hash = "51676ae7e151a0b906c3a8ad34f474cb5b65eaa3bf40bb09b00c624747bcb241"

    condition:
        elf.type == elf.ET_EXEC and
        elf.entry_point < filesize and // file scanning only
        elf.number_of_sections > 0 and
        elf.dynamic_section_entries > 0 and
        for any i in (0..elf.dynamic_section_entries):
        (
            elf.dynamic[i].type == elf.DT_SYMTAB and
            not
            (
                for any j in (0..elf.number_of_sections):
                (
                    elf.sections[j].type == elf.SHT_DYNSYM and
                    for any k in (0..elf.number_of_segments):
                    (
                        (elf.segments[k].virtual_address <= elf.dynamic[i].val) and
                        ((elf.segments[k].virtual_address + elf.segments[k].file_size) >= elf.dynamic[i].val) and
                        (elf.segments[k].offset + (elf.dynamic[i].val - elf.segments[k].virtual_address)) == elf.sections[j].offset
                    )
                )
            )
        )
}


rule maldoc_API_hashing
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a1 = {AC 84 C0 74 07 C1 CF 0D 01 C7 EB F4 81 FF}
        $a2 = {AC 84 C0 74 07 C1 CF 07 01 C7 EB F4 81 FF}
    condition:
        any of them
}

rule maldoc_function_prolog_signature
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a1 = {55 8B EC 81 EC}
        $a2 = {55 8B EC 83 C4}
        $a3 = {55 8B EC E8}
        $a4 = {55 8B EC E9}
        $a5 = {55 8B EC EB}
    condition:
        any of them
}

rule maldoc_structured_exception_handling
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a1 = {64 8B (05|0D|15|1D|25|2D|35|3D) 00 00 00 00}
        $a2 = {64 A1 00 00 00 00}
    condition:
        any of them
}

rule maldoc_indirect_function_call_1
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {FF 75 ?? FF 55 ??}
    condition:
        for any i in (1..#a): (uint8(@a[i] + 2) == uint8(@a[i] + 5))
}

rule maldoc_indirect_function_call_2
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {FF B5 ?? ?? ?? ?? FF 95 ?? ?? ?? ??}
    condition:
        for any i in (1..#a): ((uint8(@a[i] + 2) == uint8(@a[i] + 8)) and (uint8(@a[i] + 3) == uint8(@a[i] + 9)) and (uint8(@a[i] + 4) == uint8(@a[i] + 10)) and (uint8(@a[i] + 5) == uint8(@a[i] + 11)))
}

rule maldoc_indirect_function_call_3
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {FF B7 ?? ?? ?? ?? FF 57 ??}
    condition:
        $a
}

rule maldoc_find_kernel32_base_method_1
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a1 = {64 8B (05|0D|15|1D|25|2D|35|3D) 30 00 00 00}
        $a2 = {64 A1 30 00 00 00}
    condition:
        any of them
}

rule maldoc_find_kernel32_base_method_2
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {31 ?? ?? 30 64 8B ??}
    condition:
        for any i in (1..#a): ((uint8(@a[i] + 1) >= 0xC0) and (((uint8(@a[i] + 1) & 0x38) >> 3) == (uint8(@a[i] + 1) & 0x07)) and ((uint8(@a[i] + 2) & 0xF8) == 0xA0) and (uint8(@a[i] + 6) <= 0x3F) and (((uint8(@a[i] + 6) & 0x38) >> 3) != (uint8(@a[i] + 6) & 0x07)))
}

rule maldoc_find_kernel32_base_method_3
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {68 30 00 00 00 (58|59|5A|5B|5C|5D|5E|5F) 64 8B ??}
    condition:
        for any i in (1..#a): (((uint8(@a[i] + 5) & 0x07) == (uint8(@a[i] + 8) & 0x07)) and (uint8(@a[i] + 8) <= 0x3F) and (((uint8(@a[i] + 8) & 0x38) >> 3) != (uint8(@a[i] + 8) & 0x07)))
}

rule maldoc_getEIP_method_1
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {E8 00 00 00 00 (58|59|5A|5B|5C|5D|5E|5F)}
    condition:
        $a
}

rule maldoc_getEIP_method_4
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a1 = {D9 EE D9 74 24 F4 (58|59|5A|5B|5C|5D|5E|5F)}
        $a2 = {D9 EE 9B D9 74 24 F4 (58|59|5A|5B|5C|5D|5E|5F)}
    condition:
        any of them
}

rule maldoc_OLE_file_magic_number
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {D0 CF 11 E0}
    condition:
        $a
}

rule Contains_VBE_File
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
        description = "Detect a VBE file inside a byte sequence"
        method = "Find string starting with #@~^ and ending with ^#~@"
    strings:
        $vbe = /#@~\^.+\^#~@/
    condition:
        $vbe
}

rule Check_Dlls_for_python_runtime
{
	meta:
		Author = "Wiffzack"
		Description = "Checks for common python dlls"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings:
		$dll1 = "pywintypes" wide nocase ascii
		$dll2 = "pythoncom" wide nocase ascii
		$dll3 = "python27" wide nocase ascii
		$dll4 = "KERNEL32" wide nocase ascii
		$dll5 = "MSVCR90" wide nocase ascii
	condition:
		4 of them
}

rule Check_Dlls_for_perl_runtime
{
	meta:
		Author = "Wiffzack"
		Description = "Checks for common python dlls"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings:
		$dll1 = "msvcrt" wide nocase ascii
		$dll2 = "KERNEL32" wide nocase ascii
		$dll3 = "VirtualQuery" wide nocase ascii
		$dll4 = "perl" wide nocase ascii
	condition:
		4 of them
}


rule detect_msvcrt_randomization {
    meta:
        author = "Wiffzack"
        description = "Most malware this day use random generated  distraction any stupid idiot could use a pseudo random generator so this is fuckig useless at the end of the day"
        name = "just as shit "
        URL = 185

    strings:
        $s1 = { E86E080000 }     		 // msvcrt.time
        /*$s2 = { C7042400000000 }         // srand(time(NULL));*/
        /*$s3 = { E86E080000 }             // msvcrt.srand*/
        $s4 = { E871080000 }             // msvcrt.rand
    condition:
		$s1 and $s4
}

/*         $s2 = { 648b ??30 }             // mov edx, fs:[???+0x30]*/
rule detect_msvcrt_call {
    meta:
        author = "Wiffzack"
        description = "fuck off"
        name = "just as shit "
        URL = 185

    strings:
        $s1 = { E8 ???30000 }     		 // call msvcrt._threadid+1BA
    condition:
		1 of them
}


rule detect_strange_function_call {
    meta:
        author = "Wiffzack"
        description = "fuck off"
        name = "just as shit "
        URL = 185

    strings:
        $s1 = { C74424??????????8B4424??FFD0 }     		 // void (*fp)() = wtf;
    condition:
		1 of them
}

rule detect_bullshit {
    meta:
        author = "Wiffzack"
        description = "Most malware this day use random generated  distraction any stupid idiot could use a pseudo random generator so this is fuckig useless at the end of the day"
        name = "just as shit "
        URL = 185

    strings:
        $s1 = { E8???80000 }     					  //  { ->->KERNEL32.GetSystemInfo }
        $s2 = { E8???90000  }          		          // ->->KERNEL32.GetTimeZoneInformation
		$s3	= "KERNEL32.dll" wide ascii               // msvcrt.rand
    condition:
		($s1 or $s2) and $s3
}

rule detect_bullshit2 {
    meta:
        author = "Wiffzack"
        description = "Once again someone is trying to fill the memory with crap 0x90 is suspicious crap"
        name = "just as shit "
        URL = 185

    strings:
        $s1 = { C74424??900000008D4424??890424E8???90000 }     					  //      memset(&buffer, 0x90, ???);
    condition:
		1 of them
}

rule detect_bullshit3 {
    meta:
        author = "Wiffzack"
        description = "Once again someone is trying to fill the memory with crap"
        name = "just as shit "
        URL = 185

    strings:
        $s1 = { 8B8424????????8D50??899424????????8B9424????????8910 }     					  //      ptr* = **ptr()
    condition:
		1 of them
}


rule detect_bullshit4 {
    meta:
        author = "Wiffzack"
        description = "This function is so often used that this rule has a 100% right false change"
        name = "just as shit "
        URL = 185

    strings:
        $s1 = { C74424??????????C70424????????E8???80000 }     			       //       badfile = fopen("./badfile", "w");
        $s2 = { C74424??????????C74424??????????8D4424??890424E8???????? }     //       fwrite(buffer, ???, ?, badfile);
    condition:
		2 of them
}


rule detect_bullshit5 {
    meta:
        author = "Wiffzack"
        description = "This function is so often used that this rule has a 100% right false change"
        name = "just as shit "
        URL = 185

    strings:
        $s1 = { 890424E8???80000  }     			       //       badfile = fopen("./badfile", "w");
    condition:
		1 of them
}

rule detect_bullshit6 {
    meta:
        author = "Wiffzack"
        description = "Once again someone is trying to fill the memory with crap"
        name = "just as shit "
        URL = 185

    strings:
        $s1 = { C74424??????????8D4424??890424E8???????? }     					  //      ((void(*)( ))buf)( );
    condition:
		1 of them
}

rule detect_bullshit7 {
    meta:
        author = "Wiffzack"
        description = "Shell + Injection Shellcode"
        name = "just as shit "
        URL = 185

    strings:
        $s1 = { 8B????890424A1????????FFD0 }     					  //    
		$s2 = { E89E130000 }                                          // >->KERNEL32.CreateToolhelp32Snapshot
		$s3 = { E86F130000  }   		                              // ->->KERNEL32.Process32First
    condition:
		all of them
}

rule detect_bullshit8 {
    meta:
        author = "Wiffzack"
        description = "strlen of shellcode maybe"
        name = "just as shit "
        URL = 185

    strings:
        $s1 = { C70424????????E839120000 }     					  //   ->->msvcrt.strlen  
    condition:
		all of them
}

rule detect_rename {
    meta:
        author = "Wiffzack"
        description = "strlen of shellcode maybe"
        name = "just as shit "
        URL = 185

    strings:
        $s1 = { 890424E815110000  }     					  //   >->msvcrt.rename
    condition:
		all of them
}



rule heuristic_destroyer1 {
    meta:
        author = "Wiffzack"
        description = "This function is so often used that this rule has a 100% right false change"
        name = "just as shit "
        URL = 185

    strings:
        $s1 = { C70424[500-2147483647]E8A2080000  }            //       endless long sleep
        $s2 = { E8B1080000  }     			                   //       ->->KERNEL32.GetTickCount
		$s3 = { C70424[1-255][1-255]????E8F1080000 }		   //       ->->msvcrt.malloc
    condition:
		$s1 or $s3 or ($s2 and $s1)
}

rule heuristic_destroyer2 {
    meta:
        author = "Wiffzack"
        description = "This function is so often used that this rule has a 100% right false change"
        name = "just as shit "
        URL = 185

    strings:
		$s1 = { E8AE080000 }		   //       ->->KERNEL32.CreateMutexA
		$s2 = { E8AB080000 }		   //       ->->KERNEL32.GetLastError
    condition:
		$s1 and $s2 and ( @s1[1] + 18 >= @s2[1] )
}

rule unsafe_fuction_call {
    meta:
        author = "Wiffzack"
        description = "Function which are not if not handled properly can "
        name = "just as shit "
        URL = 185

    strings:
        $s1 = { E856080000 }     			       //      >msvcrt.gets
        $s2 = { E852080000 }     			       //      >msvcrt.strcpy
        $s3 = { E88B080000 }     			       //      >->msvcrt.mbscat
        $s4 = { E88B080000 }     			       //      ->->msvcrt.sprintf
        $s5 = { E89E080000 }     			       //      ->->msvcrt.malloc	
        $s6 = { E88A080000 }     			       //      ->->msvcrt.scanf	
        $s7 = { E857080000 }     			       //      ->->msvcrt.strlen			
    condition:
		( @s5[1] + 18 >= @s1[1] ) or ( @s5[1] + 18 >= @s2[1] ) or $s3 or $s4 or ( @s5[1] + 18 >= @s6[1] ) or ( @s5[1] + 18 >= @s7[1] )
}

rule unsafe_fuction_call2 {
    meta:
        author = "Wiffzack"
        description = "Function which are not if not handled properly can "
        name = "just as shit "
        URL = 185

    strings:
        $s1 = { E835080000  }     			       //      >->msvcrt.system }
    condition:
		1 of them
}

rule shellcode_load {
    meta:
        author = "Wiffzack"
        description = "Function which are not if not handled properly can "
        name = "just as shit "
        URL = 185

    strings:
        $s1 = { B8????????FFD0    }     			       //      (*  (int(*)()) shellcode    ) ();
    condition:
		1 of them
}



rule stackoverflow_try {
    meta:
        author = "Wiffzack"
        description = "Stackoverflow loop call"
        name = "just as shit "
        URL = 185

    strings:
		$s1 = { 5589E583EC??E8F?FFFFFF }		   //       ->-> call loop
		$s2 = { 89E5B8??[1-255]????  }		           //       ->-> huge memory
    condition:
		1 of them
}

rule heapbased_overflow {
    meta:
        author = "Wiffzack"
        description = "Stackoverflow loop call"
        name = "just as shit "
        URL = 185

    strings:
		$s1 = { C70424????????E855080000 }		   //   
		$s2 = { 894424??C7442404????????8B4424??890424 }		   //   
		$s3 = { E845080000 }		   //   		
    condition:
		all of them
}

rule new_address_calculation {
    meta:
        author = "Wiffzack"
        description = "Function which are not if not handled properly can "
        name = "just as shit "
        URL = 185

    strings:
        $s1 = { 8B5424??8B4424??29C289D0894424??  }     			                           //      new address calculation
        $s2 = { C605????????000FB605????????0FB6C0894424??836C24????8B4424??A2????????  }      //      new address calculation
    condition:
		1 of them
}

rule tcache_poisoning_attack {
    meta:
        author = "Wiffzack"
        description = "Function which are not if not handled properly can "
        name = "just as shit "
        URL = 185

    strings:
        $s1 = { C70424????????E8????????  }                        //      new address calculation
        $s2 = { 894424??8B4424??890424E8????????  }                //      new address calculation
		$s3 = { 8D5424??8B4424??8910C70424????????E8????????  }
    condition:
		all of them
}

rule Dangling_pointer {
    meta:
        author = "Wiffzack"
        description = "Function which are not if not handled properly can "
        name = "just as shit "
        URL = 185

    strings:
        $s1 = { E856080000  }                                              //      ->->msvcrt.malloc 
        $s2 = { 894424??8B4424??890424E84E080000  }                        //      ->->msvcrt.free
		$s3 = { C74424??00000000  }                                       //      pointer = NULL;
    condition:
		( @s2[1] + 18 >= @s1[1] ) and not ( @s3[1] > @s2[1] )
}




rule hide_console_or_window {
    meta:
        author = "Wiffzack"
        description = "Stackoverflow loop call"
        name = "just as shit "
        URL = 185

    strings:
		$s1 = { E8 D00B0000 }		   				                                   //       ->->KERNEL32.GetTempPathA
		$s2 = { C7 44 24 ?? 00000000 8? ?? ?? 89 04 24 E8 ????????    }		           //       ShowWindow( hWnd, SW_HIDE );
    condition:
		all of them
}


rule load_dsound{
    meta:
        author = "Wiffzack"
        description = "Check if maybe d3d? is loaded"
    strings:
		$s1 = { 488D?????????? }		         //       lea
		$s2 = "dsound.dll" wide nocase ascii
    condition:
		all of them
}

rule load_ddraw{
    meta:
        author = "Wiffzack"
        description = "Check if maybe d3d? is loaded"
    strings:
		$s1 = { 488D?????????? }		         //       lea
		$s2 = "ddraw.dll" wide nocase ascii
    condition:
		all of them
}


rule load_d3d9 {
    meta:
        author = "Wiffzack"
        description = "Check if maybe d3d? is loaded"
    strings:
		$s1 = { 488D?????????? }		         //       lea
		$s2 = "d3d9.dll" wide nocase ascii
    condition:
		all of them
}

rule load_d3d10 {
    meta:
        author = "Wiffzack"
        description = "Check if maybe d3d? is loaded"
    strings:
		$s1 = { 488D?????????? }		         //       lea
		$s2 = "d3d10.dll" wide nocase ascii
    condition:
		all of them
}


rule load_d3d11 {
    meta:
        author = "Wiffzack"
        description = "Check if maybe d3d? is loaded"
    strings:
		$s1 = { 488D?????????? }		         //       lea
		$s2 = "d3d11.dll" wide nocase ascii
    condition:
		all of them
}

rule load_sdl{
    meta:
        author = "Wiffzack"
        description = "Check if maybe d3d? is loaded"
    strings:
		$s1 = { 488D?????????? }		         //       lea
		$s2 = "SDL.dll" wide nocase ascii
		$s3 = "SDL2.dll" wide nocase ascii
    condition:
		$s1 and ($s2 or $s3)
}

rule IP {
    meta:
        author = "Antonio S. <asanchez@plutec.net>"
    strings:
        $ip = /([0-9]{1,3}\.){3}[0-9]{1,3}/ wide ascii
    condition:
        $ip
}

rule hook_check {
    meta:
        author = "Wiffzack"
        description = "Check for usually hooked func"
    strings:
		$s1 = "NTDLL.DLL" wide nocase ascii
		$s2 = "ADVAPI32.DLL" wide nocase ascii
		$s3 = "WS2_32.DLL" wide nocase ascii
		$s4 = "SECUR32.DLL" wide nocase ascii
		$s5 = "NtResumeThread" wide nocase ascii
		$s6 = "LdrLoadDll" wide nocase ascii
		$s7 = "LdrUnloadDll" wide nocase ascii
		$s8 = "NtQuerySystemInformation" wide nocase ascii
		$s9 = "NtQueryDirectoryFile" wide nocase ascii
		$s10 = "NtVdmControl" wide nocase ascii
		$s11 = "NtDeviceIoControlFile" wide nocase ascii
		$s12 = "NtEnumerateKey" wide nocase ascii
		$s13 = "NtEnumerateValueKey" wide nocase ascii
		$s14 = "NtQueryVolumeInformationFile" wide nocase ascii
		$s15 = "NtOpenFile" wide nocase ascii
		$s16 = "NtCreateFile" wide nocase ascii
		$s17 = "NtReadFile" wide nocase ascii
		$s18 = "NtOpenProcess" wide nocase ascii
		$s19 = "NtSaveKey" wide nocase ascii
		$s20 = "NtSaveMergedKeys" wide nocase ascii
		$s21 = "EnumServicesStatusA" wide nocase ascii
		$s22 = "EnumServiceGroupW" wide nocase ascii
		$s23 = "EnumServicesStatusExA" wide nocase ascii
		$s24 = "EnumServicesStatusExW" wide nocase ascii
		$s25 = "recv" wide nocase ascii
		$s26 = "WSARecv" wide nocase ascii
		$s27 = "LsaLogonUser" wide nocase ascii
    condition:
		$s1 and ($s5 or $s6 or $s7 or $s8 or $s9 or $s10 or $s11 or $s12 or $s13 or $s14 or $s15 or $s16 or $s17 or $s18 or $s19 or $s20) or $s2 and ($s21 or $s22 or $s23 or $s24) or $s3 and ($s25 or $s26) or $s4 and $s27
}


rule GEN_PowerShell 
{

    meta:
        description = "Generic PowerShell Malware Rule"
        author = "https://github.com/interleaved"
    
    strings:
        $s1 = "powershell"
        $s2 = "-ep bypass" nocase
        $s3 = "-nop" nocase
        $s10 = "-executionpolicy bypass" nocase
        $s4 = "-win hidden" nocase
        $s5 = "-windowstyle hidden" nocase
        $s11 = "-w hidden" nocase
        /*$s6 = "-noni" fullword ascii*/
        /*$s7 = "-noninteractive" fullword ascii*/
        $s8 = "-enc" nocase
        $s9 = "-encodedcommand" nocase
    
    condition:
        $s1 and (($s2 or $s3 or $s10) and ($s4 or $s5 or $s11) and ($s8 or $s9))
}

rule Msfpayloads_msf {
   meta:
      description = "Metasploit Payloads - file msf.sh"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "320a01ec4e023fb5fbbaef963a2b57229e4f918847e5a49c7a3f631cb556e96c"
   strings:
      $s1 = "export buf=\\" fullword ascii
   condition:
      ( uint16(0) == 0x7865 and filesize < 4KB and ( 10 of ($s*) ) ) or ( all of them )
}

rule Msfpayloads_msf_2 {
   meta:
      description = "Metasploit Payloads - file msf.asp"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "e52f98466b92ee9629d564453af6f27bd3645e00a9e2da518f5a64a33ccf8eb5"
   strings:
      $s1 = "& \"\\\" & \"svchost.exe\"" fullword ascii
      $s2 = "CreateObject(\"Wscript.Shell\")" fullword ascii
      $s3 = "<% @language=\"VBScript\" %>" fullword ascii
   condition:
      all of them
}

rule Msfpayloads_msf_psh {
   meta:
      description = "Metasploit Payloads - file msf-psh.vba"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "5cc6c7f1aa75df8979be4a16e36cece40340c6e192ce527771bdd6463253e46f"
   strings:
      $s1 = "powershell.exe -nop -w hidden -e" ascii
      $s2 = "Call Shell(" fullword ascii
      $s3 = "Sub Workbook_Open()" fullword ascii
   condition:
      all of them
}

rule Msfpayloads_msf_exe {
   meta:
      description = "Metasploit Payloads - file msf-exe.vba"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "321537007ea5052a43ffa46a6976075cee6a4902af0c98b9fd711b9f572c20fd"
   strings:
      $s1 = "'* PAYLOAD DATA" fullword ascii
      $s2 = " = Shell(" ascii
      $s3 = "= Environ(\"USERPROFILE\")" fullword ascii
      $s4 = "'**************************************************************" fullword ascii
      $s5 = "ChDir (" fullword ascii
      $s6 = "'* MACRO CODE" fullword ascii
   condition:
      4 of them
}

rule Msfpayloads_msf_3 {
   meta:
      description = "Metasploit Payloads - file msf.psh"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "335cfb85e11e7fb20cddc87e743b9e777dc4ab4e18a39c2a2da1aa61efdbd054"
   strings:
      $s1 = "[DllImport(\"kernel32.dll\")] public static extern int WaitForSingleObject(" ascii
      $s2 = "public enum MemoryProtection { ExecuteReadWrite = 0x40 }" fullword ascii
      $s3 = ".func]::VirtualAlloc(0,"
      $s4 = ".func+AllocationType]::Reserve -bOr [" ascii
      $s5 = "New-Object System.CodeDom.Compiler.CompilerParameters" fullword ascii
      $s6 = "ReferencedAssemblies.AddRange(@(\"System.dll\", [PsObject].Assembly.Location))" fullword ascii
      $s7 = "public enum AllocationType { Commit = 0x1000, Reserve = 0x2000 }" fullword ascii
      $s8 = ".func]::CreateThread(0,0,$" fullword ascii
      $s9 = "public enum Time : uint { Infinite = 0xFFFFFFFF }" fullword ascii
      $s10 = "= [System.Convert]::FromBase64String(\"/" ascii
      $s11 = "{ $global:result = 3; return }" fullword ascii
   condition:
      4 of them
}

rule Msfpayloads_msf_4 {
   meta:
      description = "Metasploit Payloads - file msf.aspx"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "26b3e572ba1574164b76c6d5213ab02e4170168ae2bcd2f477f246d37dbe84ef"
   strings:
      $s1 = "= VirtualAlloc(IntPtr.Zero,(UIntPtr)" ascii
      $s2 = ".Length,MEM_COMMIT, PAGE_EXECUTE_READWRITE);" ascii
      $s3 = "[System.Runtime.InteropServices.DllImport(\"kernel32\")]" fullword ascii
      $s4 = "private static IntPtr PAGE_EXECUTE_READWRITE=(IntPtr)0x40;" fullword ascii
      $s5 = "private static extern IntPtr VirtualAlloc(IntPtr lpStartAddr,UIntPtr size,Int32 flAllocationType,IntPtr flProtect);" fullword ascii
   condition:
      4 of them
}

rule Msfpayloads_msf_exe_2 {
   meta:
      description = "Metasploit Payloads - file msf-exe.aspx"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "3a2f7a654c1100e64d8d3b4cd39165fba3b101bbcce6dd0f70dae863da338401"
   strings:
      $x1 = "= new System.Diagnostics.Process();" fullword ascii
      $x2 = ".StartInfo.UseShellExecute = true;" fullword ascii
      $x3 = ", \"svchost.exe\");" ascii
      $s4 = " = Path.GetTempPath();" ascii
   condition:
      all of them
}

rule Msfpayloads_msf_5 {
   meta:
      description = "Metasploit Payloads - file msf.msi"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "7a6c66dfc998bf5838993e40026e1f400acd018bde8d4c01ef2e2e8fba507065"
   strings:
      $s1 = "required to install Foobar 1.0." fullword ascii
      $s2 = "Copyright 2009 The Apache Software Foundation." fullword wide
      $s3 = "{50F36D89-59A8-4A40-9689-8792029113AC}" fullword ascii
   condition:
      all of them
}

rule Msfpayloads_msf_6 {
   meta:
      description = "Metasploit Payloads - file msf.vbs"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "8d6f55c6715c4a2023087c3d0d7abfa21e31a629393e4dc179d31bb25b166b3f"
   strings:
      $s1 = "= CreateObject(\"Wscript.Shell\")" fullword ascii
      $s2 = "= CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
      $s3 = ".GetSpecialFolder(2)" ascii
      $s4 = ".Write Chr(CLng(\"" ascii
      $s5 = "= \"4d5a90000300000004000000ffff00" ascii
      $s6 = "For i = 1 to Len(" ascii
      $s7  = ") Step 2" ascii
   condition:
      5 of them
}

rule Msfpayloads_msf_7 {
   meta:
      description = "Metasploit Payloads - file msf.vba"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "425beff61a01e2f60773be3fcb74bdfc7c66099fe40b9209745029b3c19b5f2f"
   strings:
      $s1 = "Private Declare PtrSafe Function CreateThread Lib \"kernel32\" (ByVal" ascii
      $s2 = "= VirtualAlloc(0, UBound(Tsw), &H1000, &H40)" fullword ascii
      $s3 = "= RtlMoveMemory(" ascii
   condition:
      all of them
}

rule Msfpayloads_msf_8 {
   meta:
      description = "Metasploit Payloads - file msf.ps1"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "519717e01f0cb3f460ef88cd70c3de8c7f00fb7c564260bd2908e97d11fde87f"
   strings:
      $s1 = "[DllImport(\"kernel32.dll\")]" fullword ascii
      $s2 = "[DllImport(\"msvcrt.dll\")]" fullword ascii
      $s3 = "-Name \"Win32\" -namespace Win32Functions -passthru" fullword ascii
      $s4 = "::VirtualAlloc(0,[Math]::Max($" ascii
      $s5 = ".Length,0x1000),0x3000,0x40)" ascii
      $s6 = "public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);" fullword ascii
      $s7 = "::memset([IntPtr]($" ascii
   condition:
      6 of them
}

rule Msfpayloads_msf_cmd {
   meta:
      description = "Metasploit Payloads - file msf-cmd.ps1"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "9f41932afc9b6b4938ee7a2559067f4df34a5c8eae73558a3959dd677cb5867f"
   strings:
      $x1 = "%COMSPEC% /b /c start /b /min powershell.exe -nop -w hidden -e" ascii
   condition:
      all of them
}

rule Msfpayloads_msf_9 {
   meta:
      description = "Metasploit Payloads - file msf.war - contents"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "e408678042642a5d341e8042f476ee7cef253871ef1c9e289acf0ee9591d1e81"
   strings:
      $s1 = "if (System.getProperty(\"os.name\").toLowerCase().indexOf(\"windows\") != -1)" fullword ascii
      $s2 = ".concat(\".exe\");" fullword ascii
      $s3 = "[0] = \"chmod\";" ascii
      $s4 = "= Runtime.getRuntime().exec(" ascii
      $s5 = ", 16) & 0xff;" ascii

      $x1 = "4d5a9000030000000" ascii
   condition:
      4 of ($s*) or $x1 at 0
}

rule Msfpayloads_msf_10 {
   meta:
      description = "Metasploit Payloads - file msf.exe"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "3cd74fa28323c0d64f45507675ac08fb09bae4dd6b7e11f2832a4fbc70bb7082"
   strings:
      $s1 = { 0c 8b 52 14 8b 72 28 0f b7 4a 26 31 ff ac 3c 61 }
      $s2 = { 01 c7 38 e0 75 f6 03 7d f8 3b 7d 24 75 e4 58 8b }
      $s3 = { 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0 5f 5f }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}

rule Msfpayloads_msf_svc {
   meta:
      description = "Metasploit Payloads - file msf-svc.exe"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "2b02c9c10577ee0c7590d3dadc525c494122747a628a7bf714879b8e94ae5ea1"
   strings:
      $s1 = "PAYLOAD:" fullword ascii
      $s2 = ".exehll" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 50KB and all of them )
}

rule Msfpayloads_msf_11 {
   meta:
      description = "Metasploit Payloads - file msf.hta"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "d1daf7bc41580322333a893133d103f7d67f5cd8a3e0f919471061d41cf710b6"
   strings:
      $s1 = ".ExpandEnvironmentStrings(\"%PSModulePath%\") + \"..\\powershell.exe\") Then" fullword ascii
      $s2 = "= CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
      $s3 = "= CreateObject(\"Wscript.Shell\") " fullword ascii
   condition:
      all of them
}

rule Msfpayloads_msf_ref {
   meta:
      description = "Metasploit Payloads - file msf-ref.ps1"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "4ec95724b4c2b6cb57d2c63332a1dd6d4a0101707f42e3d693c9aab19f6c9f87"
   strings:
      $s1 = "kernel32.dll WaitForSingleObject)," ascii
      $s2 = "= ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\\\')" ascii
      $s3 = "GetMethod('GetProcAddress').Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object" ascii
      $s4 = ".DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual'," ascii
      $s5 = "= [System.Convert]::FromBase64String(" ascii
      $s6 = "[Parameter(Position = 0, Mandatory = $True)] [Type[]]" fullword ascii
      $s7 = "DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard," ascii
   condition:
      5 of them
}

rule meterpreter_reverse_tcp_shellcode {
    meta:
        author = "FDD @ Cuckoo sandbox"
        description = "Rule for metasploit's  meterpreter reverse tcp raw shellcode"

    strings:
        $s1 = { fce8 8?00 0000 60 }     // shellcode prologe in metasploit
        $s2 = { 648b ??30 }             // mov edx, fs:[???+0x30]
        $s3 = { 4c77 2607 }             // kernel32 checksum
        $s4 = "ws2_"                    // ws2_32.dll
        $s5 = { 2980 6b00 }             // WSAStartUp checksum
        $s6 = { ea0f dfe0 }             // WSASocket checksum
        $s7 = { 99a5 7461 }             // connect checksum

    condition:
        all of them and filesize < 5KB
}

rule meterpreter_reverse_tcp_shellcode_rev1 {
    meta:
        author = "FDD @ Cuckoo sandbox"
        description = "Meterpreter reverse TCP shell rev1"
        LHOST = 0xae
        LPORT = 0xb5

    strings:
        $s1 = { 6a00 53ff d5 }

    condition:
        meterpreter_reverse_tcp_shellcode and $s1 in (270..filesize)
}

rule meterpreter_reverse_tcp_shellcode_rev2 {
    meta:
        author = "FDD @ Cuckoo sandbox"
        description = "Meterpreter reverse TCP shell rev2"
        LHOST = 194
        LPORT = 201

    strings:
        $s1 = { 75ec c3 }

    condition:
        meterpreter_reverse_tcp_shellcode and $s1 in (270..filesize)
}

rule meterpreter_reverse_tcp_shellcode_domain {
    meta:
        author = "FDD @ Cuckoo sandbox"
        description = "Variant used if the user specifies a domain instead of a hard-coded IP"

    strings:
        $s1 = { a928 3480 }             // Checksum for gethostbyname
        $domain = /(\w+\.)+\w{2,6}/

    condition:
        meterpreter_reverse_tcp_shellcode and all of them
}

rule metasploit_download_exec_shellcode_rev1 {
    meta:
        author = "FDD @ Cuckoo Sandbox"
        description = "Rule for metasploit's download and exec shellcode"
        name = "Metasploit download & exec payload"
        URL = 185

    strings:
        $s1 = { fce8 8?00 0000 60 }     // shellcode prologe in metasploit
        $s2 = { 648b ??30 }             // mov edx, fs:[???+0x30]
        $s4 = { 4c77 2607 }             // checksum for LoadLibraryA
        $s5 = { 3a56 79a7 }             // checksum for InternetOpenA
        $s6 = { 5789 9fc6 }             // checksum for InternetConnectA
        $s7 = { eb55 2e3b }             // checksum for HTTPOpenRequestA
        $s8 = { 7546 9e86 }             // checksum for InternetSetOptionA
        $s9 = { 2d06 187b }             // checksum for HTTPSendRequestA
        $url = /\/[\w_\-\.]+/

    condition:
        all of them and filesize < 5KB
}

rule metasploit_download_exec_shellcode_rev2 {
    meta:
        author = "FDD @ Cuckoo Sandbox"
        description = "Rule for metasploit's download and exec shellcode"
        name = "Metasploit download & exec payload"
        URL = 185

    strings:
        $s1 = { fce8 8?00 0000 60 }     // shellcode prologe in metasploit
        $s2 = { 648b ??30 }             // mov edx, fs:[???+0x30]
        $s4 = { 4c77 2607 }             // checksum for LoadLibraryA
        $s5 = { 3a56 79a7 }             // checksum for InternetOpenA
        $s6 = { 5789 9fc6 }             // checksum for InternetConnectA
        $s7 = { eb55 2e3b }             // checksum for HTTPOpenRequestA
        $s9 = { 2d06 187b }             // checksum for HTTPSendRequestA
        $url = /\/[\w_\-\.]+/

    condition:
        all of them and filesize < 5KB
}

rule metasploit_bind_shell {
    meta:
        author = "FDD @ Cuckoo Sandbox"
        description = "Rule for metasploit's bind shell shellcode"
        name = "Metasploit bind shell payload"

    strings:
        $s1 = { fce8 8?00 0000 60 }     // shellcode prologe in metasploit
        $s2 = { 648b ??30 }             // mov edx, fs:[???+0x30]
        $s3 = { 4c77 2607 }             // checksum for LoadLibraryA
        $s4 = { 2980 6b00 }             // checksum for WSAStartup
        $s5 = { ea0f dfe0 }             // checksum for WSASocketA
        $s6 = { c2db 3767 }             // checksum for bind
        $s7 = { b7e9 38ff }             // checksum for listen
        $s8 = { 74ec 3be1 }             // checksum for accept

    condition:
        all of them and filesize < 5KB
}

rule Meterpreter_Reverse_Tcp 
{ 
  meta: // This is the standard backdoor/RAT from Metasploit, could be used by any actor 
    author = "chort (@chort0)" 
    description = "Meterpreter reverse TCP backdoor in memory. Tested on Win7x64." 
  strings: 
    $a = { 4d 45 54 45 52 50 52 45 54 45 52 5f 54 52 41 4e 53 50 4f 52 54 5f 53 53 4c [32-48] 68 74 74 70 73 3a 2f 2f 58 58 58 58 58 58 } // METERPRETER_TRANSPORT_SSL … https://XXXXXX 
    $b = { 4d 45 54 45 52 50 52 45 54 45 52 5f 55 41 } // METERPRETER_UA 
    $c = { 47 45 54 20 2f 31 32 33 34 35 36 37 38 39 20 48 54 54 50 2f 31 2e 30 } // GET /123456789 HTTP/1.0 
    $d = { 6d 65 74 73 72 76 2e 64 6c 6c [2-4] 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 } // metsrv.dll … ReflectiveLoader 
    
  condition: 
    $a or (any of ($b, $d) and $c) 
}


rule _WATCOM_CCpp_32_RunTime_System_19881994_
{
	meta:
		description = "WATCOM C/C++ 32 Run-Time System 1988-1994"
	strings:
		$0 = {E9 57}
	condition:
		$0 at entrypoint
}
rule _Borland_Delphi_v60_
{
	meta:
		description = "Borland Delphi v6.0"
	strings:
		$0 = {55 8B EC 83 C4 F0 B8 45 ?? E8 FF A1 45 ?? 8B ?? E8 FF FF 8B}
		$1 = {55 8B EC 83 C4 F0 B8 40 ?? E8 FF FF A1 72 40 ?? 33 D2 E8 FF FF A1 72 40 ?? 8B ?? 83 C0 14 E8 FF FF E8 FF}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Microsoft_Visual_Cpp_
{
	meta:
		description = "Microsoft Visual C++"
	strings:
		$0 = {8B 44 24 08 83}
		$1 = {53 56 57 BB 8B 55 3B FB}
		$2 = {FF FF FF ?? ?? ?? ?? ?? ?? 30 ?? ?? ??}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}
rule _Cygwin32_
{
	meta:
		description = "Cygwin32"
	strings:
		$0 = {6A FF 15}
	condition:
		$0 at entrypoint
}
rule _Borland_Cpp_for_Win32_1995_
{
	meta:
		description = "Borland C++ for Win32 1995"
	strings:
		$0 = {A1 C1 A3 83 75 80}
		$1 = {EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 A1 C1 E0 02 A3}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Microsoft_Visual_Cpp_v42_
{
	meta:
		description = "Microsoft Visual C++ v4.2"
	strings:
		$0 = {64 A1 ?? ?? ?? ?? 55 8B EC 6A FF 68 68 50 64 83 53 56 57 89}
		$1 = {53 B8 8B 56 57 85 DB 55}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _MinGW_v32x__mainCRTStartup_
{
	meta:
		description = "MinGW v3.2.x (_mainCRTStartup)"
	strings:
		$0 = {E8 FF FF E8 FF}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Basic_v50_
{
	meta:
		description = "Microsoft Visual Basic v5.0"
	strings:
		$0 = {68}
	condition:
		$0 at entrypoint
}
rule _FASM_v13x_
{
	meta:
		description = "FASM v1.3x"
	strings:
		$0 = {E8 ?? 6E ?? ?? 55 89 E5 8B 7D 0C 8B 75 08 89 F8 8B 5D 10}
	condition:
		$0 at entrypoint
}
rule _LCC_Win32_DLL_
{
	meta:
		description = "LCC Win32 DLL"
	strings:
		$0 = {8B 44 24 08 56 83 E8 74 48}
	condition:
		$0 at entrypoint
}
rule _Borland_Delphi_v60_KOL_
{
	meta:
		description = "Borland Delphi v6.0 KOL"
	strings:
		$0 = {55 8B EC 83 C4 53 56 57 33 C0 89 45 F0 89 45 D4 89 45 D0}
	condition:
		$0 at entrypoint
}
rule _LCC_Win32_v1x_
{
	meta:
		description = "LCC Win32 v1.x"
	strings:
		$0 = {55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 FF 75 10 FF 75 0C FF 75 08}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Cpp_v60_SPx_
{
	meta:
		description = "Microsoft Visual C++ v6.0 SPx"
	strings:
		$0 = {55 8B EC 83 EC 44 56 FF 15 6A 01 8B F0 FF}
		$1 = {55 8B EC 6A FF 68 68 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 53 56}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Microsoft_Visual_Cpp_v60_DLL_
{
	meta:
		description = "Microsoft Visual C++ v6.0 DLL"
	strings:
		$0 = {83 7C 24 08 01 75 09 8B 44 24 04 A3 ?? 10 E8 8B FF FF}
		$1 = {55 8B EC 83 EC 50 53 56 57 BE 8D 7D F4 A5 A5 66 A5}
		$2 = {55 8B EC 53 8B 5D 08 56 8B 75}
		$3 = {0D ??}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint or $3 at entrypoint
}
rule _Free_Pascal_v09910_
{
	meta:
		description = "Free Pascal v0.99.10"
	strings:
		$0 = {64 A1 55 89 E5 6A FF 68 68 9A 10 40}
	condition:
		$0 at entrypoint
}
rule _Borland_Delphi_vxx_Component_
{
	meta:
		description = "Borland Delphi vx.x (Component)"
	strings:
		$0 = {55 8B EC 83 C4 B4 B8 E8 E8 8D}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Cpp_v50v60_MFC_
{
	meta:
		description = "Microsoft Visual C++ v5.0/v6.0 (MFC)"
	strings:
		$0 = {55 8B EC ??}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_C_v70__Basic_NET_
{
	meta:
		description = "Microsoft Visual C# v7.0 / Basic .NET"
	strings:
		$0 = {53 55 56 8B 74 24 14 85 F6 57 B8}
	condition:
		$0 at entrypoint
}
rule _MinGW_GCC_DLL_v2xx_
{
	meta:
		description = "MinGW GCC DLL v2xx"
	strings:
		$0 = {55 89 E5 83 EC 18 89 75 FC 8B 75 0C 89 5D F8 83 FE 01 74 5C 89 74 24 04 8B 55 10 89 54 24 08 8B 55 08 89 14 24 E8 96 01 ?? ?? 83 EC 0C 83 FE 01 89 C3 74 2C 85 F6 75 0C 8B 0D ?? 30 ?? 10 85}
	condition:
		$0 at entrypoint
}
rule _Borland_Delphi_v60__v70_
{
	meta:
		description = "Borland Delphi v6.0 - v7.0"
	strings:
		$0 = {E8 6A E8 89 05 E8 89 05 C7 05 0A B8}
		$1 = {53 8B D8 33 C0 A3 ?? 6A ?? E8 ?? FF A3 ?? A1 ?? A3 ?? 33 C0 A3 ?? 33 C0 A3 ??}
		$2 = {55 8B EC B9 6A ?? 6A ??}
		$3 = {55 8B EC 83 C4 F0 B8 E8 FB FF A1 8B E8 FF FF 8B 0D A1 8B ?? 8B 15 E8 FF FF A1 8B E8 FF}
		$4 = {55 8B EC}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint or $3 at entrypoint or $4 at entrypoint
}
rule _Borland_Delphi_Component_
{
	meta:
		description = "Borland Delphi (Component)"
	strings:
		$0 = {55 89 E5 83 EC 04 83}
	condition:
		$0 at entrypoint
}
rule _Borland_Delphi_v20_
{
	meta:
		description = "Borland Delphi v2.0"
	strings:
		$0 = {50 6A E8 FF FF BA 52 89 05 89 42 04 E8 5A 58 E8 C3 55 8B EC 33}
	condition:
		$0 at entrypoint
}
rule _Borland_Pascal_v70_for_Windows_
{
	meta:
		description = "Borland Pascal v7.0 for Windows"
	strings:
		$0 = {A1 C1 A3 83 75 57 51 33 C0}
	condition:
		$0 at entrypoint
}
rule _Borland_Delphi_v40__v50_
{
	meta:
		description = "Borland Delphi v4.0 - v5.0"
	strings:
		$0 = {55 8B EC 83}
		$1 = {50 6A ?? E8 FF FF BA 52 89 05 89 42 04 C7 42 08 ?? ?? ?? ?? C7 42 0C ?? ?? ?? ?? E8 5A 58 E8}
		$2 = {BA 83 7D 0C 01 75 50 52 C6 05 8B 4D 08 89 0D 89 4A}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}
rule _Borland_Delphi_v30_
{
	meta:
		description = "Borland Delphi v3.0"
	strings:
		$0 = {55 8B EC 83}
		$1 = {50 6A E8 FF FF BA 52 89 05 89 42 04 C7 42 08 C7 42 0C E8 5A 58 E8}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _MinGW_v32x_WinMain_
{
	meta:
		description = "MinGW v3.2.x (WinMain)"
	strings:
		$0 = {55 89 E5 83 EC 08 6A ?? 6A ?? 6A ?? 6A ?? E8 0D ?? ?? ?? B8 ?? ?? ?? ?? C9 C3 90 90 90 90 90 90 FF 25 38 20 ?? 10 90 90 ?? ?? ?? ?? ?? ?? ?? ?? FF FF FF FF ?? ?? ?? ?? FF FF FF}
	condition:
		$0 at entrypoint
}
rule _Borland_Delphi_Setup_Module_
{
	meta:
		description = "Borland Delphi Setup Module"
	strings:
		$0 = {55 8B EC 83 C4}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Basic_v60_DLL_
{
	meta:
		description = "Microsoft Visual Basic v6.0 DLL"
	strings:
		$0 = {55 89 E5 E8 C9 C3 45 58}
	condition:
		$0 at entrypoint
}
rule _WATCOM_CCpp_
{
	meta:
		description = "WATCOM C/C++"
	strings:
		$0 = {53 56 57 55 8B 74 24 14 8B 7C 24 18 8B 6C 24 1C 83 FF 03 0F}
	condition:
		$0 at entrypoint
}
rule _MinGW_v32x_Dll_WinMain_
{
	meta:
		description = "MinGW v3.2.x (Dll_WinMain)"
	strings:
		$0 = {55 89 E5 83 EC 08 C7 04 24 01 ?? ?? ?? FF 15 E4 40 40 ?? E8 68 ?? ?? ?? 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 C7 04 24 02 ?? ?? ?? FF 15 E4 40 40 ?? E8 48 ?? ?? ?? 89 EC 31 C0 5D C3 89}
	condition:
		$0 at entrypoint
}
rule _Borland_Delphi_v50_KOL_
{
	meta:
		description = "Borland Delphi v5.0 KOL"
	strings:
		$0 = {53 8B D8 33 C0 A3 6A ?? E8 FF A3 A1 A3 33 C0 A3 33 C0 A3}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Cpp_DLL_
{
	meta:
		description = "Microsoft Visual C++ DLL"
	strings:
		$0 = {53 56 57 BB 01 8B 24}
		$1 = {53 B8 01 ?? ?? ?? 8B 5C 24 0C 56 57 85 DB 55 75 12 83 3D 75 09 33}
		$2 = {55 8B EC 56 57 BF 01 ?? ?? ?? 8B 75}
		$3 = {55 8B EC 6A FF 68 68 64 A1 ?? ?? ?? ?? 50 64 89}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint or $3 at entrypoint
}
rule _Microsoft_Visual_C_v20_
{
	meta:
		description = "Microsoft Visual C v2.0"
	strings:
		$0 = {55 8B EC 56 57 BF 8B 3B F7}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Cpp_v42_DLL_
{
	meta:
		description = "Microsoft Visual C++ v4.2 DLL"
	strings:
		$0 = {55 8B EC 6A FF 68 68 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 53 56}
	condition:
		$0 at entrypoint
}
rule _MinGW_v32x_Dll_main_
{
	meta:
		description = "MinGW v3.2.x (Dll_main)"
	strings:
		$0 = {55 89 E5 83 EC 18 89 75 FC 8B 75 0C 89 5D F8 83 FE 01 74 5C 89 74 24 04 8B 55 10 89 54 24 08 8B 55 08 89 14 24 E8 76 01 ?? ?? 83 EC 0C 83 FE 01 89 C3 74 2C 85 F6 75 0C 8B 0D ?? 30 ?? 10 85}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Cpp_v70_
{
	meta:
		description = "Microsoft Visual C++ v7.0"
	strings:
		$0 = {6A 68}
		$1 = {55 8D 6C 81 EC 8B 45 83 F8 01 56 0F 84 85 C0 0F}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _WATCOM_CCpp_32_RunTime_System_19881995_
{
	meta:
		description = "WATCOM C/C++ 32 Run-Time System 1988-1995"
	strings:
		$0 = {FB 83 89 E3 89 89 66 66 BB 29 C0 B4 30 CD}
	condition:
		$0 at entrypoint
}
rule _Borland_Delphi_v50_KOLMCK_
{
	meta:
		description = "Borland Delphi v5.0 KOL/MCK"
	strings:
		$0 = {55 8B EC 83 C4 F0 B8 40 ?? E8 FF FF E8 FF FF E8 FF FF 8B}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Cpp_vxx_
{
	meta:
		description = "Microsoft Visual C++ vx.x"
	strings:
		$0 = {53 55 56 8B 85 F6 57 B8 75 8B 85 C9 75 33 C0 5F 5E 5D 5B}
		$1 = {64 A1 ?? ?? ?? ?? 55 8B EC 6A FF 68 68 50 64 89 25 ?? ?? ?? ?? 83 EC 53 56}
		$2 = {55 8B EC 83 EC 44 56 FF 15 8B F0 8A 3C}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}
rule _Stranik_13_ModulaCPascal_
{
	meta:
		description = "Stranik 1.3 Modula/C/Pascal"
	strings:
		$0 = {E9 57 41 54 43 4F 4D 20 43 2F 43 2B 2B 33 32 20 52 75 6E 2D}
	condition:
		$0 at entrypoint
}
rule _Borland_Cpp_for_Win32_1994_
{
	meta:
		description = "Borland C++ for Win32 1994"
	strings:
		$0 = {A1 C1 A3 57 51 33 C0 BF B9 3B CF}
	condition:
		$0 at entrypoint
}
rule _Borland_Delphi_DLL_
{
	meta:
		description = "Borland Delphi DLL"
	strings:
		$0 = {55 8B EC 83}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Cpp_v60_Debug_Version_
{
	meta:
		description = "Microsoft Visual C++ v6.0 (Debug Version)"
	strings:
		$0 = {6A 68 E8 BF 8B C7 E8 89 65 8B F4 89 3E 56 FF 15 8B 4E 89 0D 8B 46}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Cpp_v4x_
{
	meta:
		description = "Microsoft Visual C++ v4.x"
	strings:
		$0 = {64 A1 ?? ?? ?? ?? 55 8B EC 6A FF 68 68 50 64 83 53 56 57 89}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Cpp_v50_
{
	meta:
		description = "Microsoft Visual C++ v5.0"
	strings:
		$0 = {24 ?? 8B 24}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Cpp_v50_DLL_
{
	meta:
		description = "Microsoft Visual C++ v5.0 DLL"
	strings:
		$0 = {55 8B EC 6A FF 68 68 64 A1 ?? ?? ?? ??}
	condition:
		$0 at entrypoint
}
rule _MinGW_v32x_Dll_mainCRTStartup_
{
	meta:
		description = "MinGW v3.2.x (Dll_mainCRTStartup)"
	strings:
		$0 = {55 89 E5 83 EC 08 6A ?? 6A ?? 6A ?? 6A ?? E8 0D ?? ?? ?? B8 ?? ?? ?? ?? C9 C3 90 90 90 90 90 90 FF 25 38 20 40 ?? 90 90 ?? ?? ?? ?? ?? ?? ?? ?? FF FF FF FF ?? ?? ?? ?? FF FF FF}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Cpp_v70_DLL_
{
	meta:
		description = "Microsoft Visual C++ v7.0 DLL"
	strings:
		$0 = {55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10}
		$1 = {FF 25 ??}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Borland_Cpp_
{
	meta:
		description = "Borland C++"
	strings:
		$0 = {A1 C1 E0 02}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Cpp_v60_
{
	meta:
		description = "Microsoft Visual C++ v6.0"
	strings:
		$0 = {51}
		$1 = {55 8D 6C 81 EC 8B 45 83 F8 01 56 0F 84 85 C0 0F}
		$2 = {55 8B EC 51}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}
rule _Borland_Cpp_for_Win32_1999_
{
	meta:
		description = "Borland C++ for Win32 1999"
	strings:
		$0 = {EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B}
		$1 = {A1 C1 E0 02 A3 57 51 33 C0 BF B9 3B CF 76 05 2B CF FC F3 AA 59}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _MinGW_GCC_v2x_
{
	meta:
		description = "MinGW GCC v2.x"
	strings:
		$0 = {55 89 E5 FF}
		$1 = {55 89 E5 E8 C9 C3 45 58}
		$2 = {55 89}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}
rule _MinGW_v32x_main_
{
	meta:
		description = "MinGW v3.2.x (main)"
	strings:
		$0 = {55 89 E5 83 EC 08 C7 04 24 01 ?? ?? ?? FF 15 FC 40 40 ?? E8 68 ?? ?? ?? 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 C7 04 24 02 ?? ?? ?? FF 15 FC 40 40 ?? E8 48 ?? ?? ?? 89 EC 31 C0 5D C3 89}
	condition:
		$0 at entrypoint
}
rule _Borland_Delphi_
{
	meta:
		description = "Borland Delphi"
	strings:
		$0 = {C3 E9 FF 8D}
	condition:
		$0 at entrypoint
}
rule _Microsoft_Visual_Basic_v50__v60_
{
	meta:
		description = "Microsoft Visual Basic v5.0 / v6.0"
	strings:
		$0 = {5A 68 68 52 E9}
	condition:
		$0 at entrypoint
}
rule _Borland_Cpp_DLL_
{
	meta:
		description = "Borland C++ DLL"
	strings:
		$0 = {EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90}
		$1 = {EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 A1 C1 E0 02 A3}
		$2 = {EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 A1 C1 E0 02 A3}
		$3 = {C3 E9 FF 8D}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint or $3 at entrypoint
}

rule _PE_Spin_v0b_
{
	meta:
		description = "PE Spin v0.b"
	strings:
		$0 = {66 9C 60 E8 CA 03 04 05 06 07}
	condition:
		$0 at entrypoint
}
rule _LaunchAnywhere_v4001_
{
	meta:
		description = "LaunchAnywhere v4.0.0.1"
	strings:
		$0 = {55 8B EC 83 EC 44 56 FF 15 10 ?? 01 8B F0 8A 06 3C 22 75 14 8A 46 01 46 84 C0 74 04 3C 22 75 F4 80 3E 22 75 0D EB 0A 3C}
	condition:
		$0 at entrypoint
}
rule _XPEOR_v099b_
{
	meta:
		description = "X-PEOR v0.99b"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D 81 ED E7 1A 40 ?? E8 A1 ?? ?? ?? E8 D1 ?? ?? ?? E8 85 01 ?? ?? F7}
	condition:
		$0 at entrypoint
}
rule _PECompact_v09781_
{
	meta:
		description = "PECompact v0.978.1"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB D1 84 40 87 DD 8B 85 56}
	condition:
		$0 at entrypoint
}
rule _Alloy_v1x2000_
{
	meta:
		description = "Alloy v1.x.2000"
	strings:
		$0 = {52 31 C0 E8 FF FF FF}
	condition:
		$0 at entrypoint
}
rule _PECompact_v134__v140b1_
{
	meta:
		description = "PECompact v1.34 - v1.40b1"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 87 DD 8B 85 A6 A0 40 01 85 03 A0 40 66 C7 85 A0 40 90 90 01 85 9E A0 40}
	condition:
		$0 at entrypoint
}
rule _CodeCrypt_v0164_
{
	meta:
		description = "CodeCrypt v0.164"
	strings:
		$0 = {43 4F 44 45 2D 4C 4F 43 4B 2E 4F 43}
	condition:
		$0 at entrypoint
}
rule _Krypton_v03_
{
	meta:
		description = "Krypton v0.3"
	strings:
		$0 = {54 E8 5D 8B C5 81 ED 61 34 2B 85 60 37 83 E8}
	condition:
		$0 at entrypoint
}
rule _PECompact_v14xp_
{
	meta:
		description = "PECompact v1.4x+"
	strings:
		$0 = {33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC}
	condition:
		$0 at entrypoint
}
rule _PECompact_v167_
{
	meta:
		description = "PECompact v1.67"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 87 DD 8B 85 E6 90 40 01 85 33 90 40 66 C7 85 90 40 90 90 01 85 DA 90 40 01 85 DE 90 40 01}
	condition:
		$0 at entrypoint
}
rule _Exe_Shield_v17_
{
	meta:
		description = "Exe Shield v1.7"
	strings:
		$0 = {EB 06 68 F4 86 06 ?? C3 9C 60 E8}
	condition:
		$0 at entrypoint
}
rule _UPX_v060__v061_
{
	meta:
		description = "UPX v0.60 - v0.61"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 58 83 E8 3D 50 8D B8 FF 57 66 81 87 8D B0 F0 01 83 CD FF 31 DB 90 90 90 EB 08 90 90 8A 06 46 88 07 47 01 DB 75}
	condition:
		$0 at entrypoint
}
rule _kryptor_9_
{
	meta:
		description = "kryptor 9"
	strings:
		$0 = {8B 0C 24 E9 0A 7C 01 AD 42 40 BD BE 9D 7A}
	condition:
		$0 at entrypoint
}
rule _PECompact_v0977_
{
	meta:
		description = "PECompact v0.977"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 24 88 40 87 DD 8B 85 A9}
	condition:
		$0 at entrypoint
}
rule _FSG_v131_
{
	meta:
		description = "FSG v1.31"
	strings:
		$0 = {BE A4 01 40 ?? AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13}
	condition:
		$0 at entrypoint
}
rule _Ding_Boys_PElock_Phantasm_v08_
{
	meta:
		description = "Ding Boy's PE-lock Phantasm v0.8"
	strings:
		$0 = {55 57 56 52 51 53 66 81 C3 EB 02 EB FC 66 81 C3 EB 02 EB}
	condition:
		$0 at entrypoint
}
rule _y0das_Crypter_v10_
{
	meta:
		description = "y0da's Crypter v1.0"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D 81 ED 8A 1C 40 ?? B9 9E ?? ?? ?? 8D BD 4C 23 40 ?? 8B F7}
	condition:
		$0 at entrypoint
}
rule _PECompact_v155_
{
	meta:
		description = "PECompact v1.55"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 90 40 87 DD 8B 85 A2 90 40 01 85 03 90 40 66 C7 85 90 40 90 90 01 85 9E 90 40}
	condition:
		$0 at entrypoint
}
rule _PECompact_v100_
{
	meta:
		description = "PECompact v1.00"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 28 63 40 87 DD 8B 85 AD}
	condition:
		$0 at entrypoint
}
rule _SoftSentry_v30_
{
	meta:
		description = "SoftSentry v3.0"
	strings:
		$0 = {52 53 51 56 57 55 E8 5D 81 ED 36 E8 01 60 BA E8}
	condition:
		$0 at entrypoint
}
rule _PECompact_v2x_
{
	meta:
		description = "PECompact v2.x"
	strings:
		$0 = {53 51 52 56 57 55 E8 ?? ?? ?? ?? 5D 8B D5 81 ED A2 30 40 ?? 2B 95 91 33 40 ?? 81 EA 0B ?? ?? ?? 89 95 9A 33 40 ?? 80 BD 99 33 40 ?? ??}
	condition:
		$0 at entrypoint
}
rule _tElock_v098b2_
{
	meta:
		description = "tElock v0.98b2"
	strings:
		$0 = {E9 FF FF ?? ?? ?? ?? ?? ?? ??}
	condition:
		$0 at entrypoint
}
rule _PECompact_v110b7_
{
	meta:
		description = "PECompact v1.10b7"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 87 DD 8B 85 9A 70}
	condition:
		$0 at entrypoint
}
rule _BopCrypt_v10_
{
	meta:
		description = "BopCrypt v1.0"
	strings:
		$0 = {55 8B EC 81 EC 0C 02 56 BE 04 01 8D 85 F8 FE FF FF 56 50 6A FF 15 54 10 40 8A 8D F8 FE FF FF 33 D2 84 C9 8D 85 F8 FE FF FF 74}
	condition:
		$0 at entrypoint
}
rule _APatch_GUI_v11_
{
	meta:
		description = "APatch GUI v1.1"
	strings:
		$0 = {60 E8 5D 81 ED 92 1A 44 B8 8C 1A 44 03 C5 2B 85 CD 1D 44 89 85 D9 1D 44 80 BD C4 1D}
	condition:
		$0 at entrypoint
}
rule _Nullsoft_Install_System_v198_
{
	meta:
		description = "Nullsoft Install System v1.98"
	strings:
		$0 = {83 EC 0C 53 55 56 57 FF 15 70 40 ?? 8B 35 92 40 ?? 05 E8 03 ?? ?? 89 44 24 14 B3 20 FF 15 2C 70 40 ?? BF ?? 04 ?? ?? 68 ?? 57 FF 15 40 ?? 57 FF}
	condition:
		$0 at entrypoint
}
rule _WWPack32_v100_v111_v112_v120_
{
	meta:
		description = "WWPack32 v1.00, v1.11, v1.12, v1.20"
	strings:
		$0 = {53 55 8B E8 33 DB EB}
	condition:
		$0 at entrypoint
}
rule _PEtite_v12_
{
	meta:
		description = "PEtite v1.2"
	strings:
		$0 = {66 9C 60 50 8D 88 F0 8D 90 04 16 8B DC 8B E1 68 53 50 80 04 24 08 50 80 04 24}
	condition:
		$0 at entrypoint
}
rule _PECompact_v110b1_
{
	meta:
		description = "PECompact v1.10b1"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 87 DD 8B 85 94}
	condition:
		$0 at entrypoint
}
rule _ASPack_v10801_
{
	meta:
		description = "ASPack v1.08.01"
	strings:
		$0 = {60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 44 BB 10 44 03 DD 2B}
		$1 = {90 90 75 90}
		$2 = {90 75 90}
		$3 = {60 EB 5D EB FF}
		$4 = {60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 44 ?? BB 10 44 ?? 03 DD 2B}
		$5 = {60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ED 23 6A 44 ?? BB 10 44 ?? 03 DD 2B 9D}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint or $3 at entrypoint or $4 at entrypoint or $5 at entrypoint
}
rule _PECompact_v160__v165_
{
	meta:
		description = "PECompact v1.60 - v1.65"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 87 DD 8B 85 E6 90 40 01 85 33 90 40 66 C7 85 90 40 90 90 01 85 DA 90 40}
	condition:
		$0 at entrypoint
}
rule _BJFnt_v12_RC_
{
	meta:
		description = ".BJFnt v1.2 RC"
	strings:
		$0 = {EB 03 3A 4D 3A 1E EB 02 CD 20 9C EB 02 CD 20 EB 02 CD 20}
	condition:
		$0 at entrypoint
}
rule _XtremeProtector_v105_
{
	meta:
		description = "Xtreme-Protector v1.05"
	strings:
		$0 = {B8 ?? B9 75 ?? 50 51 E8 05 ?? ?? ?? E9 4A 01 ?? ?? 60 8B 74 24 24 8B 7C 24 28 FC B2 80 8A 06 46 88 07 47 BB 02 ?? ?? ?? 02 D2 75 05 8A 16 46 12 D2 73 EA 02 D2 75 05 8A 16 46}
	condition:
		$0 at entrypoint
}
rule _PENightMare_v13_
{
	meta:
		description = "PENightMare v1.3"
	strings:
		$0 = {60 E9 EF 40 03 A7 07 8F 07 1C 37 5D 43 A7 04 B9 2C}
	condition:
		$0 at entrypoint
}
rule _PEncrypt_v10_
{
	meta:
		description = "PEncrypt v1.0"
	strings:
		$0 = {E8 ?? ?? ?? ?? 5D 81 ED 05 10 40 ?? 8D B5 24 10 40 ?? 8B FE B9 0F ?? ?? ?? BB AD 33 C3 E2}
	condition:
		$0 at entrypoint
}
rule _Symantec_Visual_Cafe_v30_
{
	meta:
		description = "Symantec Visual Cafe v3.0"
	strings:
		$0 = {E8 ?? ?? ?? ?? 5D 8B C5 2D ?? 50 81 ED 05 ?? ?? ?? 8B C5 2B 85 03 0F ?? ?? 89 85 03 0F ?? ?? 8B F0 03 B5 0B 0F ?? ?? 8B F8 03 BD 07 0F ?? ?? 83 7F 0C ?? 74 2B 56 57 8B 7F 10 03 F8}
	condition:
		$0 at entrypoint
}
rule _ASPack_v101b_
{
	meta:
		description = "ASPack v1.01b"
	strings:
		$0 = {60 E8 5D 81 ED 3E D9 43 B8 38 03 C5 2B 85 0B DE 43 89 85 17 DE 43 80 BD 01 DE 43 75 15 FE 85 01 DE 43 E8 1D E8 79 02 E8 12 03 8B}
	condition:
		$0 at entrypoint
}
rule _CrypWrap_vxx_
{
	meta:
		description = "CrypWrap vx.x"
	strings:
		$0 = {6A 04 68 ?? 10 ?? ?? FF 35 9C 14 40 ?? 6A ?? FF 15 38 10 40 ?? A3 FC 10 40 ?? 97 BE ?? 20 40 ?? E8 71 ?? ?? ?? 3B 05 9C 14 40 ?? 75 61 6A ?? 6A 20 6A 02 6A ?? 6A 03 68 ?? ?? ?? C0 68 94 10}
	condition:
		$0 at entrypoint
}
rule _RatPacker_Glue_stub_
{
	meta:
		description = "RatPacker (Glue) stub"
	strings:
		$0 = {83 3D 55 8B EC 56 57 75 65 68 ?? 01 E8 E6 FF FF 83 C4 04 8B 75 08 A3 85 F6 74 1D 68}
	condition:
		$0 at entrypoint
}
rule _Shrinker_v32_
{
	meta:
		description = "Shrinker v3.2"
	strings:
		$0 = {83 3D ?? ?? 55 8B EC 56 57 75 65 68 ?? 01 ?? ??}
	condition:
		$0 at entrypoint
}
rule _XCR_v013_
{
	meta:
		description = "XCR v0.13"
	strings:
		$0 = {E8 5D 8B CD 81 ED 7A 29 40 89 AD 0F 6D}
	condition:
		$0 at entrypoint
}
rule _Guardant_Stealth_aka_Novex_Dongle_
{
	meta:
		description = "Guardant Stealth aka Novex Dongle"
	strings:
		$0 = {50 53 51 52 57 56 8B 75 1C 8B 3E 8B 5D 08 8A FB 03 5D 10 8B 45 0C 8B 4D 14 8B 55 18 80 FF}
	condition:
		$0 at entrypoint
}
rule _ASPack_v104b_
{
	meta:
		description = "ASPack v1.04b"
	strings:
		$0 = {75 ??}
	condition:
		$0 at entrypoint
}
rule _Feokt_
{
	meta:
		description = "Feokt"
	strings:
		$0 = {55 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? BE ?? ?? ?? 03 F5 BA ?? ?? 2B D5 8B DD 33 C0 AC 3C ?? 74 3D 3C 01 74 0E 3C 02 74 0E 3C 03 74 0D 03 D8 29 13 EB E7 66 AD EB F6 AD EB F3 AC 0F}
	condition:
		$0 at entrypoint
}
rule _SVKProtector_v1051_
{
	meta:
		description = "SVK-Protector v1.051"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D 81 ED 06 ?? ?? ?? EB 05 B8 06 36 42 ?? 64 A0}
	condition:
		$0 at entrypoint
}
rule _EXE32Pack_v136_
{
	meta:
		description = "EXE32Pack v1.36"
	strings:
		$0 = {3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC 02 81 3B DB 74 01 BE 5D 8B D5 81 ED 4C 8E}
	condition:
		$0 at entrypoint
}
rule _SPEC_b2_
{
	meta:
		description = "SPEC b2"
	strings:
		$0 = {5B 53 50 45 43 5D E8 5D 8B C5 81 ED 41 24 40 2B 85 89 26 40 83 E8 0B 89 85 8D 26 40 0F B6 B5 91 26 40 8B}
	condition:
		$0 at entrypoint
}
rule _PESHiELD_v025_
{
	meta:
		description = "PESHiELD v0.25"
	strings:
		$0 = {5D 83 ED 06 EB 02 EA 04}
	condition:
		$0 at entrypoint
}
rule _ASPack_v211d_
{
	meta:
		description = "ASPack v2.11d"
	strings:
		$0 = {60 E8 03 ?? ?? ?? E9 EB 04 5D 45 55 C3 E8 01 ?? ?? ?? EB 5D BB ED FF FF FF 03 DD 81}
	condition:
		$0 at entrypoint
}
rule _Winkript_v10_
{
	meta:
		description = "Winkript v1.0"
	strings:
		$0 = {FF 15 ?? B1 22 38 08 74 02 B1 20 40 80 38 ?? 74 10 38 08 74 06 40 80 38 ?? 75 F6 80 38 ?? 74 01 40 33 C9 FF}
	condition:
		$0 at entrypoint
}
rule _UPX_p_ECLiPSE_layer_
{
	meta:
		description = "UPX + ECLiPSE layer"
	strings:
		$0 = {90 61 BE 8D BE 57 83 CD}
	condition:
		$0 at entrypoint
}
rule _tElock_v071_
{
	meta:
		description = "tElock v0.71"
	strings:
		$0 = {60 E8 44 11 ?? ?? C3}
	condition:
		$0 at entrypoint
}
rule _ASPack_v211c_
{
	meta:
		description = "ASPack v2.11c"
	strings:
		$0 = {60 E8 02 ?? ?? ?? EB 09 5D}
	condition:
		$0 at entrypoint
}
rule _Macromedia_Windows_Flash_ProjectorPlayer_v50_
{
	meta:
		description = "Macromedia Windows Flash Projector/Player v5.0"
	strings:
		$0 = {83 EC 44 56 FF 15 24 81 49 ?? 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB}
	condition:
		$0 at entrypoint
}
rule _DBPE_vxxx_
{
	meta:
		description = "DBPE vx.xx"
	strings:
		$0 = {60 E8 5D 8B FD 81 ED 2B B9 81 EF 83 BD 0F}
	condition:
		$0 at entrypoint
}
rule _UPX_v0896__v102__v105__v122_DLL_
{
	meta:
		description = "UPX v0.89.6 - v1.02 / v1.05 - v1.22 DLL"
	strings:
		$0 = {8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB}
	condition:
		$0 at entrypoint
}
rule _CodeCrypt_v014b_
{
	meta:
		description = "CodeCrypt v0.14b"
	strings:
		$0 = {E9 31 03 ?? ?? EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7}
	condition:
		$0 at entrypoint
}
rule _kryptor_6_
{
	meta:
		description = "kryptor 6"
	strings:
		$0 = {EB 6A 87}
	condition:
		$0 at entrypoint
}
rule _UPX_v080__v084_
{
	meta:
		description = "UPX v0.80 - v0.84"
	strings:
		$0 = {8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB}
	condition:
		$0 at entrypoint
}
rule _Hasp_4_envelope_dongle_Alladin_
{
	meta:
		description = "Hasp 4 envelope dongle (Alladin)"
	strings:
		$0 = {5C 5C 2E 5C 48 41 52 44 4C 4F 43 4B 2E 56 58 44 ?? ?? ?? ?? 5C 5C 2E 5C 46 45 6E 74 65 44 65}
	condition:
		$0 at entrypoint
}
rule _Hardlock_dongle_Alladin_
{
	meta:
		description = "Hardlock dongle (Alladin)"
	strings:
		$0 = {49 6E 6E 6F 53 65 74 75 70 4C 64 72 57 69 6E 64 6F 77 ?? ?? 53 54 41 54 49}
	condition:
		$0 at entrypoint
}
rule _PECompact_v0971__v0976_
{
	meta:
		description = "PECompact v0.971 - v0.976"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB A0 86 40 87 DD 8B 85 2A}
	condition:
		$0 at entrypoint
}
rule _CodeCrypt_v015b_
{
	meta:
		description = "CodeCrypt v0.15b"
	strings:
		$0 = {E9 2E 03 ?? ?? EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7}
	condition:
		$0 at entrypoint
}
rule _Pack_Master_v10_
{
	meta:
		description = "Pack Master v1.0"
	strings:
		$0 = {53 51 52 56 57 55 E8 ?? ?? ?? ?? 5D 8B CD 81 ED 33 30 40 2B 8D EE 32 40 ?? 83 E9 0B 89 8D F2 32 40 80 BD D1 32 40 01 0F}
		$1 = {9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 40 87 DD 6A 04 68 10 68 02 6A FF}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _FixupPak_v120_
{
	meta:
		description = "FixupPak v1.20"
	strings:
		$0 = {83 EC 0C 53 56 57 E8 24}
	condition:
		$0 at entrypoint
}
rule _ASProtect_v10_
{
	meta:
		description = "ASProtect v1.0"
	strings:
		$0 = {60 E9 04 E9}
	condition:
		$0 at entrypoint
}
rule _tElock_v100_
{
	meta:
		description = "tElock v1.00"
	strings:
		$0 = {66 8B C0 8D 24 24 EB 01 EB 60 EB 01 EB 9C E8 ?? ?? ?? ?? 5E 83 C6 50 8B FE 68 78 01 59 EB 01 EB AC 54 E8 03 5C EB}
	condition:
		$0 at entrypoint
}
rule _VOB_ProtectCD_5_
{
	meta:
		description = "VOB ProtectCD 5"
	strings:
		$0 = {5F 81 EF BE 40 8B 87 03 C6 57 56 8C A7 FF 10 89 87 5E}
	condition:
		$0 at entrypoint
}
rule _Macromedia_Windows_Flash_ProjectorPlayer_v60_
{
	meta:
		description = "Macromedia Windows Flash Projector/Player v6.0"
	strings:
		$0 = {E9}
	condition:
		$0 at entrypoint
}
rule _PECompact_v098_
{
	meta:
		description = "PECompact v0.98"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 2F 85 40 87 DD 8B 85 B4}
	condition:
		$0 at entrypoint
}
rule _PE_Diminisher_v01_
{
	meta:
		description = "PE Diminisher v0.1"
	strings:
		$0 = {5D 8B D5 81 ED A2 30 40 2B 95 91 33 40 81 EA 0B 89 95 9A 33 40 80 BD}
		$1 = {60 9C BE ?? 10 40 ?? 8B FE B9 28 03 ?? ?? BB 78 56 34 12 AD 33 C3 AB E2 FA 9D}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _EXE_Stealth_v272_
{
	meta:
		description = "EXE Stealth v2.72"
	strings:
		$0 = {3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC 02 81 3B DB 74 01 BE 5D 8B D5 81 ED CC 8D}
	condition:
		$0 at entrypoint
}
rule _Nullsoft_Install_System_v1xx_
{
	meta:
		description = "Nullsoft Install System v1.xx"
	strings:
		$0 = {83 EC 0C 53 56 57 FF 15 20 71 40 ?? 05 E8 03 ?? ?? BE 60 FD 41 ?? 89 44 24 10 B3 20 FF 15 28 70 40 ?? 68 ?? 04 ?? ?? FF 15 28 71 40 ?? 50 56 FF 15 08 71 40 ?? 80 3D 60 FD 41 ?? 22 75 08 80}
		$1 = {83 EC 0C 53 56 57 FF 15 2C 81}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _Soft_Defender_v10__v11_
{
	meta:
		description = "Soft Defender v1.0 - v1.1"
	strings:
		$0 = {55 8B EC 83 EC 53 56 57 E9}
	condition:
		$0 at entrypoint
}
rule _PEShit_
{
	meta:
		description = "PEShit"
	strings:
		$0 = {EB 01 68 60 E8 ?? ?? ?? ?? 8B 1C 24 83 C3 12 81 2B E8 B1 06 ?? FE 4B FD 82 2C 24 72 C8 46 ?? 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 ?? 43 B7 F6 C3 6B B7 ?? ?? F9 FF E3 C9 C2}
	condition:
		$0 at entrypoint
}
rule _tElock_v098b1_
{
	meta:
		description = "tElock v0.98b1"
	strings:
		$0 = {E9 1B E4 FF}
	condition:
		$0 at entrypoint
}
rule _EXE32Pack_v13x_
{
	meta:
		description = "EXE32Pack v1.3x"
	strings:
		$0 = {E8 24 8B 4C 24 0C C7 01 17 01 C7 81 31 C0 89 41 14 89 41 18 80}
	condition:
		$0 at entrypoint
}
rule _VOB_ProtectCD_
{
	meta:
		description = "VOB ProtectCD"
	strings:
		$0 = {9C 55 E8 EC ?? ?? ?? 87 D5 5D 60 87 D5 80 BD 15 27 40 ??}
	condition:
		$0 at entrypoint
}
rule _tElock_v096_
{
	meta:
		description = "tElock v0.96"
	strings:
		$0 = {E9 25 E4 FF FF ?? ?? ??}
	condition:
		$0 at entrypoint
}
rule _EXECryptor_v1401_
{
	meta:
		description = "EXECryptor v1.4.0.1"
	strings:
		$0 = {E8 24 8B 4C 24 0C C7 01 17 01 C7 81 B8 31 C0 89 41 14 89 41 18 80 A1 C1 FE C3 31 C0 64 FF 30 64 89 20 CC}
	condition:
		$0 at entrypoint
}
rule _AcidCrypt_
{
	meta:
		description = "AcidCrypt"
	strings:
		$0 = {BE 02 38 40 4E 75 FA 8B C2 8A 18 32 DF C0}
		$1 = {9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 20 40 87 DD 6A 04 68 10 68 02 6A FF 95 46 23 40}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _ASPack_v2001_
{
	meta:
		description = "ASPack v2.001"
	strings:
		$0 = {60 E8 72 05 ?? ?? EB 33 87 DB}
	condition:
		$0 at entrypoint
}
rule _Stones_PE_Encryptor_v10_
{
	meta:
		description = "Stone's PE Encryptor v1.0"
	strings:
		$0 = {55 57 56 52 51 53 E8 5D 8B D5 81 ED 97 3B 40 2B 95 2D 3C 40 83 EA 0B 89 95 36 3C 40 01 95 24 3C 40 01 95}
	condition:
		$0 at entrypoint
}
rule _FSG_v13_
{
	meta:
		description = "FSG v1.3"
	strings:
		$0 = {BB D0 01 40 ?? BF ?? 10 40 ?? BE 53 BB B2 80 A4 B6 80 FF D3 73 F9 33}
	condition:
		$0 at entrypoint
}
rule _LTC_v13_
{
	meta:
		description = "LTC v1.3"
	strings:
		$0 = {2C E8 5D 8B C5 81 ED F6 73 2B 85 83 E8 06 89}
	condition:
		$0 at entrypoint
}
rule _Stealth_PE_v11_
{
	meta:
		description = "Stealth PE v1.1"
	strings:
		$0 = {55 57 56 52 51 53 E8 5D 8B D5 81 ED 63 3A 40 2B 95 C2 3A 40 83 EA 0B 89 95 CB 3A 40 8D B5 CA 3A 40 0F B6}
	condition:
		$0 at entrypoint
}
rule _UPX_Modified_stub_
{
	meta:
		description = "UPX Modified stub"
	strings:
		$0 = {EB EC 8A 06 46 88 07 47 01 DB 75}
	condition:
		$0 at entrypoint
}
rule _PECompact_v09782_
{
	meta:
		description = "PECompact v0.978.2"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB D7 84 40 87 DD 8B 85 5C}
	condition:
		$0 at entrypoint
}
rule _EXECryptor_vxxxx_
{
	meta:
		description = "EXECryptor vx.x.x.x"
	strings:
		$0 = {68 ?? 10 40 ?? 68 04 01 ?? ?? E8 39 03 ?? ?? 05 ?? 10 40 C6 ?? 5C 68 68 6A ??}
	condition:
		$0 at entrypoint
}
rule _SoftSentry_v211_
{
	meta:
		description = "SoftSentry v2.11"
	strings:
		$0 = {55 8B EC 83 EC 53 56 57 E9 B0}
	condition:
		$0 at entrypoint
}
rule _ASPack_v1061b_
{
	meta:
		description = "ASPack v1.061b"
	strings:
		$0 = {60 E8 5D 81 ED B8 03 C5 2B 85 0B DE 89 85 17 DE 80 BD 01}
	condition:
		$0 at entrypoint
}
rule _PECompact_v140b2__v140b4_
{
	meta:
		description = "PECompact v1.40b2 - v1.40b4"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 87 DD 8B 85 A6 A0 40 01 85 03 A0 40 66 C7 85 A0 40 90 90 01 85 9E A0 40}
	condition:
		$0 at entrypoint
}
rule _PESHiELD_v02__v02b__v02b2_
{
	meta:
		description = "PESHiELD v0.2 / v0.2b / v0.2b2"
	strings:
		$0 = {60 E8}
	condition:
		$0 at entrypoint
}
rule _Neolite_v20_
{
	meta:
		description = "Neolite v2.0"
	strings:
		$0 = {9E 37 ?? ?? 48 6F 4C}
	condition:
		$0 at entrypoint
}
rule _PE_Lock_NT_v201_
{
	meta:
		description = "PE Lock NT v2.01"
	strings:
		$0 = {EB 02 C7 85 1E EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB 02}
	condition:
		$0 at entrypoint
}
rule _tElock_v085f_
{
	meta:
		description = "tElock v0.85f"
	strings:
		$0 = {E8 02 ?? ?? ?? E8 ?? E8 ?? ?? ?? ?? 5E}
	condition:
		$0 at entrypoint
}
rule _EXEJoiner_v10_
{
	meta:
		description = "EXEJoiner v1.0"
	strings:
		$0 = {9C FE 03 60 BE 41 8D BE 10 FF FF 57 83 CD FF EB}
	condition:
		$0 at entrypoint
}
rule _kryptor_8_
{
	meta:
		description = "kryptor 8"
	strings:
		$0 = {60 E8 5E B9 2B C0 02 04 0E D3 C0 49 79 F8 41 8D 7E 2C 33 46 66}
	condition:
		$0 at entrypoint
}
rule _NX_PE_Packer_v10_
{
	meta:
		description = "NX PE Packer v1.0"
	strings:
		$0 = {EB 02 E8 E7}
	condition:
		$0 at entrypoint
}
rule _PECompact_v156_
{
	meta:
		description = "PECompact v1.56"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 80 40 87 DD 8B 85 D2 80 40 01 85 33 80 40 66 C7 85 80 40 90 90 01 85 CE 80 40}
	condition:
		$0 at entrypoint
}
rule _CodeCrypt_v016b__v0163b_
{
	meta:
		description = "CodeCrypt v0.16b - v0.163b"
	strings:
		$0 = {E9 2E 03 ?? ?? EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F EB 03 FF 1D}
	condition:
		$0 at entrypoint
}
rule _CDCops_II_
{
	meta:
		description = "CD-Cops II"
	strings:
		$0 = {E9 C5 02 ?? ?? EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7}
	condition:
		$0 at entrypoint
}
rule _kryptor_5_
{
	meta:
		description = "kryptor 5"
	strings:
		$0 = {E8 03 E9 EB 68 58 33 D2 74 02 E9 E9 40 42 75}
	condition:
		$0 at entrypoint
}
rule _tElock_v092a_
{
	meta:
		description = "tElock v0.92a"
	strings:
		$0 = {E9 D5 E4 FF}
	condition:
		$0 at entrypoint
}
rule _Stones_PE_Encryptor_v20_
{
	meta:
		description = "Stone's PE Encryptor v2.0"
	strings:
		$0 = {60 E8 5D 81 ED 06 64 A0}
	condition:
		$0 at entrypoint
}
rule _PECompact_v184_
{
	meta:
		description = "PECompact v1.84"
	strings:
		$0 = {B8 50 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 33 C0 89}
	condition:
		$0 at entrypoint
}
rule _PC_Shrinker_v045_
{
	meta:
		description = "PC Shrinker v0.45"
	strings:
		$0 = {9C 60 BD 01 AD 54 3A 40 FF B5 50 3A 40 6A 40 FF 95 88 3A 40 50 50 2D 89}
	condition:
		$0 at entrypoint
}
rule _UPX_Alternative_stub_
{
	meta:
		description = "UPX Alternative stub"
	strings:
		$0 = {50 BE 8D BE 57 83}
	condition:
		$0 at entrypoint
}
rule _32Lite_v003a_
{
	meta:
		description = "32Lite v0.03a"
	strings:
		$0 = {60 B9 ?? BA ?? BE ?? 02 38 40 4E 75 FA 8B C2 8A 18 32 DF C0}
	condition:
		$0 at entrypoint
}
rule _tElock_v071b2_
{
	meta:
		description = "tElock v0.71b2"
	strings:
		$0 = {60 E8 48 11 ?? ?? C3}
	condition:
		$0 at entrypoint
}
rule _Obsidium_v1111_
{
	meta:
		description = "Obsidium v1.1.1.1"
	strings:
		$0 = {E8 AB}
	condition:
		$0 at entrypoint
}
rule _UPX_v081__v084_Modified_
{
	meta:
		description = "UPX v0.81 - v0.84 Modified"
	strings:
		$0 = {01 DB 07 8B 1E 83 EE FC 11 DB ED B8 01 ?? ?? ?? 01 DB 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73}
	condition:
		$0 at entrypoint
}
rule _ZCode_Win32PE_Protector_v101_
{
	meta:
		description = "ZCode Win32/PE Protector v1.01"
	strings:
		$0 = {53 51 56 E8 ?? ?? ?? ?? 5B 81 EB 08 10 ?? ?? 8D B3 34 10 ?? ?? B9 F3 03 ?? ?? BA 63 17 2A EE 31 16 83 C6}
	condition:
		$0 at entrypoint
}
rule _EP_v10_
{
	meta:
		description = "EP v1.0"
	strings:
		$0 = {6A 60 E9 01}
	condition:
		$0 at entrypoint
}
rule _ASPack_v107b_
{
	meta:
		description = "ASPack v1.07b"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D B8 03}
		$1 = {90 90 75}
		$2 = {90 75}
		$3 = {90 75 01 FF}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint or $3 at entrypoint
}
rule _XtremeProtector_v106_
{
	meta:
		description = "Xtreme-Protector v1.06"
	strings:
		$0 = {60 8B F0 33 DB 83 C3 01 83 C0}
	condition:
		$0 at entrypoint
}
rule _Wise_Installer_Stub_
{
	meta:
		description = "Wise Installer Stub"
	strings:
		$0 = {55 8B EC 81 EC 78 05 ?? ?? 53 56 BE 04 01 ?? ?? 57 8D 85 94 FD FF FF 56 33 DB 50 53 FF 15 34 20 40 ?? 8D 85 94 FD FF FF 56 50 8D 85 94 FD FF FF 50 FF 15 30 20 40 ?? 8B 3D 2C 20 40 ?? 53 53}
		$1 = {55 8B EC 81 EC 40 0F ?? ?? 53 56 57 6A 04 FF 15 F4 30 40 ?? FF 15 74 30 40 ?? 8A 08 89 45 E8 80 F9 22 75 48 8A 48 01 40 89 45 E8 33 F6 84 C9 74 0E 80 F9 22 74 09 8A 48 01 40 89 45 E8 EB EE}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PENightMare_2_Beta_
{
	meta:
		description = "PENightMare 2 Beta"
	strings:
		$0 = {90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90}
	condition:
		$0 at entrypoint
}
rule _PECompact_v123b3__v1241_
{
	meta:
		description = "PECompact v1.23b3 - v1.24.1"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 87 DD 8B 85 A6 70 40 01 85 03 70 40 66 C7 85 70 40 90 90 01 85 9E 70 40 BB}
	condition:
		$0 at entrypoint
}
rule _EXECryptor_v13045_
{
	meta:
		description = "EXECryptor v1.3.0.45"
	strings:
		$0 = {E8 24 ?? ?? ?? 8B 4C 24 0C C7 01 17 ?? 01 ?? C7 81 31 C0 89 41 14 89 41 18 80}
		$1 = {E8 24 ?? ?? ?? 8B 4C 24 0C C7 01 17 ?? 01 ?? C7 81 B8 ?? ?? ?? ?? ?? 31 C0 89 41 14 89 41 18}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _UPX_v0896__v102__v105__v122_
{
	meta:
		description = "UPX v0.89.6 - v1.02 / v1.05 - v1.22"
	strings:
		$0 = {8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 8A 07 72 EB B8 01 ?? ?? ?? 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0}
	condition:
		$0 at entrypoint
}
rule _DxPack_10_
{
	meta:
		description = "DxPack 1.0"
	strings:
		$0 = {50 83 C0 17 8B F0 97 33 C0 33 C9 B1 24 AC 86 C4 AC AA 86 C4 AA E2 F6 ?? B8 40 ?? 03 ?? 3C 40 D2 33 8B 66 14 50 70 8B 8D 34 02 44 8B 18 10 48 70 03 BA 0C C0 33 FE 8B 30 AC 30 D0}
	condition:
		$0 at entrypoint
}
rule _ASProtect_vxx_
{
	meta:
		description = "ASProtect vx.x"
	strings:
		$0 = {60 90 5D 03}
		$1 = {60 E8 01 90 5D 81 ED BB 03 DD 2B}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PECompact_v140__v145_
{
	meta:
		description = "PECompact v1.40 - v1.45"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 87 DD 8B 85 A6 A0 40 01 85 03 A0 40 66 C7 85 A0 40 90 90 01 85 9E A0 40}
	condition:
		$0 at entrypoint
}
rule _Private_EXE_v20a_
{
	meta:
		description = "Private EXE v2.0a"
	strings:
		$0 = {EB CD CD EB EB EB EB CD E8 E9 50}
		$1 = {E8 58 83 D8 05 89 C3 81 C3 8B 43 64}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _ASProtect_v123_RC1_
{
	meta:
		description = "ASProtect v1.23 RC1"
	strings:
		$0 = {68 01 E8 01 C3}
	condition:
		$0 at entrypoint
}
rule _ASPack_v100b_
{
	meta:
		description = "ASPack v1.00b"
	strings:
		$0 = {60 E8 5D 81 ED D2 2A 44 B8 CC 2A 44 03 C5 2B 85 A5 2E 44 89 85 B1 2E 44 80 BD 9C 2E}
	condition:
		$0 at entrypoint
}
rule _CopyControl_v303_
{
	meta:
		description = "CopyControl v3.03"
	strings:
		$0 = {55 8B EC 81 EC 20 02 ?? ?? 53 56 57 6A ?? FF 15 18 61 40 ?? 68 ?? 70 40 ?? 89 45 08 FF 15 14 61 40 ?? 85 C0 74 27 6A ?? A1 ?? 20 40 ?? 50 FF 15 3C 61 40 ?? 8B F0 6A 06 56 FF 15 38 61 40 ??}
	condition:
		$0 at entrypoint
}
rule _ASPack_v106b_
{
	meta:
		description = "ASPack v1.06b"
	strings:
		$0 = {90 90 75 ??}
		$1 = {90 90 90 75 ??}
		$2 = {60 E8 5D 81 ED EA A8 43 B8 E4 A8 43 03 C5 2B 85 78 AD 43 89 85 84 AD 43 80 BD 6E AD}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}
rule _EXE32Pack_v138_
{
	meta:
		description = "EXE32Pack v1.38"
	strings:
		$0 = {3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC 02 81 3B DB 74 01 BE 5D 8B D5 81 ED EC 8D}
	condition:
		$0 at entrypoint
}
rule _PE_Crypt32_Console_v10_v101_v102_
{
	meta:
		description = "PE Crypt32 (Console v1.0, v1.01, v1.02)"
	strings:
		$0 = {8B 04 24 9C 60 E8 5D 81 ED 0A 45 40 80 BD 67 44 40 0F 85}
	condition:
		$0 at entrypoint
}
rule _BJFnt_v13_
{
	meta:
		description = ".BJFnt v1.3"
	strings:
		$0 = {EB 3A 1E EB CD 20 9C EB CD 20 EB CD 20 60}
		$1 = {60 06 FC 1E 07 BE 6A 04 68 10}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _ExeSmasher_vxx_
{
	meta:
		description = "ExeSmasher vx.x"
	strings:
		$0 = {E9 19 32 ?? ?? E9 7C 2A ?? ?? E9 19 24 ?? ?? E9 FF 23 ?? ?? E9 1E 2E ?? ?? E9 88 2E ?? ?? E9}
	condition:
		$0 at entrypoint
}
rule _PECompact_v168__v184_
{
	meta:
		description = "PECompact v1.68 - v1.84"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC}
	condition:
		$0 at entrypoint
}
rule _PECompact_v166_
{
	meta:
		description = "PECompact v1.66"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 87 DD 8B 85 E6 90 40 01 85 33 90 40 66 C7 85 90 40 90 90 01 85 DA 90 40 01 85 DE 90 40 01}
	condition:
		$0 at entrypoint
}
rule _Krypton_v02_
{
	meta:
		description = "Krypton v0.2"
	strings:
		$0 = {8B 0C 24 E9 C0 8D 01 C1 3A 6E CA 5D 7E 79 6D B3 64 5A 71}
	condition:
		$0 at entrypoint
}
rule _UPXScrambler_RC_v1x_
{
	meta:
		description = "UPX-Scrambler RC v1.x"
	strings:
		$0 = {B8 43 ?? B9 15 ?? ?? ?? 80 34 08 E2 FA E9 D6 FF FF}
	condition:
		$0 at entrypoint
}
rule _ASPack_v102a_
{
	meta:
		description = "ASPack v1.02a"
	strings:
		$0 = {60 E8 5D 81 ED 96 78 43 B8 90 78 43 03 C5 2B 85 7D 7C 43 89 85 89 7C 43 80 BD 74 7C}
	condition:
		$0 at entrypoint
}
rule _Inno_Setup_Module_
{
	meta:
		description = "Inno Setup Module"
	strings:
		$0 = {49 6E 6E}
		$1 = {55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 A7 7F FF FF E8 FA 92 FF FF E8 F1 B3 FF FF 33}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _UPX_Modifier_v01x_
{
	meta:
		description = "UPX Modifier v0.1x"
	strings:
		$0 = {79 07 0F B7 07 47 50 47 B9 57 48 F2 AE 55 FF 96 84 ?? ?? 09 C0 74 07 89 03 83 C3 04 EB D8 FF 96 88 ?? ?? 61 E9}
	condition:
		$0 at entrypoint
}
rule _Inno_Setup_Module_v109a_
{
	meta:
		description = "Inno Setup Module v1.09a"
	strings:
		$0 = {55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 EC 89 45 C0 E8 5B 73 FF FF E8 D6 87 FF FF E8 C5 A9 FF FF E8}
	condition:
		$0 at entrypoint
}
rule _PEnguinCrypt_v10_
{
	meta:
		description = "PEnguinCrypt v1.0"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D B9 80 31 15 41 81}
	condition:
		$0 at entrypoint
}
rule _PEMangle_
{
	meta:
		description = "PEMangle"
	strings:
		$0 = {E8 B9 1B 01}
	condition:
		$0 at entrypoint
}
rule _PECompact_v133_
{
	meta:
		description = "PECompact v1.33"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 80 40 87 DD 8B 85 A6 80 40 01 85 03 80 40 66 C7 85 ?? 80 40 90 90 01 85 9E 80}
	condition:
		$0 at entrypoint
}
rule _PEtite_v22_
{
	meta:
		description = "PEtite v2.2"
	strings:
		$0 = {B8 66 9C 60}
	condition:
		$0 at entrypoint
}
rule _ASProtect_v11_
{
	meta:
		description = "ASProtect v1.1"
	strings:
		$0 = {60 E9 91 78 79 79 79}
	condition:
		$0 at entrypoint
}
rule _EXE_Stealth_v271_
{
	meta:
		description = "EXE Stealth v2.71"
	strings:
		$0 = {EB ?? EB 2F 53 68 61 72 65 77 61 72 65 20 2D}
	condition:
		$0 at entrypoint
}
rule _CipherWall_SelfExtratorDecryptor_Console_v15_
{
	meta:
		description = "CipherWall Self-Extrator/Decryptor (Console) v1.5"
	strings:
		$0 = {60 60 9C 8C C9 32 C9 E3 0C 52 0F 01 4C 24 FE 5A 83 C2 0C 8B 1A 9D}
	condition:
		$0 at entrypoint
}
rule _ASProtect_v12_
{
	meta:
		description = "ASProtect v1.2"
	strings:
		$0 = {68 01 C3 AA ??}
	condition:
		$0 at entrypoint
}
rule _y0das_Crypter_v12_
{
	meta:
		description = "y0da's Crypter v1.2"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D 81 ED B9 ?? ?? 8D BD 8B F7}
	condition:
		$0 at entrypoint
}
rule _PECompact_v110b4_
{
	meta:
		description = "PECompact v1.10b4"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 87 DD 8B 85 95 60 40 01 85 03 60 40 66 C7 85 60 40 90 90 BB}
	condition:
		$0 at entrypoint
}
rule _Crunch_v40_
{
	meta:
		description = "Crunch v4.0"
	strings:
		$0 = {E8 58 83 E8 05 50 5F 57 8B F7 81 EF 83 C6 39 BA 8B DF B9 0B 8B}
	condition:
		$0 at entrypoint
}
rule _PEtite_v13_
{
	meta:
		description = "PEtite v1.3"
	strings:
		$0 = {66 9C 60 50 8B D8 03 ?? 68 54 BC ?? ?? 6A ?? FF 50 14 8B}
	condition:
		$0 at entrypoint
}
rule _ASPack_v10802_
{
	meta:
		description = "ASPack v1.08.02"
	strings:
		$0 = {60 EB 03 5D FF E5 E8 F8 FF FF FF 81 ED 1B 6A 44 ?? BB 10 6A 44 ?? 03 DD 2B 9D}
	condition:
		$0 at entrypoint
}
rule _PECompact_v140b5__v140b6_
{
	meta:
		description = "PECompact v1.40b5 - v1.40b6"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 87 DD 8B 85 A6 A0 40 01 85 03 A0 40 66 C7 85 A0 40 90 90 01 85 9E A0 40}
	condition:
		$0 at entrypoint
}
rule _eXpressor_v12x_
{
	meta:
		description = "eXpressor v1.2x"
	strings:
		$0 = {55 8B EC 83 EC 64 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 33 2E}
	condition:
		$0 at entrypoint
}
rule _Wise_Installer_Stub_v11010291_
{
	meta:
		description = "Wise Installer Stub v1.10.1029.1"
	strings:
		$0 = {53 55 8B E8 33 DB EB 60 0D 0A 0D 0A 57 57 50 61 63 6B 33}
	condition:
		$0 at entrypoint
}
rule _ASPack_v2xx_
{
	meta:
		description = "ASPack v2.xx"
	strings:
		$0 = {60 E8 70 05 ?? ?? EB}
		$1 = {60 ?? ??}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _UPX_v0896__v102__v105__v122_Modified_
{
	meta:
		description = "UPX v0.89.6 - v1.02 / v1.05 - v1.22 Modified"
	strings:
		$0 = {01 DB 07 8B 1E 83 EE FC 11 DB 8A 07 EB B8 01 ?? ?? ?? 01 DB 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73}
	condition:
		$0 at entrypoint
}
rule _y0das_Crypter_v1x__Modified_
{
	meta:
		description = "y0da's Crypter v1.x / Modified"
	strings:
		$0 = {E9 12 ?? ?? ?? E9 FB FF FF FF C3 68 64 FF}
	condition:
		$0 at entrypoint
}
rule _PE_Packer_
{
	meta:
		description = "PE Packer"
	strings:
		$0 = {E8 04 8B EC 5D C3 33 C0 5D 8B FD 81 ED 33 26 40 81 EF 83 EF 05 89 AD 88 27 40 8D 9D 07 29 40 8D B5 62 28 40 46}
	condition:
		$0 at entrypoint
}
rule _ExeBundle_v30_standard_loader_
{
	meta:
		description = "ExeBundle v3.0 (standard loader)"
	strings:
		$0 = {60 BE ?? F0 40 ?? 8D BE ?? 20 FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 ?? ?? ?? 01 DB 75 07 8B 1E 83 EE FC 11 ?? ?? ??}
	condition:
		$0 at entrypoint
}
rule _EXE32Pack_v137_
{
	meta:
		description = "EXE32Pack v1.37"
	strings:
		$0 = {3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC 02 81 3B DB 74 01 BE 5D 8B D5 81 ED DC 8D}
	condition:
		$0 at entrypoint
}
rule _UPX_v051_
{
	meta:
		description = "UPX v0.51"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 58 83 E8 3D 50 8D B8 FF 57 8D B0}
	condition:
		$0 at entrypoint
}
rule _SmokesCrypt_v12_
{
	meta:
		description = "SmokesCrypt v1.2"
	strings:
		$0 = {74 07 75 05 19 32 67 E8 E8 74 1F 75 1D E8 68 39 44 CD 59 9C 50 74 0A 75 08 E8 59 C2 04 55 8B EC E8 F4 FF FF FF 56 57 53 78 0F 79 0D E8 34 99 47 49 34 33 EF 31 34 52 47 23 68 A2 AF 47}
	condition:
		$0 at entrypoint
}
rule _PEBundle_v244_
{
	meta:
		description = "PEBundle v2.44"
	strings:
		$0 = {EB 06 68 C3 9C 60 BD B9 02 B0 90 8D BD F3 AA 01 AD FF}
	condition:
		$0 at entrypoint
}
rule _UPXShit_006_
{
	meta:
		description = "UPXShit 0.06"
	strings:
		$0 = {8C E0 0B C5 8C E0 0B C4 03 C5 74 ?? 74 ?? 8B}
	condition:
		$0 at entrypoint
}
rule _FSG_v133_
{
	meta:
		description = "FSG v1.33"
	strings:
		$0 = {89 25 A8 11 40 ?? BF ?? 31 C0 B9 ?? 29 F9 FC F3}
	condition:
		$0 at entrypoint
}
rule _ASPack_v211b_
{
	meta:
		description = "ASPack v2.11b"
	strings:
		$0 = {60 E8 02 ?? ?? ?? EB 09 5D 55 81 ED 39 39 44 ?? C3 E9 59}
	condition:
		$0 at entrypoint
}
rule _PE_Crypt_v102_
{
	meta:
		description = "PE Crypt v1.02"
	strings:
		$0 = {E8 ?? ?? ?? ?? 5B 83 EB 52 4E 44}
	condition:
		$0 at entrypoint
}
rule _PECompact_v120__v1201_
{
	meta:
		description = "PECompact v1.20 - v1.20.1"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 87 DD 8B 85 A6 70 40 01 85 03 70 40 66 C7 85 70 40 90 90 01 85 9E 70 40}
	condition:
		$0 at entrypoint
}
rule _CipherWall_SelfExtratorDecryptor_GUI_v15_
{
	meta:
		description = "CipherWall Self-Extrator/Decryptor (GUI) v1.5"
	strings:
		$0 = {90 61 BE ?? 10 42 ?? 8D BE ?? ?? FE FF C7 87 C0 20 02 ?? 0B 6E 5B 9B 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 ?? ?? ?? 01 DB 75 07 8B 1E}
	condition:
		$0 at entrypoint
}
rule _PECompact_v126b1__v126b2_
{
	meta:
		description = "PECompact v1.26b1 - v1.26b2"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 80 40 87 DD 8B 85 A6 80 40 01 85 03 80 40 66 C7 85 ?? 80 40 90 90 01 85 9E 80 40}
	condition:
		$0 at entrypoint
}
rule _tElock_v095_
{
	meta:
		description = "tElock v0.95"
	strings:
		$0 = {E9 59 E4 FF}
	condition:
		$0 at entrypoint
}
rule _NeoLite_v200_
{
	meta:
		description = "NeoLite v2.00"
	strings:
		$0 = {8B 44 24 04 23 05 50 E8 83 C4 04 FE 05 0B C0}
		$1 = {E9 4E 65 6F 4C 69 74}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PCGuard_v405d_v410d_v415d_
{
	meta:
		description = "PC-Guard v4.05d, v4.10d, v4.15d"
	strings:
		$0 = {FC 55 50 E8 ?? ?? ?? ?? 5D 60 E8 03 ?? ?? ?? 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 0B 61 B8 30 D2 40 ?? EB 01 E3 60 E8 03 ?? ?? ?? D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 2B}
	condition:
		$0 at entrypoint
}
rule _EZIP_v10_
{
	meta:
		description = "EZIP v1.0"
	strings:
		$0 = {BB D0 01 40 ?? BF ?? 10 40 ?? BE 53 E8 0A ?? ?? ?? 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02}
	condition:
		$0 at entrypoint
}
rule _DBPE_v210_
{
	meta:
		description = "DBPE v2.10"
	strings:
		$0 = {EB 20 9C 55 57 56 52 51 53 9C E8 5D 81 ED EB 58 75 73 65 72 33 32 2E}
		$1 = {EB 20 40 9C 55 57 56 52 51 53 9C E8 5D 81 ED 9C 6A 10 73 0B EB 02 C1 51}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _ASPack_v108_
{
	meta:
		description = "ASPack v1.08"
	strings:
		$0 = {90 90 75 01 FF}
		$1 = {90 90 90 75 01 FF}
		$2 = {90 90 90 75 90}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}
rule _ASPack_v21_
{
	meta:
		description = "ASPack v2.1"
	strings:
		$0 = {60 E9 3D}
	condition:
		$0 at entrypoint
}
rule _PEtite_v14_
{
	meta:
		description = "PEtite v1.4"
	strings:
		$0 = {66 9C 60 50 8B D8 03 68 54 BC 6A FF 50 14 8B}
		$1 = {B8 66 9C 60 50 8B D8 03 68 54 BC 6A FF 50 18 8B CC 8D A0 54 BC 8B C3 8D 90 E0 15}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _ExeBundle_v30_small_loader_
{
	meta:
		description = "ExeBundle v3.0 (small loader)"
	strings:
		$0 = {65 78 65 73 68 6C 2E 64 6C 6C C0}
	condition:
		$0 at entrypoint
}
rule _PE_Protect_v09_
{
	meta:
		description = "PE Protect v0.9"
	strings:
		$0 = {E8 E8 01 60 01 AD B3 27 40}
	condition:
		$0 at entrypoint
}
rule _Obsidium_v10061_
{
	meta:
		description = "Obsidium v1.0.0.61"
	strings:
		$0 = {E8 47}
	condition:
		$0 at entrypoint
}
rule _XCR_v011_
{
	meta:
		description = "XCR v0.11"
	strings:
		$0 = {60 9C E8 8B DD 5D 81 ED 89}
	condition:
		$0 at entrypoint
}
rule _ASPack_v108x_
{
	meta:
		description = "ASPack v1.08.x"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D BB 03}
	condition:
		$0 at entrypoint
}
rule _PENinja_
{
	meta:
		description = "PENinja"
	strings:
		$0 = {5D 8B C5 81 ED B2 2C 40 ?? 2B 85 94 3E 40 ?? 2D 71 02 ?? ?? 89 85 98 3E 40 ?? 0F B6 B5 9C 3E 40 ?? 8B}
	condition:
		$0 at entrypoint
}
rule _Nullsoft_PIMP_Install_System_v1x_
{
	meta:
		description = "Nullsoft PIMP Install System v1.x"
	strings:
		$0 = {FF 60 FF CA FF ?? BA DC 0D E0 40 ?? 50 ?? 60 ?? 70 ??}
	condition:
		$0 at entrypoint
}
rule _VBOX_v43_MTE_
{
	meta:
		description = "VBOX v4.3 MTE"
	strings:
		$0 = {36 3E 26 8A C0 60}
	condition:
		$0 at entrypoint
}
rule _TASM__MASM_
{
	meta:
		description = "TASM / MASM"
	strings:
		$0 = {E9 E5 E2 FF}
	condition:
		$0 at entrypoint
}
rule _JDPack_
{
	meta:
		description = "JDPack"
	strings:
		$0 = {EB 66 87}
	condition:
		$0 at entrypoint
}
rule _KGCrypt_vxx_
{
	meta:
		description = "KGCrypt vx.x"
	strings:
		$0 = {60 66 9C BB 80 B3 ?? 10 40 ?? 90 4B 83 FB FF 75 F3 66 9D}
	condition:
		$0 at entrypoint
}
rule _ASPack_v2000_
{
	meta:
		description = "ASPack v2.000"
	strings:
		$0 = {60 E8 72 05 ?? ?? EB}
	condition:
		$0 at entrypoint
}
rule _FSG_v12_
{
	meta:
		description = "FSG v1.2"
	strings:
		$0 = {BB D0 01 40 ?? BF ?? 10 40 ?? BE 53 E8 0A ?? ?? ?? 02 D2 75 05 8A 16 46 12 D2 C3 B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14}
	condition:
		$0 at entrypoint
}
rule _ORiEN_v211_DEMO_
{
	meta:
		description = "ORiEN v2.11 (DEMO)"
	strings:
		$0 = {60 E8 01 E8 83 C4 04 E8 01 E9 5D 81 ED D3 22 40 E8 04 02 E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47}
	condition:
		$0 at entrypoint
}
rule _DBPE_v153_
{
	meta:
		description = "DBPE v1.53"
	strings:
		$0 = {9C 6A 10 73 0B EB 02 C1 51 E8 06 C4 11 73 F7 5B CD 83 C4 04 EB 02 99 EB FF 0C 24 71 01 E8 79 E0 7A 01 75 83 C4 04 9D EB 01 75 68 5F 20 40 E8 B0 EF FF FF 72 03 73 01 75}
	condition:
		$0 at entrypoint
}
rule _SVKProtector_v132_
{
	meta:
		description = "SVK-Protector v1.32"
	strings:
		$0 = {64 8B 05 55 8B EC 6A FF 68 40 68 40 50 64 89 25 83 EC 08 50 53 56 57 89 65 E8 C7 45}
	condition:
		$0 at entrypoint
}
rule _PC_Shrinker_v029_
{
	meta:
		description = "PC Shrinker v0.29"
	strings:
		$0 = {BD 01 AD E3 38 40 FF B5 DF 38}
	condition:
		$0 at entrypoint
}
rule _Anticrack_Software_Protector_v109_ACProtect_
{
	meta:
		description = "Anticrack Software Protector v1.09 (ACProtect)"
	strings:
		$0 = {60 E8 01 ?? ?? ?? ?? ??}
		$1 = {60 ?? ?? E8 01 ?? ?? ?? 83 04 24 06}
		$2 = {90}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}
rule _PEEncrypt_v40b_JunkCode_
{
	meta:
		description = "PEEncrypt v4.0b (JunkCode)"
	strings:
		$0 = {E8 5B 83 EB 05 EB 04 52 4E 44 21 EB 02 CD 20}
	condition:
		$0 at entrypoint
}
rule _UPX_v071__v072_
{
	meta:
		description = "UPX v0.71 - v0.72"
	strings:
		$0 = {80 7C 24 08 01 0F 85 ?? 60 BE 8D BE 57 83 CD}
	condition:
		$0 at entrypoint
}
rule _PE_Crypt32_v102_
{
	meta:
		description = "PE Crypt32 v1.02"
	strings:
		$0 = {E8 ?? ?? ?? ?? 5B 83 EB 05 EB 04 52 4E 44 21 EB 02 CD 20}
	condition:
		$0 at entrypoint
}
rule _EXE32Pack_v139_
{
	meta:
		description = "EXE32Pack v1.39"
	strings:
		$0 = {3B 74 02 81 83 55 3B 74 02 81 53 3B 74 01 02 81 E8 3B 74 01 5D 8B D5 81}
	condition:
		$0 at entrypoint
}
rule _PECompact_v094_
{
	meta:
		description = "PECompact v0.94"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 5D 55 5B 81 ED 8B 85 01 85 66 C7}
	condition:
		$0 at entrypoint
}
rule _UPX_v103__v104_
{
	meta:
		description = "UPX v1.03 - v1.04"
	strings:
		$0 = {60 BE 8D BE C7 87 57 83 CD FF EB 0E 8A 06 46 88 07 47 01 DB 75 07}
	condition:
		$0 at entrypoint
}
rule _PE_Pack_v099_
{
	meta:
		description = "PE Pack v0.99"
	strings:
		$0 = {74}
	condition:
		$0 at entrypoint
}
rule _Krypton_v05_
{
	meta:
		description = "Krypton v0.5"
	strings:
		$0 = {E8 5D 81 ED 64 A1 30 84 C0 74 64 A1 20 0B C0}
	condition:
		$0 at entrypoint
}
rule _EP_v20_
{
	meta:
		description = "EP v2.0"
	strings:
		$0 = {60 BE ?? B0 42 ?? 8D BE ?? 60 FD FF C7 87 B0 E4 02 ?? 31 3C 4B DF 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 ?? ?? ?? 01 DB ?? ?? ??}
	condition:
		$0 at entrypoint
}
rule _CreateInstall_Stub_vxx_
{
	meta:
		description = "CreateInstall Stub vx.x"
	strings:
		$0 = {55 E8 5D 83 ED 06 8B C5 55 60 89 AD 2B}
	condition:
		$0 at entrypoint
}
rule _NFO_v1x_modified_
{
	meta:
		description = "NFO v1.x modified"
	strings:
		$0 = {EB 01 9A E8 3D ?? ?? ?? EB 01 9A E8 EB 01 ?? ?? EB 01 9A E8 2C 04 ?? ?? EB}
	condition:
		$0 at entrypoint
}
rule _PC_Shrinker_v020_
{
	meta:
		description = "PC Shrinker v0.20"
	strings:
		$0 = {BD 01 AD 55 39 40 8D B5 35 39}
	condition:
		$0 at entrypoint
}
rule _CExe_v10a_
{
	meta:
		description = "CExe v1.0a"
	strings:
		$0 = {53 60 BD 8D 45 8D 5D E8}
	condition:
		$0 at entrypoint
}
rule _Exe_Shield_v27_
{
	meta:
		description = "Exe Shield v2.7"
	strings:
		$0 = {EB 06 68 40 85 06 ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 ?? 87 DD 8B 85 E6 90 40 ?? 01 85 33 90 40 ?? 66 C7 85 30 90 40 ?? 90 90 01 85 DA 90 40 ??}
	condition:
		$0 at entrypoint
}
rule _WWPack32_v1x_
{
	meta:
		description = "WWPack32 v1.x"
	strings:
		$0 = {E8 ?? ?? ?? ?? 5D 8B CD 81 ED 7A 29 40 ?? 89 AD 0F 6D}
	condition:
		$0 at entrypoint
}
rule _ASPack_v102b_
{
	meta:
		description = "ASPack v1.02b"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D 81 ED 96 78 43 ?? B8 90 78 43 ?? 03}
		$1 = {60 E8 5D 81 ED AE 98 43 B8 A8 98 43 03 C5 2B 85 18 9D 43 89 85 24 9D 43 80 BD 0E 9D}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _ASPack_v103b_
{
	meta:
		description = "ASPack v1.03b"
	strings:
		$0 = {60 E8 5D 81 ED CE 3A 44 B8 C8 3A 44 03 C5 2B 85 B5 3E 44 89 85 C1 3E 44 80 BD AC 3E}
		$1 = {60 E8 5D 81 ED B8 03 C5 2B 85 12 9D 89 85 1E 9D 80 BD 08}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _EXE_Stealth_v11_
{
	meta:
		description = "EXE Stealth v1.1"
	strings:
		$0 = {EB ?? 60 EB ?? E8 ?? ?? ?? ?? 5D 81 ED D3 26}
	condition:
		$0 at entrypoint
}
rule _PE_Pack_v10_
{
	meta:
		description = "PE Pack v1.0"
	strings:
		$0 = {FC 8B 35 70 01 40 83 EE 40 6A 40 68 30}
	condition:
		$0 at entrypoint
}
rule _FSG_v11_
{
	meta:
		description = "FSG v1.1"
	strings:
		$0 = {4B 45 52 4E 45 4C 33 32 2E 64 6C 6C ?? ?? 4C 6F 61 64 4C 69 62 72 61 72 79 41 ?? ?? 47 65 74 50 72 6F 63 41 64 64 72 65 73}
	condition:
		$0 at entrypoint
}
rule _PECrypter_
{
	meta:
		description = "PE-Crypter"
	strings:
		$0 = {60 E8 01 ?? ?? ?? E8 83 C4 04 E8 01 ?? ?? ?? E9 5D 81 ED D3 22 40 ?? E8 04 02 ?? ?? E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47}
	condition:
		$0 at entrypoint
}
rule _PECompact_v110b5_
{
	meta:
		description = "PECompact v1.10b5"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 ?? 87 DD 8B 85 9A 60 40 01 85 03 60 40 66 C7 85 60 40 90 90 01 85 92 60 40}
	condition:
		$0 at entrypoint
}
rule _SecuPack_v15_
{
	meta:
		description = "SecuPack v1.5"
	strings:
		$0 = {60 B8 B8 8A 14 08 80 F2 88 14 08 41 83 F9 75}
	condition:
		$0 at entrypoint
}
rule _PE_Lock_v106_
{
	meta:
		description = "PE Lock v1.06"
	strings:
		$0 = {60 E8 5D 83 ED 06 80 BD E0 04 01 0F 84}
	condition:
		$0 at entrypoint
}
rule _ASProtect_v11_MTEb_
{
	meta:
		description = "ASProtect v1.1 MTEb"
	strings:
		$0 = {90 60 E8 1B E9}
	condition:
		$0 at entrypoint
}
rule _tElock_v099_
{
	meta:
		description = "tElock v0.99"
	strings:
		$0 = {50 E8 58 25 F0 FF FF 8B C8 83 C1 60 51 83 C0 40 83 EA 06 52 FF 20 9D}
	condition:
		$0 at entrypoint
}
rule _DBPE_v233_
{
	meta:
		description = "DBPE v2.33"
	strings:
		$0 = {EB 20 40 9C 55 57 56 52 51 53 9C E8 5D 81}
	condition:
		$0 at entrypoint
}
rule _NeoLite_v20_
{
	meta:
		description = "NeoLite v2.0"
	strings:
		$0 = {8D 50 12 2B C9 B1 1E 8A 02 34 77 88 02 42 E2 F7 C8}
	condition:
		$0 at entrypoint
}
rule _eXpressor_v10x__v11x_
{
	meta:
		description = "eXpressor v1.0x / v1.1x"
	strings:
		$0 = {55 8B EC 81 EC D4 01 ?? ?? 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 32 2E}
	condition:
		$0 at entrypoint
}
rule _VBOX_v42_MTE_
{
	meta:
		description = "VBOX v4.2 MTE"
	strings:
		$0 = {0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B}
	condition:
		$0 at entrypoint
}
rule _y0das_Crypter_v11_
{
	meta:
		description = "y0da's Crypter v1.1"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D 81 ED F3 1D 40 ?? B9 7B 09 ?? ?? 8D BD 3B 1E 40 ?? 8B F7}
	condition:
		$0 at entrypoint
}
rule _Blade_Joiner_v15_
{
	meta:
		description = "Blade Joiner v1.5"
	strings:
		$0 = {60 BD}
	condition:
		$0 at entrypoint
}
rule _tElock_v04x__v05x_
{
	meta:
		description = "tElock v0.4x - v0.5x"
	strings:
		$0 = {E9 ?? ?? ?? ?? 60 E8 ?? ?? ?? ?? 58 83 C0}
	condition:
		$0 at entrypoint
}
rule _PESHiELD_v01b_MTE_
{
	meta:
		description = "PESHiELD v0.1b MTE"
	strings:
		$0 = {60 E8 41 4E 41 4B 49 4E 5D 83 ED 06 EB 02 EA}
	condition:
		$0 at entrypoint
}
rule _Stones_PE_Encryptor_v113_
{
	meta:
		description = "Stone's PE Encryptor v1.13"
	strings:
		$0 = {53 51 52 56 57 55 E8 5D 81 ED 42 30 40 FF 95 32 35 40 B8 37 30 40 03 C5 2B 85 1B 34 40 89 85 27 34 40}
	condition:
		$0 at entrypoint
}
rule _tElock_v07x__v084_
{
	meta:
		description = "tElock v0.7x - v0.84"
	strings:
		$0 = {60 E8 02 ?? ?? ?? CD 20 E8 ?? ?? ?? ?? 5E 2B C9 58 74}
	condition:
		$0 at entrypoint
}
rule _Macromedia_Windows_Flash_ProjectorPlayer_v30_
{
	meta:
		description = "Macromedia Windows Flash Projector/Player v3.0"
	strings:
		$0 = {83 EC 44 56 FF 15 24 41 43 ?? 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB}
	condition:
		$0 at entrypoint
}
rule _DEF_v10_
{
	meta:
		description = "DEF v1.0"
	strings:
		$0 = {55 57 56 52 51 53 E8 ?? ?? ?? ?? 5D 8B D5 81 ED 23 35}
	condition:
		$0 at entrypoint
}
rule _WinZip_32bit_SFX_v6x_module_
{
	meta:
		description = "WinZip 32-bit SFX v6.x module"
	strings:
		$0 = {53 FF 15 ?? B3 22 38 18 74 03 80 C3 FE 8A 48 01 40 33 D2 3A CA 74 0A 3A CB 74 06 8A 48 01 40 EB F2 38 10 74 01 40 FF}
	condition:
		$0 at entrypoint
}
rule _ASProtect_v11_MTE_
{
	meta:
		description = "ASProtect v1.1 MTE"
	strings:
		$0 = {90 60 E9}
	condition:
		$0 at entrypoint
}
rule _WinZip_32bit_SFX_v8x_module_
{
	meta:
		description = "WinZip 32-bit SFX v8.x module"
	strings:
		$0 = {E9 ?? ?? ?? ?? ?? ?? 90 90 90 ?? ??}
	condition:
		$0 at entrypoint
}
rule _UPX_v0896__v102__v105__v122_Delphi_stub_
{
	meta:
		description = "UPX v0.89.6 - v1.02 / v1.05 - v1.22 (Delphi) stub"
	strings:
		$0 = {01 DB 07 8B 1E 83 EE FC 11 DB ED B8 01 ?? ?? ?? 01 DB 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 77}
	condition:
		$0 at entrypoint
}
rule _SVKProtector_v111_
{
	meta:
		description = "SVK-Protector v1.11"
	strings:
		$0 = {60 EB 03 C7 84 E8 EB 03 C7 84 9A E8 ?? ?? ?? ?? 5D 81 ED 10 ?? ?? ?? EB 03 C7 84 E9 64 A0 23 ?? ?? ??}
	condition:
		$0 at entrypoint
}
rule _ASPR_Stripper_v2x_unpacked_
{
	meta:
		description = "ASPR Stripper v2.x unpacked"
	strings:
		$0 = {55 8B EC 81 C4 E4 FE FF FF 53 56 57 33 C0 89 45 F0 89}
	condition:
		$0 at entrypoint
}
rule _PENinja_modified_
{
	meta:
		description = "PENinja modified"
	strings:
		$0 = {60 9C BE 8B FE B9 BB 44 52 4F 4C AD 33}
	condition:
		$0 at entrypoint
}
rule __Protector_v1111_DDeMPE_Engine_v09_DDeMCI_v092_
{
	meta:
		description = "*** Protector v1.1.11 (DDeM->PE Engine v0.9, DDeM->CI v0.9.2)"
	strings:
		$0 = {E9 ?? ?? E9 ?? ?? E9 ?? ??}
	condition:
		$0 at entrypoint
}
rule _CICompress_v10_
{
	meta:
		description = "CICompress v1.0"
	strings:
		$0 = {90 61 BE ?? 10 42 ?? 8D BE ?? ?? FE FF C7 87 C0 20 02 ?? F9 89 C7 6A 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 ?? ?? ?? 01 DB 75 07 8B 1E}
	condition:
		$0 at entrypoint
}
rule _kryptor_3_
{
	meta:
		description = "kryptor 3"
	strings:
		$0 = {E8 03 E9 EB 6C 58 40 FF}
	condition:
		$0 at entrypoint
}
rule _PESHiELD_v0251_
{
	meta:
		description = "PESHiELD v0.251"
	strings:
		$0 = {B8 B9 83 F9 ?? 7E 06 80 30 40 E2 F5 E9}
	condition:
		$0 at entrypoint
}
rule _Exe_Shield_v29_
{
	meta:
		description = "Exe Shield v2.9"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D 81 ED FB 1D 40 ?? B9 7B 09 ?? ?? 8B F7}
	condition:
		$0 at entrypoint
}
rule _Program_Protector_XP_v10_
{
	meta:
		description = "Program Protector XP v1.0"
	strings:
		$0 = {50 60 29 C0 64 FF 30 E8 5D 83 ED 3C 89 E8 89 A5 14 2B 85 1C 89 85 1C 8D 85 27 03 50 8B 85 C0 0F 85 C0 8D BD 5B 03 8D B5 43}
	condition:
		$0 at entrypoint
}
rule _PECompact_v110b2_
{
	meta:
		description = "PECompact v1.10b2"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 87 DD 8B 85 95 60 40 01 85 03 60 40 66 C7 85 60 40 90 90 BB}
	condition:
		$0 at entrypoint
}
rule _Lockless_Intro_Pack_
{
	meta:
		description = "Lockless Intro Pack"
	strings:
		$0 = {55 89 E5 53 83 EC 48 55 B8 FF FF FF FF 50 50 68 E0 3E 42 ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 68 C0 69 44 ?? E8 E4 80 FF FF 59 E8 4E 29 ?? ?? E8 C9 0D ?? ?? 85 C0 75 08 6A FF E8 6E}
	condition:
		$0 at entrypoint
}
rule _PEtite_v20_
{
	meta:
		description = "PEtite v2.0"
	strings:
		$0 = {B8 6A 68 64 FF 35 64 89 25 66 9C 60}
	condition:
		$0 at entrypoint
}
rule _ASPack_v10803_
{
	meta:
		description = "ASPack v1.08.03"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D 81 ED 0A 4A 44 ?? BB 04 4A 44 ?? 03}
		$1 = {60 E8 ?? ?? ?? ?? 5D 81 ED 0A 4A 44 ?? BB 04 4A 44 ?? 03 DD 2B 9D B1 50 44 ?? 83 BD AC 50 44 ?? ?? 89 9D BB}
		$2 = {60 E8 41 06 ?? ?? EB}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}
rule _PECompact_v090__v092_
{
	meta:
		description = "PECompact v0.90 - v0.92"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 5D 55 58 81 ED 2B 85 01 85 50 B9}
	condition:
		$0 at entrypoint
}
rule _NeoLite_vxx_
{
	meta:
		description = "NeoLite vx.x"
	strings:
		$0 = {E9 9B ?? ?? ??}
	condition:
		$0 at entrypoint
}
rule _Special_EXE_Password_Protector_v10_
{
	meta:
		description = "Special EXE Password Protector v1.0"
	strings:
		$0 = {55 57 51 53 E8 5D 8B C5 81 ED 2B 85 83 E8 09 89 85 0F}
	condition:
		$0 at entrypoint
}
rule _NoodleCrypt_v20_
{
	meta:
		description = "NoodleCrypt v2.0"
	strings:
		$0 = {55 8B EC 83 EC 2C 53 56 33 F6 57 56 89 75 DC 89 75 F4 BB A4 9E 40 ?? FF 15 60 70 40 ?? BF C0 B2 40 ?? 68 04 01 ?? ?? 57 50 A3 AC B2 40 ?? FF 15 4C 70 40 ?? 56 56 6A 03 56 6A 01 68 ?? ?? ??}
	condition:
		$0 at entrypoint
}
rule _PECompact_v0978_
{
	meta:
		description = "PECompact v0.978"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 49 87 40 87 DD 8B 85 CE}
	condition:
		$0 at entrypoint
}
rule _PEtite_v21_
{
	meta:
		description = "PEtite v2.1"
	strings:
		$0 = {B8 68 64 FF 35 64 89 25 66 9C 60}
	condition:
		$0 at entrypoint
}
rule _PEncrypt_v30_
{
	meta:
		description = "PEncrypt v3.0"
	strings:
		$0 = {E9 ?? F0 0F}
	condition:
		$0 at entrypoint
}
rule _XCR_v012_
{
	meta:
		description = "XCR v0.12"
	strings:
		$0 = {93 71 08 8B D8 78 E2 9C 33 C3 60 79 CE E8 01 83 C4 04 E8 AB FF FF FF 2B E8 03 C5 FF}
	condition:
		$0 at entrypoint
}
rule _UG2002_Cruncher_v03b3_
{
	meta:
		description = "UG2002 Cruncher v0.3b3"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 58 83 E8 3D 50 8D B8 FF 57 8D B0 D8 01 83 CD FF 31 DB 01 DB 75 07 8B 1E 83 EE FC 11 DB 73 0B 8A 06 46 88 07 47 EB EB}
	condition:
		$0 at entrypoint
}
rule _tElock_v051_
{
	meta:
		description = "tElock v0.51"
	strings:
		$0 = {C1 EE ?? 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 ?? ?? ?? ?? 5E 83 C6 8B FE 68 79 01 59 EB}
	condition:
		$0 at entrypoint
}
rule _Shrinker_v33_
{
	meta:
		description = "Shrinker v3.3"
	strings:
		$0 = {83 3D B4 55 8B EC 56 57 75 6B 68 ?? 01 ?? ?? E8 0B ?? ?? 83 C4 04 8B 75 08 A3 B4 85 F6 74 23 83 7D 0C 03 77 1D 68}
	condition:
		$0 at entrypoint
}
rule _CrunchPE_
{
	meta:
		description = "Crunch/PE"
	strings:
		$0 = {55 E8 5D 83 ED 06 8B C5 55 60 89 AD 2B 85 89 85 80 BD 75 09 C6}
	condition:
		$0 at entrypoint
}
rule _Inno_Setup_Module_v129_
{
	meta:
		description = "Inno Setup Module v1.2.9"
	strings:
		$0 = {55 8B EC 81 EC 14 ?? ?? 53 56 57 6A ?? FF 15 68 FF 15 85 C0 74}
	condition:
		$0 at entrypoint
}
rule _tElock_v071b7_
{
	meta:
		description = "tElock v0.71b7"
	strings:
		$0 = {60 E8 F9 11 ?? ?? C3}
	condition:
		$0 at entrypoint
}
rule _Exe_Shield_v27b_
{
	meta:
		description = "Exe Shield v2.7b"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D 81 ED 0B 20 40 ?? B9 EB 08 ?? ?? 8D BD 53 20 40 ?? 8B F7 AC}
	condition:
		$0 at entrypoint
}
rule _SOFTWrapper_for_Win9xNT_Evaluation_Version_
{
	meta:
		description = "SOFTWrapper for Win9x/NT (Evaluation Version)"
	strings:
		$0 = {6A ?? E8 ?? ?? A3}
	condition:
		$0 at entrypoint
}
rule _Obsidium_vxxxx_
{
	meta:
		description = "Obsidium vx.x.x.x"
	strings:
		$0 = {E9 5D 01 ?? ?? CE D1 CE CE 0D 0A 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 0D 0A 2D 20 4F 52 69 45}
	condition:
		$0 at entrypoint
}
rule _LameCrypt_v10_
{
	meta:
		description = "LameCrypt v1.0"
	strings:
		$0 = {54 E8 ?? ?? ?? ?? 5D 8B C5 81 ED F6 73 40 ?? 2B 85 87 75 40 ?? 83 E8}
	condition:
		$0 at entrypoint
}
rule _Shrinker_v34_
{
	meta:
		description = "Shrinker v3.4"
	strings:
		$0 = {58 60 8B E8 55 33 F6 68 48 01 E8 49 01}
	condition:
		$0 at entrypoint
}
rule _Obsidium_v10059_Final_
{
	meta:
		description = "Obsidium v1.0.0.59 Final"
	strings:
		$0 = {E8 AF}
	condition:
		$0 at entrypoint
}
rule _CrypKey_v5__v6_
{
	meta:
		description = "CrypKey v5 - v6"
	strings:
		$0 = {E8 B8 E8 90 02 83 F8 75 07 6A E8 FF 15 49 8F 40 A9 80 74}
	condition:
		$0 at entrypoint
}
rule _DAEMON_Protect_v067_
{
	meta:
		description = "DAEMON Protect v0.6.7"
	strings:
		$0 = {BE 01 40 ?? 6A 05 59 80 7E 07 ?? 74 11 8B}
	condition:
		$0 at entrypoint
}
rule _EXE_Stealth_v27_
{
	meta:
		description = "EXE Stealth v2.7"
	strings:
		$0 = {EB ?? 60 EB ?? E8 ?? ?? ?? ?? 5D 81 ED B0 27}
	condition:
		$0 at entrypoint
}
rule _PEBundle_v02__v20x_
{
	meta:
		description = "PEBundle v0.2 - v2.0x"
	strings:
		$0 = {9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 40 87 DD 01 AD 01}
	condition:
		$0 at entrypoint
}
rule _The_Guard_Library_
{
	meta:
		description = "The Guard Library"
	strings:
		$0 = {B8 EF BE AD DE 50 6A FF 15 10 19 40 E9 AD FF FF}
	condition:
		$0 at entrypoint
}
rule _CodeSafe_v20_
{
	meta:
		description = "CodeSafe v2.0"
	strings:
		$0 = {CC 90 90 EB 0B 01 50 51 52 53 54 61 33 61 2D 35 CA D1 07 52 D1 A1}
	condition:
		$0 at entrypoint
}
rule _PE_Intro_v10_
{
	meta:
		description = "PE Intro v1.0"
	strings:
		$0 = {EB 03 CD 20 EB EB 01 EB 1E EB 01 EB EB 02 CD 20 9C EB 03}
	condition:
		$0 at entrypoint
}
rule _Nullsoft_Install_System_v20b2_v20b3_
{
	meta:
		description = "Nullsoft Install System v2.0b2, v2.0b3"
	strings:
		$0 = {55 8B EC 81 EC ?? ?? 56 57 6A BE 59 8D}
	condition:
		$0 at entrypoint
}
rule _PE_Lock_NT_v203_
{
	meta:
		description = "PE Lock NT v2.03"
	strings:
		$0 = {EB CD CD EB EB EB EB CD E8 E9 50}
	condition:
		$0 at entrypoint
}
rule _Macromedia_Windows_Flash_ProjectorPlayer_v40_
{
	meta:
		description = "Macromedia Windows Flash Projector/Player v4.0"
	strings:
		$0 = {83 EC 44 56 FF 15 70 61 44 ?? 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB 0C 3C 20 7E 08 8A 46 01 46 3C 20 7F F8 8A 06 84 C0 74}
	condition:
		$0 at entrypoint
}
rule _ASPack_v211_
{
	meta:
		description = "ASPack v2.11"
	strings:
		$0 = {60 E8 02 ?? ?? ?? EB 09 5D 55 81 ED 39 39 44 ?? C3 E9 3D}
	condition:
		$0 at entrypoint
}
rule _PCGuard_v303d_v305d_
{
	meta:
		description = "PC-Guard v3.03d, v3.05d"
	strings:
		$0 = {FC 55 50 E8 ?? ?? ?? ?? 5D EB}
	condition:
		$0 at entrypoint
}
rule _Hasp_dongle_Alladin_
{
	meta:
		description = "Hasp dongle (Alladin)"
	strings:
		$0 = {10 02 D0 51 0F ??}
	condition:
		$0 at entrypoint
}
rule _BJFnt_v11b_
{
	meta:
		description = ".BJFnt v1.1b"
	strings:
		$0 = {EB 02 69 B1 83 EC 04 EB 03 CD 20 EB EB 01 EB 9C EB 01 EB}
	condition:
		$0 at entrypoint
}
rule _ASProtect_v11_BRS_
{
	meta:
		description = "ASProtect v1.1 BRS"
	strings:
		$0 = {68 01}
	condition:
		$0 at entrypoint
}
rule _Protection_Plus_vxx_
{
	meta:
		description = "Protection Plus vx.x"
	strings:
		$0 = {40 20 FF ?? ?? ?? ?? ?? ?? ?? BE ?? 60 40 ?? 8D BE ?? B0 FF}
	condition:
		$0 at entrypoint
}
rule _PEX_v099_
{
	meta:
		description = "PEX v0.99"
	strings:
		$0 = {60 E8 01 83 C4 04 E8 01 5D}
		$1 = {55 8B EC A1 85 C0 74 09 B8 01 ?? ?? ?? 5D C2 0C ?? 8B 45 0C 57 56 53 8B 5D}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PECompact_v146_
{
	meta:
		description = "PECompact v1.46"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 87 DD 8B 85 A6 A0 40 01 85 03 A0 40 66 C7 85 A0 40 90 90 01 85 9E A0 40}
	condition:
		$0 at entrypoint
}
rule _ASProtect_v21x_
{
	meta:
		description = "ASProtect v2.1x"
	strings:
		$0 = {BB E9 60 9C FC BF B9 F3 AA 9D 61 C3 55 8B}
	condition:
		$0 at entrypoint
}
rule _CrunchPE_v10xx_
{
	meta:
		description = "Crunch/PE v1.0.x.x"
	strings:
		$0 = {55 E8 5D 83 ED 06 8B C5 55 60 89 AD 2B 85 89 85 55 BB 03 DD 53 64 67 FF 36 64 67 89}
	condition:
		$0 at entrypoint
}
rule _UPX_v070_
{
	meta:
		description = "UPX v0.70"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 83 CD FF 31 DB 5E 8D BE FA FF 57 66 81 87 81 C6 B3 01 EB 0A 8A 06 46 88 07 47 01 DB 75}
	condition:
		$0 at entrypoint
}
rule _PEtite_vxx_
{
	meta:
		description = "PEtite vx.x"
	strings:
		$0 = {E9 F5 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4}
	condition:
		$0 at entrypoint
}
rule _Ding_Boys_PElock_Phantasm_v15b3_
{
	meta:
		description = "Ding Boy's PE-lock Phantasm v1.5b3"
	strings:
		$0 = {9C 55 57 56 52 51 53 9C FA E8 5D 81 ED 5B 53 40 B0 E8 5E 83 C6 11 B9 27 30 06 46 49 75}
	condition:
		$0 at entrypoint
}
rule _Exe_Shield_vxx_
{
	meta:
		description = "Exe Shield vx.x"
	strings:
		$0 = {EB 06 68 90 1F 06 ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F}
	condition:
		$0 at entrypoint
}
rule _SoftWrap_
{
	meta:
		description = "SoftWrap"
	strings:
		$0 = {9C 60 8B 44 24 24 E8 5D 81 ED 50 E8 ED 02 8C C0 0F}
	condition:
		$0 at entrypoint
}
rule _PECompact_v110b6_
{
	meta:
		description = "PECompact v1.10b6"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 87 DD 8B 85 9A 60 40 01 85 03 60 40 66 C7 85 60 40 90 90 01 85 92 60 40}
	condition:
		$0 at entrypoint
}
rule _ASPack_v107b_DLL_
{
	meta:
		description = "ASPack v1.07b (DLL)"
	strings:
		$0 = {90 90 90 75}
	condition:
		$0 at entrypoint
}
rule _PECompact_v1242__v1243_
{
	meta:
		description = "PECompact v1.24.2 - v1.24.3"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 87 DD 8B 85 A6 70 40 01 85 03 70 40 66 C7 85 70 40 90 90 01 85 9E 70 40 BB}
	condition:
		$0 at entrypoint
}
rule _tElock_v060_
{
	meta:
		description = "tElock v0.60"
	strings:
		$0 = {60 E8 BD 10 ?? ?? C3 83 E2 ?? F9 75 FA}
	condition:
		$0 at entrypoint
}
rule _ASPack_v105b_
{
	meta:
		description = "ASPack v1.05b"
	strings:
		$0 = {90 75 ??}
	condition:
		$0 at entrypoint
}
rule _EXECryptor_v151x_
{
	meta:
		description = "EXECryptor v1.5.1.x"
	strings:
		$0 = {E8 24 8B 4C 24 0C C7 01 17 01 C7 81 B8 31 C0 89}
	condition:
		$0 at entrypoint
}
rule _CrunchPE_v20xx_
{
	meta:
		description = "Crunch/PE v2.0.x.x"
	strings:
		$0 = {EB 10 55 E8 5D 81 ED 18 8B C5 55 60 9C 2B 85 89 85 FF}
	condition:
		$0 at entrypoint
}
rule _tElock_v090_
{
	meta:
		description = "tElock v0.90"
	strings:
		$0 = {E9 7E E9 FF}
	condition:
		$0 at entrypoint
}
rule _UPX_v103__v104_Modified_
{
	meta:
		description = "UPX v1.03 - v1.04 Modified"
	strings:
		$0 = {01 DB 07 8B 1E 83 EE FC 11 DB ED B8 01 ?? ?? ?? 01 DB 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73}
	condition:
		$0 at entrypoint
}
rule _Nullsoft_PIMP_Install_System_v13x_
{
	meta:
		description = "Nullsoft PIMP Install System v1.3x"
	strings:
		$0 = {83 EC 5C 53 55 56 57 FF}
	condition:
		$0 at entrypoint
}
rule _PECompact_v147__v150_
{
	meta:
		description = "PECompact v1.47 - v1.50"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 80 40 87 DD 8B 85 A2 80 40 01 85 03 80 40 66 C7 85 80 40 90 90 01 85 9E 80 40}
	condition:
		$0 at entrypoint
}
rule _PEBundle_v20b5__v23_
{
	meta:
		description = "PEBundle v2.0b5 - v2.3"
	strings:
		$0 = {9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 40 87 DD 83}
	condition:
		$0 at entrypoint
}
rule _Gleam_v100_
{
	meta:
		description = "Gleam v1.00"
	strings:
		$0 = {55 8B EC 83 C4 F0 60 E8 51 FF FF}
	condition:
		$0 at entrypoint
}
rule _Shrink_Wrap_v14_
{
	meta:
		description = "Shrink Wrap v1.4"
	strings:
		$0 = {55 8B EC 83 C4 F0 53 56 57 33 C0 89 45 F0 B8 CC 3A 40 E8 E0 FC FF FF 33 C0 55 68 EA 3C 40 64 FF 30 64 89 20 6A 68 80 6A 03 6A 6A 01}
	condition:
		$0 at entrypoint
}
rule _PE_Crypt_v100v101_
{
	meta:
		description = "PE Crypt v1.00/v1.01"
	strings:
		$0 = {E8 5B 83 EB 05 EB 04 52 4E}
	condition:
		$0 at entrypoint
}
rule _eXpressor_v13x_
{
	meta:
		description = "eXpressor v1.3x"
	strings:
		$0 = {55 8B EC 83 EC 58 53 56 57 83 65 DC ?? F3 EB 0C 65 58 50 72 2D 76 2E 31 2E 34}
	condition:
		$0 at entrypoint
}
rule _PC_PE_Encryptor_Alpha_preview_
{
	meta:
		description = "PC PE Encryptor Alpha preview"
	strings:
		$0 = {66 ?? 66}
	condition:
		$0 at entrypoint
}
rule _Microsoft_CAB_SFX_module_
{
	meta:
		description = "Microsoft CAB SFX module"
	strings:
		$0 = {55 8B EC 83 EC 44 56 FF 15 94 13 42 ?? 8B F0 B1 22 8A 06 3A C1 75 13 8A 46 01 46 3A C1 74 04 84 C0 75 F4 38 0E 75 0D 46 EB 0A 3C 20 7E}
	condition:
		$0 at entrypoint
}
rule _Install_Stub_32bit_
{
	meta:
		description = "Install Stub 32-bit"
	strings:
		$0 = {60 E8 5D 8B D5 81 ED 2B 95 81 EA 06 89 95 83 BD}
	condition:
		$0 at entrypoint
}
rule _SPEC_b3_
{
	meta:
		description = "SPEC b3"
	strings:
		$0 = {BA ?? FF E2 BA ?? B8 89 02 83 C2 03 B8 89 02 83 C2 FD FF}
	condition:
		$0 at entrypoint
}
rule _Ding_Boys_PElock_Phantasm_v10__v11_
{
	meta:
		description = "Ding Boy's PE-lock Phantasm v1.0 / v1.1"
	strings:
		$0 = {9C 55 57 56 52 51 53 9C FA E8 ?? ?? ?? ?? 5D 81 ED 5B 53 40 ??}
	condition:
		$0 at entrypoint
}
rule _tElock_v070_
{
	meta:
		description = "tElock v0.70"
	strings:
		$0 = {60 E8 ED 10 ?? ?? C3}
	condition:
		$0 at entrypoint
}
rule _tElock_v041x_
{
	meta:
		description = "tElock v0.41x"
	strings:
		$0 = {C1 EE ?? 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 ?? ?? ?? ?? 5E 83 C6 52 8B FE 68 79 01 59 EB 01 EB AC 54 E8 03 5C EB}
	condition:
		$0 at entrypoint
}
rule _PE_Lock_NT_v202c_
{
	meta:
		description = "PE Lock NT v2.02c"
	strings:
		$0 = {EB 02 C7 85 1E EB 03 CD 20 C7 9C EB 02 69 B1 60 EB 02 EB}
	condition:
		$0 at entrypoint
}
rule _PC_Shrinker_v071_
{
	meta:
		description = "PC Shrinker v0.71"
	strings:
		$0 = {55 50 E8 5D EB 01 E3 60 E8 03 D2 EB 0B 58 EB 01 48 40 EB}
	condition:
		$0 at entrypoint
}
rule _Ding_Boys_PElock_v007_
{
	meta:
		description = "Ding Boy's PE-lock v0.07"
	strings:
		$0 = {55 57 56 52 51 53 E8 ?? ?? ?? ?? 5D 8B D5 81 ED 0D 39}
	condition:
		$0 at entrypoint
}
rule _WinRAR_32bit_SFX_Module_
{
	meta:
		description = "WinRAR 32-bit SFX Module"
	strings:
		$0 = {55 8B EC 81 EC 04 ?? ?? 53 56 57 6A FF 15}
	condition:
		$0 at entrypoint
}
rule _PE_Password_v02_SMTSMF_
{
	meta:
		description = "PE Password v0.2 SMT/SMF"
	strings:
		$0 = {52 51 55 57 64 67 A1 30 ?? 85 C0 78 0D E8 58 83 C0 07 C6}
	condition:
		$0 at entrypoint
}
rule _Krypton_v04_
{
	meta:
		description = "Krypton v0.4"
	strings:
		$0 = {54 E8 5D 8B C5 81 ED 71 44 2B 85 64 60 EB 43}
	condition:
		$0 at entrypoint
}
rule _PECompact_v122_
{
	meta:
		description = "PECompact v1.22"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 87 DD 8B 85 A6 70 40 01 85 03 70 40 66 C7 85 70 40 90 90 01 85 9E 70 40 BB}
	condition:
		$0 at entrypoint
}
rule _PECompact_v110b3_
{
	meta:
		description = "PECompact v1.10b3"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 87 DD 8B 85 95 60 40 01 85 03 60 40 66 C7 85 60 40 90 90 BB}
	condition:
		$0 at entrypoint
}
rule _PKLITE32_v11_
{
	meta:
		description = "PKLITE32 v1.1"
	strings:
		$0 = {68 68 68 ?? ?? ?? ??}
		$1 = {50 4B 4C 49 54 45 33 32 20 43 6F 70 79 72 69 67 68 74 20}
		$2 = {53 E8 ?? ?? ?? ?? 5B 8B C3}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}
rule _ASProtect_v12x_
{
	meta:
		description = "ASProtect v1.2x"
	strings:
		$0 = {68 01 ?? E8 01 ?? ?? ?? C3}
	condition:
		$0 at entrypoint
}
rule _ASPack_v10804_
{
	meta:
		description = "ASPack v1.08.04"
	strings:
		$0 = {A8 03 61 75 08 B8 01 C2 0C 68 C3 8B 85 26 04 8D 8D 3B 04 51 50 FF}
	condition:
		$0 at entrypoint
}
rule _Thinstall_vxx_
{
	meta:
		description = "Thinstall vx.x"
	strings:
		$0 = {60 E8 5D 81 ED E8 0D}
	condition:
		$0 at entrypoint
}
rule _PEncrypt_v31_
{
	meta:
		description = "PEncrypt v3.1"
	strings:
		$0 = {B8 93 ?? 55 50 67 64 FF 36 ?? ?? 67 64 89 26 ?? ?? BD 4B 48 43 42 B8 04 ?? ?? ?? CC 3C 04 75 04 90 90 C3 90 67 64 8F 06 ?? ?? 58 5D BB ?? ?? 40 ?? 33 C9 33}
	condition:
		$0 at entrypoint
}
rule _tElock_v080_
{
	meta:
		description = "tElock v0.80"
	strings:
		$0 = {60 E8 ?? ?? C3}
	condition:
		$0 at entrypoint
}
rule _CodeLock_vxx_
{
	meta:
		description = "Code-Lock vx.x"
	strings:
		$0 = {83 EC 10 53 56 57 E8 C4}
	condition:
		$0 at entrypoint
}
rule _Virogen_Crypt_v075_
{
	meta:
		description = "Virogen Crypt v0.75"
	strings:
		$0 = {33 C0 8B B8 ?? 8B 90 04 85 FF 74 1B 33 C9 50 EB 0C 8A 04 39 C0 C8 04 34 1B 88 04 39 41 3B CA 72 F0}
	condition:
		$0 at entrypoint
}
rule _Spalsher_v10__v30_
{
	meta:
		description = "Spalsher v1.0 - v3.0"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D 81 ED 06 ?? ?? ?? 89 AD 8C 01 ?? ?? 8B C5 2B 85 FE 75 ?? ?? 89 85 3E}
	condition:
		$0 at entrypoint
}
rule _PECompact_v125_
{
	meta:
		description = "PECompact v1.25"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 87 DD 8B 85 A6 70 40 01 85 03 70 40 66 C7 85 70 40 90 90 01 85 9E 70 40 BB}
	condition:
		$0 at entrypoint
}
rule _NeoLite_v10_
{
	meta:
		description = "NeoLite v1.0"
	strings:
		$0 = {8B 44 24 04 8D 54 24 FC 23 05 E8 FF 35 50 FF}
		$1 = {E9}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _UPX_v062_
{
	meta:
		description = "UPX v0.62"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 58 83 E8 3D 50 8D B8 FF 57 66 81 87 8D B0 EC 01 83 CD FF 31 DB EB 07 90 8A 06 46 88 07 47 01 DB 75}
	condition:
		$0 at entrypoint
}
rule _tElock_v098_
{
	meta:
		description = "tElock v0.98"
	strings:
		$0 = {E9 25 E4 FF}
	condition:
		$0 at entrypoint
}
rule _FSG_v10_
{
	meta:
		description = "FSG v1.0"
	strings:
		$0 = {BB D0 01 40 BF 10 40 BE FC B2 80 8A 06 46 88 07 47 02 D2 75 05 8A}
	condition:
		$0 at entrypoint
}
rule _CrunchPE_v30xx_
{
	meta:
		description = "Crunch/PE v3.0.x.x"
	strings:
		$0 = {EB}
	condition:
		$0 at entrypoint
}
rule _PECompact_v099_
{
	meta:
		description = "PECompact v0.99"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB C4 84 40 87 DD 8B 85 49}
	condition:
		$0 at entrypoint
}
rule _ASPack_v212_
{
	meta:
		description = "ASPack v2.12"
	strings:
		$0 = {60 E8 03 ?? ?? ?? E9 EB 04 5D 45 55 C3 E8}
		$1 = {A8 03 ?? ?? 61 75 08 B8 01 ?? ?? ?? C2 0C ?? 68 ?? ?? ?? ?? C3 8B 85 26 04 ?? ?? 8D 8D 3B 04 ?? ?? 51 50 FF}
	condition:
		$0 at entrypoint or $1 at entrypoint
}
rule _PCGuard_v500d_
{
	meta:
		description = "PC-Guard v5.00d"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D EB}
	condition:
		$0 at entrypoint
}
rule _ASProtect_v11_MTEc_
{
	meta:
		description = "ASProtect v1.1 MTEc"
	strings:
		$0 = {60 E9}
	condition:
		$0 at entrypoint
}
rule _NFO_v10_
{
	meta:
		description = "NFO v1.0"
	strings:
		$0 = {60 9C 8D}
	condition:
		$0 at entrypoint
}
rule _tElock_v042_
{
	meta:
		description = "tElock v0.42"
	strings:
		$0 = {C1 EE ?? 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 ?? ?? ?? ?? 5E 83 C6 5E 8B FE 68 79 01 59 EB 01 EB AC 54 E8 03 5C EB}
	condition:
		$0 at entrypoint
}
rule _UPX_Protector_v10x_
{
	meta:
		description = "UPX Protector v1.0x"
	strings:
		$0 = {B8 B9 33 D2 EB 01 0F 56 EB 01 0F E8 03 ?? ?? ?? EB 01 0F EB 01 0F 5E EB}
	condition:
		$0 at entrypoint
}
