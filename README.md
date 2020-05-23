# Api-To-Etw
[![stability-experimental](https://img.shields.io/badge/stability-experimental-orange.svg)](https://github.com/mkenney/software-guides/blob/master/STABILITY-BADGES.md#experimental)

Uses ghidra to find all ETW write metadata for each API in a PE file.

Also outputs any public symbols associated with the ETW write call. 

## Why?
Some ETW providers are extremely useful for cyber security, but are not documented. :-(

![Microsoft-Windows-Kernel-Audit-API-Calls events](Microsoft-Windows-Kernel-Audit-API-Calls.png)

Previously, if you're lucky, Matt would do some reversing and [tweet](https://twitter.com/mattifestation/status/1140655593318993920) about them.

Now you can run my ghidra script on ntoskrnl.exe and grep the results...

| Function | Provider Guid | EVENT_DESCRIPTOR Symbol | Id | Version | Channel | Level | Opcode | Task | Keyword |
|--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |
| NtSetSystemInformation | e02a841c&#8209;75a3&#8209;4fa7&#8209;afc8&#8209;ae09cf9b7f23 | KERNEL_AUDIT_API_PSSETLOADIMAGENOTIFYROUTINE | 1 | 0 | 0 | 4 | 0 | 0 | 0x0 |
| NtTerminateProcess | e02a841c-75a3-4fa7-afc8-ae09cf9b7f23 | KERNEL_AUDIT_API_TERMINATEPROCESS | 2 | 0 | 0 | 4 | 0 | 0 | 0x0 |
| NtCreateSymbolicLinkObject | e02a841c-75a3-4fa7-afc8-ae09cf9b7f23 | KERNEL_AUDIT_API_CREATESYMBOLICLINKOBJECT | 3 | 0 | 0 | 4 | 0 | 0 | 0x0 |
| NtSetContextThread | e02a841c-75a3-4fa7-afc8-ae09cf9b7f23 | KERNEL_AUDIT_API_SETCONTEXTTHREAD | 4 | 0 | 0 | 4 | 0| 0 | 0x0 |
| NtOpenProcess | e02a841c-75a3-4fa7-afc8-ae09cf9b7f23 | KERNEL_AUDIT_API_OPENPROCESS | 5 | 0 | 0 | 4 | 0 | 0 | 0x0 |
| NtAlpcOpenSenderProcess | e02a841c-75a3-4fa7-afc8-ae09cf9b7f23 | KERNEL_AUDIT_API_OPENPROCESS | 5 | 0 | 0 | 4 | 0 | 0 | 0x0 |
| NtSetSystemInformation | e02a841c-75a3-4fa7-afc8-ae09cf9b7f23 | KERNEL_AUDIT_API_OPENPROCESS | 5 | 0 | 0 | 4 | 0 | 0 | 0x0 |
| NtOpenThread | e02a841c-75a3-4fa7-afc8-ae09cf9b7f23 | KERNEL_AUDIT_API_OPENTHREAD | 6 | 0 | 0 | 4 | 0 | 0 | 0x0 |
| NtAlpcOpenSenderThread | e02a841c-75a3-4fa7-afc8-ae09cf9b7f23 | KERNEL_AUDIT_API_OPENTHREAD | 6 | 0 | 0 | 4 | 0 | 0 | 0x0 |

:TODO: events 7 & 8 are missing. But this grep was only on a run for syscalls (not all exports) - so missed the kernel APIs like IoRegister.

## Sample Output
 * [syscalls in ntoskrnl.exe](ntoskrnl.exe.csv)

There are a *lot* of events that get generated for a lot of APIs. Fixing the call depth information etc should hopefully help determining which are the interesting events.

And I'm still missing some event writes.

## TODO
 * fix the (export) call depth tracker as a relevance measure
 * experiment with 'last CALL symbol before ETW write' as a relevance measure
 * handle a few of the rarer ETW write variations - [Etw|Event]WriteString, EtwErite[Start|End]Scenario, ntdll!EtwEvent*, EtwEventWriteFull, SeEtwWriteKMCveEvent, EtwWriteUMSecurityEvent
 * handle simple edges cases - REGHANDLE local parameter
 * handle complex cases - wrapper functions
 * handle [INDIRECT](https://ghidra.re/courses/languages/html/additionalpcode.html) pcode? - aka ghidra's "data-flow algorithms do not have enough information to follow the data-flow directly"
 * test it on a user-mode PE - e.g. lsasrv.dll
 * interactive (single function) mode?
 * experiment with also outputting the external calls - e.g. to make it easier to map Win32 API -> system call -> ETW event
 * better performance?
 * csv2json - calculate prevalance of event, sort by relevance
 * (maybe) handle classic provider ETW writes - [TraceEvent](https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-traceevent) etc
 * ghidra headless automation?
 
 Working backwards from ETW write call sites is *much* quicker, but I hit issues with broken call graphs (and a lack of sufficient ghidra-fu). When I'm working forwards I can programatically define any missing functions, but I end up recalculating lots of ETW write parameters. A two-parse approach might be faster and still complete? i.e. quickly test reachabilty completeness forwards - and then work backwards. 

## References
 * Ghidra's [ShowCCallsScript.java](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/ghidra_scripts/ShowCCallsScript.java)
 * Ghidra's [ShowConstantUse.java](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/ghidra_scripts/ShowConstantUse.java)
 * https://www.riverloopsecurity.com/blog/2019/05/pcode/

## Inspiration
 * https://github.com/hunters-forge/API-To-Event
 * https://twitter.com/mattifestation/status/1140655593318993920 - Microsoft-Windows-Kernel-Audit-API-Calls events
 * https://twitter.com/pathtofile - "I'm working on a side project to teach myself ghidra scripting"
 * [How do I detect technique X in Windows?](https://drive.google.com/file/d/19AhMG0ZCOt0IVsPZgn4JalkdcUOGq4DK/view), DerbyCon 2019
 * https://blog.xpnsec.com/analysing-rpc-with-ghidra-neo4j/