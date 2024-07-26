# API-To-ETW
[![stability-experimental](https://img.shields.io/badge/stability-experimental-orange.svg)](https://github.com/mkenney/software-guides/blob/master/STABILITY-BADGES.md#experimental)

A ghidra script to find all ETW write metadata for each API in a PE file, including any associated public symbols.

See [[BSides Brisbane] Kernel ETW is the best ETW](https://github.com/jdu2600/conference_talks/blob/main/2024-07-bsidesbne-KernelETW.pdf) for more details.

## Why?
Many ETW events are extremely useful for cyber security, but are not (well) documented. :disappointed:

For example, the `Kernel-Audit-API-Calls` provider sounds interesting, but all of the events are called `task_nn`.

![Microsoft-Windows-Kernel-Audit-API-Calls events](Microsoft-Windows-Kernel-Audit-API-Calls.png)

Previously, this was a manual reversing process. Now you can run this Ghidra script on `ntoskrnl.exe` and grep the results. :smiley:

| Function | EVENT_DESCRIPTOR Symbol | Id | CallPath |
|--- | --- |--- |--- |--- |--- |--- |--- |--- |
| PsSetLoadImageNotifyRoutine | KERNEL_AUDIT_API_PSSETLOADIMAGENOTIFYROUTINE | 1 | [PsSetLoadImageNotifyRoutine->PsSetLoadImageNotifyRoutineEx] |
| PsSetLoadImageNotifyRoutineEx | KERNEL_AUDIT_API_PSSETLOADIMAGENOTIFYROUTINE | 1 | [PsSetLoadImageNotifyRoutineEx] |
| NtTerminateProcess | KERNEL_AUDIT_API_TERMINATEPROCESS | 2 | [NtTerminateProcess->PspLogAuditTerminateRemoteProcessEvent] |
| NtCreateSymbolicLinkObject |  KERNEL_AUDIT_API_CREATESYMBOLICLINKOBJECT | 3 | [NtCreateSymbolicLinkObject] |
| IoCreateSymbolicLink | KERNEL_AUDIT_API_CREATESYMBOLICLINKOBJECT | 3 | [IoCreateSymbolicLink->IoCreateSymbolicLink2->ObCreateSymbolicLink] |
| NtSetContextThread | KERNEL_AUDIT_API_SETCONTEXTTHREAD | 4 | [NtSetContextThread] |
| NtOpenProcess | KERNEL_AUDIT_API_OPENPROCESS | 5 | [NtOpenProcess->PsOpenProcess] |
| NtAlpcOpenSenderProcess | KERNEL_AUDIT_API_OPENPROCESS | 5 | [NtAlpcOpenSenderProcess->PsOpenProcess] |
| NtOpenThread | KERNEL_AUDIT_API_OPENTHREAD | 6 | [NtOpenThread->PsOpenThread] |
| NtAlpcOpenSenderThread | KERNEL_AUDIT_API_OPENTHREAD | 6 | [NtAlpcOpenSenderThread->PsOpenThread] |
| IoRegisterLastChanceShutdownNotification | KERNEL_AUDIT_API_IOREGISTERLASTCHANCESHUTDOWNNOTIFICATION | 7 | [IoRegisterLastChanceShutdownNotification->IopLogAuditIoRegisterNotificationEvent] |
| IoRegisterShutdownNotification | KERNEL_AUDIT_API_IOREGISTERSHUTDOWNNOTIFICATION | 8 | [IoRegisterShutdownNotification->IopLogAuditIoRegisterNotificationEvent] |

There are also trace providers (TraceLogging and WPP) which are not documented by design. This level of debug tracing is intended for the developer only, but might also prove useful for security. For example, the 
`Microsoft.Windows.Kernel.SysEnv` TraceLogging provider includes a `SetVariable` event.


## Sample Output
 [syscalls in ntoskrnl.exe](ntoskrnl.exe.csv)
  * A full dump of all kernel ETW events is much, much longer.
  * By default I also only emit the shallowest events in the call graph. The deeper ones are usually error handling.

## How good is it?
The quality of the output depends on the quality of the decompilation. With the help of public symbols, Ghidra is pretty good out of the box for Windows binaries. But if you're not getting the results you want, some manual reversing might help. 

Sometimes you'll encounter a novel design pattern not supported by the script. For example, `lsasrv.dll` stores provider handles in [a generic table using Adelson-Velsky/Landis (AVL) trees](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlinitializegenerictableavl). So, in order to automatically extract the provider guids, the script would need to be updated to understand the GenericTableAvl APIs.

I'm still missing support for some event write edge cases, but I've tried to flag these in the script output.

## How do I use it?
 1. Import the file to analyse - such as `ntoskrnl.exe`
 1. Open the Code Browser - but don't autoanalyze just yet. We want types and symbols available.
 1. Add relevant type archives first. I've provided a [minimal ETW header](etw_all_register_write), but I use [ntddk64.gdt](https://github.com/zimawhit3/Ghidra-Windows-Data-Types/blob/main/ntddk64.gdt) (or [winapi64.gdt](https://github.com/zimawhit3/Ghidra-Windows-Data-Types/blob/main/winapi32.gdt) for usermode binaries).
 1. Load the PDB.  This will trigger autoanalyze - so go make a :coffee:...
 1. Add the local path to this repo to Script Manager's dicectories and refresh the list.
 1. Run `DumpEtwWrites.java`

## References
 * https://www.riverloopsecurity.com/blog/2019/05/pcode/
 * [ghidra_scripts](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/ghidra_scripts/)
 * [ghidra_docs](https://ghidra.re/ghidra_docs/api/)
 
## Inspiration
 * https://github.com/hunters-forge/API-To-Event
 * [How do I detect technique X in Windows?](https://drive.google.com/file/d/19AhMG0ZCOt0IVsPZgn4JalkdcUOGq4DK/view), DerbyCon 2019
 * https://pathtofile.run/codereview/re/python/2020/01/11/ghidra.html
 * https://blog.tofile.dev/2020/01/11/ghidra.html
 * https://blog.xpnsec.com/analysing-rpc-with-ghidra-neo4j/
 
## Related Work
 * https://github.com/jdu2600/Windows10EtwEvents
 * https://github.com/jsecurity101/TelemetrySource
 * https://github.com/airbus-cert/etwbreaker - an IDA plugin