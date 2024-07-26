
/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Outputs all calls to EtwWrite* reachable from each function along with provider and event metadata.
//
// functions.txt - functions to analyze. Defaults to exports otherwise.
// ignore.txt    - functions to ignore - especially error handling paths.
//
// Kernel-mode ETW functions are prefixed with Etw, the Win32 equivalents with Event and the native API ones with EtwEvent.
// All APIs take the same parameters so this script should partially work on every binary.
//
//@category Functions.ETW
//@author jdu2600

import java.io.*;
import java.lang.Math.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.*;
import generic.stl.Pair;

import docking.options.OptionsService;
import ghidra.app.cmd.function.*;
import ghidra.app.decompiler.*;
import ghidra.app.script.*;
import ghidra.app.services.*;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.util.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.*;
import ghidra.util.exception.*;


public class DumpEtwWrites extends GhidraScript {

    // **********************
    // Configurable Settings
    // quickscan: stop processing after maxEvents have been found, or extraCallDepth/maxExportCallDepth has been reached
    private Boolean quickScan = true;
    // maxEvents: maximum events to report per API
    private int maxEvents = 100;
    // maxCallDepth: maximum call depth to search for events
    private int maxCallDepth = 5;
    // extraCallDepth: maximum additional call depth to search for events
    private int extraCallDepth = 1;
    // maxExportCallDepth: maximum depth of exported functions to search
    private int maxExportCallDepth = 0;
    // debugPrint: verbose logging
    private Boolean debugPrint = false;
    // decompileTimeoutSeconds: per-function timeout for Ghidra decompilation
    private int decompileTimeoutSeconds = 60;
    // **********************

    private String functionsFile = "functions.txt"; // analyse these functions
    private String ignoreFile = "ignore.txt";       // ignore these functions

    private DataType eventDescriptorType = null;
    private DataType ucharType = null;
    private DataType ushortType = null;
    private DataType ulonglongType = null;
    private DataType guidType = null;
    private DataType stringType = null;
    private DecompInterface decomplib = null;

    private Set<String> exports = null;
    private Set<String> functions = null;
    private Set<String> ignored = null;
    private PrintWriter csv = null;
    private Dictionary<Long,Pair<String,String>> providerGuidMap = new Hashtable<Long,Pair<String,String>>(); // Address, (Guid, GuidSymbol)
    
    private List<String> notYetImplemented = new LinkedList<String>();
        
    @Override
    public void run() throws Exception {
        printf("\n\n--==[ DumpEtwWrites ]==--\n");
        printf(" * %s\n", currentProgram.getName());
        
        if(quickScan)
            printf(" * quick scan mode - maxCallDepth=%d extraCallDepth=%d maxExportCallDepth=%d\n", maxCallDepth, extraCallDepth, maxExportCallDepth);
        else
            printf(" * full scan mode - finding all reachable ETW writes\n");
    
        // we want the names of all exports - as we use these as a measure of relevance 
        // for a given ETW write
        exports = new HashSet<String>();
        for(Symbol symbol : currentProgram.getSymbolTable().getAllSymbols(false))
            if (symbol.isExternalEntryPoint())
                exports.add(symbol.getName());
        printf(" * found %d exports\n", exports.size());
        
        // provide a list of the functions that you want to analyse, finding the ETW writes    
        // if not provided, all exports will be parsed
        // e.g. this could be the list of Native API syscalls 
        // or a list of RPC methods e.g. using xpn's RpcEnum
        try {
            functions = new HashSet<String>(Files.readAllLines(Paths.get(functionsFile)));
            printf(" * analysing %d functions from %s\n", functions.size(), FileSystems.getDefault().getPath(functionsFile));
        }
        catch(Exception e) {
            if(exports.contains("NtQuerySystemInformation")) {
                functions = new HashSet<String>();
                for(String func : exports) {
                    if(func.startsWith("Nt"))
                        functions.add(func);
                    if(func.startsWith("Zw"))
                        functions.add(func.replaceFirst("Zw", "Nt"));
                }
                for(String func : functions)
                    if(func.startsWith("Nt"))
                        exports.add(func);
                printf(" * %s not provided - analysing all %d syscalls instead\n", functionsFile, functions.size());
            } else {
                functions = exports;
                printf(" * %s not provided - analysing all %d exports instead\n", functionsFile, functions.size());
            }
            Files.write(FileSystems.getDefault().getPath("exports.txt"), exports);
        }
        
        // optionally provide a list of functions you want to ignore
        // e.g. common error handling functions like KeBugCheckEx
        try {
            ignored = new HashSet<String>(Files.readAllLines(Paths.get(ignoreFile)));
            printf(" * ignoring %d functions\n", ignored.size());
        }
        catch(Exception e) 
        {
            ignored = new HashSet<String>();
        }
        
        // prepare the output file
        File csvFile = new File(currentProgram.getName() + ".csv");
        csvFile.delete();
        printf(" * output will be written to %s\n", csvFile.getAbsolutePath());
        csv = new PrintWriter(csvFile);
        csv.println("Function,ProviderGuid,ProviderSymbol,ReghandleSymbol,WriteFunction,EventDescriptorSymbol,Id,Version,Channel,Level,Opcode,Task,Keyword,ContainingFunction,CallDepth,ExportedCallDepth,CallPath");
        
        setUpDataTypes();
        setUpDecompiler(currentProgram);
        if (!decomplib.openProgram(currentProgram)) {
            println("Decompiler Setup Error: " + decomplib.getLastMessage());
            return;
        }
               
        try {
            /* first we cache the REGHANDLE address and the GUID of all register ETW Providers so that we can later  
             * match ETW events to the Provider GUIDs
             *
             * providers are registered via [Etw|Event]Register(LPCGUID ProviderId, .., .., PREGHANDLE RegHandle)
             *
             * https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-etwregister
             * https://docs.microsoft.com/en-us/windows/win32/api/evntprov/nf-evntprov-eventregister                        
             */
            for(String etwRegisterFuncName : etwRegisterFuncs)    {
                List<Function> etwRegisterFuncList = getGlobalFunctions(etwRegisterFuncName);
                if(etwRegisterFuncList.size() > 1) {
                    println("Script aborted: Found " + etwRegisterFuncList.size() + " instances of " + etwRegisterFuncName);
                    return;
                }
                if(etwRegisterFuncList.size() == 0)
                    continue;
                
                Function etwRegisterFunc = etwRegisterFuncList.get(0);
                Reference[] refs = this.getSymbolAt(etwRegisterFunc.getEntryPoint()).getReferences(null);
                printf(" * found %d %s calls\n", refs.length, etwRegisterFuncName);
                for (Reference ref : refs) {
                    if (monitor.isCancelled())
                        break;
                    analyseEtwRegisterCall(ref);
                }
            }
            
            /* now for each function, output the parameters of all ETW writes ( GUID, Event Id etc)
             */
            for(String functionName : functions)    {
                List<Function> functionList = getGlobalFunctions(functionName);
                if(functionList.size() == 0) {
                    printf(" * %s - function not found\n", functionName);
                    continue;
                }
                if(functionList.size() > 1)
                    throw new Exception("Script aborted: Found " + functionList.size() + " instances of " + functionName);
                                
                // decompile function & output ETW writes
                analyseFunction(functionList.get(0));
            }            
        }
        finally {
            decomplib.dispose();
            csv.close();
        }
       
        // if this isn't empty, then I haven't implemented all possible code paths yet :-(
        if (notYetImplemented.size() > 0)
            printf(" ---------- TODO ----------\n");
        for(String todo : notYetImplemented) {
            printf("%s\n", todo);
        }        
    }

    
    /*
     * EtwRegister - cache all global REGHANDLE addresses and registration details
     */
    List<String> etwRegisterFuncs = Arrays.asList("EtwRegister", "EventRegister", "EtwEventRegister", "EtwNotificationRegister", "EventNotificationRegister", "EtwEventNotificationRegister");
    public void analyseEtwRegisterCall(Reference ref) throws Exception {
        Address refAddr = ref.getFromAddress();
        if (refAddr == null)
            throw new NotFoundException("Reference.getFromAddress() == null");
        if(refAddr.getOffset() == 0)
            return;
        
        // skip 'data' references - e.g. import / export offsets 
        Data refData = getDataAt(refAddr);
        if (refData == null)
            refData = getDataContaining(refAddr);
        if (refData != null && 
                (refData.getDataType().toString().startsWith("_IMAGE_RUNTIME_FUNCTION_ENTRY") ||
                refData.getDataType().toString().startsWith("GuardCfgTableEntry") ||
                 refData.getDataType().isEquivalent(new IBO32DataType()) ||
                 refData.getDataType().isEquivalent(new DWordDataType()))) 
            return;
        
        Function refFunc = currentProgram.getFunctionManager().getFunctionContaining(refAddr);
        if (refFunc == null) {
            int transactionID = currentProgram.startTransaction("attempting findFunctionEntry()");
            CreateFunctionCmd createCmd = new CreateFunctionCmd(refAddr, true);
            createCmd.applyTo(currentProgram);
            currentProgram.endTransaction(transactionID, true);
            refFunc = currentProgram.getFunctionManager().getFunctionContaining(refAddr);
        }
        if (refFunc == null)
            // programmatic resolution failed - user should try manually finding and defining the function
            throw new NotFoundException("getFunctionContaining == null; refAddr=" + refAddr); 
        
        ClangTokenGroup cCode = decomplib.decompileFunction(refFunc, decompileTimeoutSeconds, monitor).getCCodeMarkup();
        if (cCode == null)
            throw new Exception("[CALL EtwRegister] Decompile Error: " + decomplib.getLastMessage());
        
        try {
            boolean found = cacheProviderReghandle(refFunc, cCode, refAddr);
            if(!found) {
                // Could not resolve provider GUID(s) yet.
                // :TODO: Search a level deeper.
                Reference[] refRefs = this.getSymbolAt(refFunc.getEntryPoint()).getReferences(null);
                logTODO("Search the " +  refRefs.length + " calls to " + refFunc.getName() + " for EtwRegister calls");
            }
        } catch(NotYetImplementedException e) {
            logTODO(e.getMessage());
        }
    }
    
    private boolean cacheProviderReghandle(Function f, ClangNode astNode, Address refAddr) throws Exception {
        if(astNode == null || astNode.getMinAddress() == null)
            return false;  // leaf node
        
        if (astNode.getMaxAddress() == null)
            throw new InvalidInputException("ClangNode.getMaxAddress() is null");
               
        boolean found = false;
        Stack<Function> callPath = new Stack<Function>(); // helps with back tracing constants, and determining relevance  
        callPath.push(f);
        
        // have we found the call(s) yet?
        if (refAddr.getPhysicalAddress().equals(astNode.getMaxAddress()) && astNode instanceof ClangStatement) {
            ClangStatement stmt = (ClangStatement) astNode;
            PcodeOp pcodeOp = stmt.getPcodeOp();
            if (pcodeOp.getOpcode() == PcodeOp.CALL) {            
                long callAddress = astNode.getMaxAddress().getOffset();
                String etwRegisterCall = getFunctionAt(pcodeOp.getInput(0).getAddress()).getName();
                
                List<Long> pGuids = null;
                List<Long> reghandles = new LinkedList<Long>();
                // we need to pass the calling function in order to back trace through any parameters
                Stack<Function> callingFunc = new Stack<Function>();
                callingFunc.push(f);
                
                debugPrintf("%s :: %s\n", refAddr.toString(), stmt);
                
                if(etwRegisterCall.endsWith("NotificationRegister")) {
                    // NTSTATUS EtwNotificationRegister (LPCGUID Guid, ULONG Type, PETW_NOTIFICATION_CALLBACK Callback, PVOID Context, PREGHANDLE RegHandle);
                    throw new NotYetImplementedException(etwRegisterCall);
                }
                
                if(f.getName().startsWith("TraceLogging"))
                {
                    if(pcodeOp.getNumInputs() == 0) {
                        printf("[WARNING] Incomplete Decompilation @ 0x%x - %s\n", callAddress,  stmt.toString());
                        return false;
                    }

                    // TraceLoggingRegisterEx_EtwRegister_EtwSetInformation(PTLGREG param_1, ...)
                    List<Long> tlgregs = null;
                    try {
                        // Only the first parameter is needed
                        // It points to an undocumented TraceLogging provider registration struct.
                            tlgregs = resolveToConstant(1, callingFunc);
                    } catch (NotFoundException e) {       
                         printf("   --> skipping %s due to local variable storage @ 0x%x\n", f.getName(), callAddress);
                        return true;
                    }
                    printf(" * found %d TraceLoggingRegister calls\n", tlgregs.size());

                    for(int i=0; i < tlgregs.size(); i++) {
                        Long tlgreg = tlgregs.get(i);

                        // At offset 8 of the TLG registration is a pointer to the TLG provider metadata
                        Long tlgprov = getLong(toAddr(tlgreg + 8));

                        // The provider guid is at offset -0x10
                        Address guidAddr = toAddr(tlgprov - 0x10);
                        clearListing(guidAddr, guidAddr.add(guidType.getLength()-1));
                        createData(guidAddr, guidType);
                        String guid = getDataAt(guidAddr).toString().substring(5);

                        // The provider name is at offet +2
                        Address nameAddr = toAddr(tlgprov + 2);
                        clearListing(nameAddr);
                        createData(nameAddr, stringType);
                        String providerName = getDataAt(nameAddr).toString().substring(3); // strip type

                        // The REGHANDLE will be saved at offset 0x20
                        Long reghandle = tlgreg + 0x20;

                        printf("   --> cached TraceLoggingRegister(%s, %s)\n", guid, providerName);
                        providerGuidMap.put(reghandle, new Pair<String,String>(guid, providerName));
                    }

                        return true;
                }
                
                   if(etwRegisterCall.startsWith("Etw") ||  etwRegisterCall.startsWith("Event")) {
                    if(pcodeOp.getNumInputs() < 5) {
                        printf("[WARNING] Incomplete Decompilation @ 0x%x - %s\n", callAddress,  stmt.toString());
                        return false;
                    }

                    try {
                        pGuids = resolveFunctionParameterToConstant(pcodeOp, 1, callingFunc);
                       } catch (NotFoundException e) {
                           printf("   --> skipping %s as guid not found @ 0x%x\n", etwRegisterCall, callAddress);
                           return false;
                       }

                    try {
                        reghandles = resolveFunctionParameterToConstant(pcodeOp, 4, callingFunc);
                     } catch (NotFoundException e) {
                         // a global REGHANDLE address was not found
                         // assume local only use - and cache the containing function as the address
                         debugPrintf("local REGHANDLE @ 0x%x\n", callAddress);
                         reghandles.add(f.getEntryPoint().getOffset());
                    }
                   }

                // :TODO: better guarantee the (guid, reghandle) correlation?
                if(pGuids.size() != reghandles.size())
                    throw new NotFoundException("ETW register parameter list size mismatch");
                for(int i = 0; i < pGuids.size(); i++) {
                    long pGuid = pGuids.get(i);
                    String guid = "";
                    String guidSymbol = "";
                    if(pGuid != 0) {
                        Address guidAddr = toAddr(pGuid);
                        clearListing(guidAddr, guidAddr.add(guidType.getLength()-1));
                        createData(guidAddr, guidType);
                        guid = getDataAt(guidAddr).toString().substring(5); // strip GUID_ prefix
                        guidSymbol = SymbolAt(pGuid); 
                    }                    
                    
                    long reghandle = reghandles.get(i);
                    if(reghandle != 0 && pGuid != 0) {
                        printf("   --> cached %s(%s, %s)\n", etwRegisterCall, guid, guidSymbol);
                        providerGuidMap.put(reghandle, new Pair<String,String>(guid, guidSymbol));
                        found = true;
                    }
                }
                return found; // CALL found - stop looking
            }
        }

        // otherwise traverse children to find call(s)
        for (int j = 0; j < astNode.numChildren(); j++) {
            found |= cacheProviderReghandle(f, astNode.Child(j), refAddr);
        }
        
        return found;
    }


    /*
     * functions of interest
     */
    List<String> etwWriteFuncs = Arrays.asList("EtwWrite", "EventWrite", "EtwEventWrite", "EtwWriteEx", "EventWriteEx", "EtwEventWriteEx", "EtwWriteTransfer", "EventWriteTransfer", "EtwEventWriteTransfer", "EtwEventWriteFull", "EtwWriteStartScenario", "EventWriteStartScenario", "EtwEventWriteStartScenario", "EtwWriteEndScenario", "EventWriteEndScenario", "EtwEventWriteEndScenario", "EtwWriteString", "EventWriteString", "EtwEventWriteString", "EtwWriteNoRegistration", "EventWriteNoRegistration", "EtwEventWriteNoRegistration");
    List<String> classicMessageFuncs = Arrays.asList("TraceMesssage", "EtwTraceMessage", "TraceMessageVa", "EtwTraceMessageVa");
    List<String> classicEventFuncs = Arrays.asList("TraceEvent", "EtwTraceEvent", "TraceEventInstance",  "EtwTraceEventInstance");
    public void analyseFunction(Function func) throws Exception {
         Queue<QueuedFunction> queue = new LinkedList<QueuedFunction>();
         List<String> processed = new LinkedList<String>();
         Stack<Function> callPath = new Stack<Function>(); // helps with back tracing constants, and determining relevance  
         callPath.push(func);
         
         int eventCount = 0;
         int depth = 0;
         int exportDepth = 0;
         int maxLocalCallDepth = maxCallDepth;
         String lastParameters = null; 
        
        // find all reachable ETW writes
        for(Function calledFunction : func.getCalledFunctions(monitor))
            queue.add(new QueuedFunction(calledFunction, func, 1, 0, callPath));
        while (queue.size() != 0) {
            if (monitor.isCancelled())
                break;
            QueuedFunction next = queue.remove();
            
            Function thisFunction = next.queuedFunction;
            Function callingFunction = next.callingFunction;
            depth = next.callDepth;
            exportDepth = next.exportedCallDepth;
            callPath = next.callPath;
            
            String funcName = thisFunction.getName();
            
            String containingFunction = callingFunction.getName();
            if( containingFunction.startsWith("FUN_")) {
                // Search for the first symbol in the call stack
                Stack<Function> stack = (Stack<Function>) callPath.clone();
                while(containingFunction.startsWith("FUN_"))
                    containingFunction = stack.pop().getName();
            }
            
            if (processed.contains(funcName) || ignored.contains(funcName))
                continue;
                        
            if(quickScan && (depth > maxLocalCallDepth || exportDepth > maxExportCallDepth || eventCount == maxEvents))
                continue;

            if(funcName.startsWith("_tlgWrite")) {
                ClangTokenGroup cCode = decomplib.decompileFunction(callingFunction, decompileTimeoutSeconds, monitor).getCCodeMarkup();
                if (cCode == null)
                    throw new Exception("[CALL _tlgWrite] Decompile Error: " + decomplib.getLastMessage());
                List<StringBuffer> tlgWriteParametersList = new LinkedList<StringBuffer>();
                try {
                    getTlgWriteParameters(funcName, cCode, tlgWriteParametersList, callPath, 0);
                    for(StringBuffer tlgWriteParameters : tlgWriteParametersList) {
                        if(tlgWriteParameters.toString().equals(lastParameters))
                            continue; // remove duplicates
                        lastParameters = tlgWriteParameters.toString();
                        csv.printf("%s,%s,%s,%d,%d,%s\n", func.getName(), tlgWriteParameters, containingFunction.replace(',','-'), depth, exportDepth, callPath.toString().replace(',','-').replace(' ','>') );
                        eventCount++;
                        maxLocalCallDepth = Math.min(maxLocalCallDepth, depth + extraCallDepth);
                    }
                } catch(NotFoundException e) {
                    logTODO(e.getMessage());
                } catch(NotYetImplementedException e) {
                    logTODO(e.getMessage());
                }
            }
            else if(classicEventFuncs.contains(funcName)) {
                logTODO("Implement classic provider support for " + containingFunction);
            }
            else if(classicMessageFuncs.contains(funcName)) {
                List<String> wppWriteParametersList = getWppWriteParameters(funcName, callingFunction, callPath);
                for(String wppWriteParameters : wppWriteParametersList) {
                    csv.printf("%s,%s,%s,%d,%d,%s\n", func.getName(), wppWriteParameters, containingFunction.replace(',','-'), depth, exportDepth, callPath.toString().replace(',','-').replace(' ','>') );
                    eventCount++;
                    maxLocalCallDepth = Math.min(maxLocalCallDepth, depth + extraCallDepth);
                }
            }
            else if(etwWriteFuncs.contains(funcName)) {
                ClangTokenGroup cCode = decomplib.decompileFunction(callingFunction, decompileTimeoutSeconds, monitor).getCCodeMarkup();
                if (cCode == null)
                    throw new Exception("[CALL EtwWrite] Decompile Error: " + decomplib.getLastMessage());
                List<StringBuffer> etwWriteParametersList = new LinkedList<StringBuffer>();
                try {
                    getEtwWriteParameters(funcName, cCode, etwWriteParametersList, callPath, 0);
                    for(StringBuffer etwWriteParameters : etwWriteParametersList) {
                        if(etwWriteParameters.toString().equals(lastParameters))
                            continue; // remove duplicates
                        lastParameters = etwWriteParameters.toString();
                        csv.printf("%s,%s,%s,%d,%d,%s\n", func.getName(), etwWriteParameters, containingFunction.replace(',','-'), depth, exportDepth, callPath.toString().replace(',','-').replace(' ','>') );
                        eventCount++;
                        maxLocalCallDepth = Math.min(maxLocalCallDepth, depth + extraCallDepth);
                    }
                } catch(NotFoundException e) {
                    logTODO(e.getMessage());
                } catch(NotYetImplementedException e) {
                    logTODO(e.getMessage());
                }
            }
            // Handling classic kernel events via this wrapper function adds more context
            else if(funcName.equals("EtwTraceKernelEvent")) {
                List<String> kernelEventParametersList = getTraceKernelEventParameters(funcName, callingFunction, callPath);
                for(String kernelEventParameters : kernelEventParametersList) {
                    if(kernelEventParameters.toString().equals(lastParameters))
                        continue; // remove duplicates
                    lastParameters = kernelEventParameters.toString();
                    csv.printf("%s,%s,%s,%d,%d,%s\n", func.getName(), kernelEventParameters, containingFunction.replace(',','-'), depth, exportDepth, callPath.toString().replace(',','-').replace(' ','>') );
                    eventCount++;
                    maxLocalCallDepth = Math.min(maxLocalCallDepth, depth + extraCallDepth);
                }
            }
            else {
                String functionCrumb = func.getName();
                if(functionCrumb.length() > 5)
                    functionCrumb = functionCrumb.substring(2, functionCrumb.length() - 5);
                if(exports.contains(funcName) && !funcName.contains(functionCrumb))
                    exportDepth++;
                
                processed.add(funcName);
                for(Function calledFunction : thisFunction.getCalledFunctions(monitor)) {
                    if(calledFunction == null)
                        throw new Exception("Argh!");
                    if(calledFunction.getName() == null)
                        createFunction(calledFunction.getEntryPoint(), null);
                    if(calledFunction.getName() == null)
                        throw new Exception("FUN_" + calledFunction.getEntryPoint().toString() + " is not defined");
                       callPath = (Stack<Function>) next.callPath.clone();
                    if(funcName.startsWith("FUN_"))
                        queue.add(new QueuedFunction(calledFunction, thisFunction, depth, exportDepth, callPath));
                    else {
                        callPath.add(thisFunction);
                        queue.add(new QueuedFunction(calledFunction, thisFunction, depth+1, exportDepth, callPath));
                    }
                }
            }
        }

        printf(" * %s - found %d events in %d functions. callDepth=%d exportDepth=%d\n",
            func.getName(), eventCount, processed.size(), maxLocalCallDepth, exportDepth);
        csv.flush();
    }    
      
    private boolean getEtwWriteParameters(String etwWriteCall, ClangNode node, List<StringBuffer> etwWriteParametersList, Stack<Function> callPath, int depth) throws Exception {
        if(node == null || node.getMinAddress() == null)
            return false;  // leaf node
        if (node.getMaxAddress() == null)
            throw new InvalidInputException("ClangNode.getMaxAddress() is null");
        
        boolean found = false;
        
        // have we found the right CALL yet?
        if(node instanceof ClangStatement) {
            ClangStatement stmt = (ClangStatement) node;
            
            PcodeOp pcodeOp = stmt.getPcodeOp();
            if (pcodeOp != null &&
            pcodeOp.getOpcode() == PcodeOp.CALL && 
            getSymbolAt(pcodeOp.getInput(0).getAddress()) != null &&
            getSymbolAt(pcodeOp.getInput(0).getAddress()).getName().endsWith(etwWriteCall)) {
                if(pcodeOp.getNumInputs() < 3) {
                    printf("[WARNING] Incomplete Decompilation @ 0x%x - %s\n", node.getMaxAddress().getOffset(), stmt.toString());
                }
                
                debugPrintf("%s :: %s\n", callPath.peek().toString(), stmt);
        
                if(etwWriteCall.endsWith("WriteNoRegistration")) {
                    // NTSTATUS EtwEventWriteNoRegistration (PCGUID ProviderId, PCEVENT_DESCRIPTOR EventDescriptor, ULONG UserDataCount, PEVENT_DATA_DESCRIPTOR UserData);
                    throw new NotYetImplementedException("EtwEventWriteNoRegistration");
                }
                
                long reghandle = 0;
                if(pcodeOp.getNumInputs() > 1) {
                    List<Long> reghandles = null;
                    try
                    {
                        reghandles = resolveFunctionParameterToConstant(pcodeOp, 1, callPath);
                        if(reghandles.size() == 0)
                            throw new NotFoundException("ETW write with no REGHANDLE");
                        if(reghandles.size() > 1)
                            throw new NotYetImplementedException("ETW write with multiple REGHANDLE");
                        reghandle = reghandles.get(0);
                    }
                    catch (NotFoundException e)
                    {
                        debugPrintf("ETW write REGHANDLE resolves to local variable in " + callPath.peek());
                        // Attempt lookup via function address instead  
                        reghandle =  callPath.peek().getEntryPoint().getOffset();
                    }
                    catch (NotYetImplementedException e) {
                        // non fatal
                        logTODO("Handle REGHANDLE in " + e.getMessage());
                    }
                }
                
                String providerGuid = "???";
                String providerSymbol = "";
                String reghandleSymbol = SymbolAt(reghandle);
                Pair<String,String> providerRegistration = providerGuidMap.get(reghandle);
                if ( providerRegistration != null) {
                    providerGuid = providerRegistration.first;
                    providerSymbol = providerRegistration.second;
                }
                StringBuffer etwWriteParameters = new StringBuffer();

                if(etwWriteCall.endsWith("WriteString")) { 
                    // NTSTATUS EtwWriteString(REGHANDLE RegHandle, UCHAR Level, ULONGLONG Keyword, LPCGUID ActivityId, PCWSTR String)
                    etwWriteParameters.append(providerGuid + ",");
                    etwWriteParameters.append(providerSymbol + ",");
                    etwWriteParameters.append(reghandleSymbol + ",");
                    etwWriteParameters.append(etwWriteCall + ",");
                    List<Long> levels = resolveFunctionParameterToConstant(pcodeOp, 2, callPath);
                    List<Long> keywords = resolveFunctionParameterToConstant(pcodeOp, 3, callPath);
                    List<Long> strings = resolveFunctionParameterToConstant(pcodeOp, 5, callPath);
                    if(levels.size() + keywords.size() + strings.size() != 3)
                        throw new NotYetImplementedException("EtwWriteString with multiple paths");
                    etwWriteParameters.append(",,,,"+ levels.get(0) + ",,," + keywords.get(0));

                    // :TODO: output (PCWSTR String) parameter
                    logTODO(etwWriteCall);
                    return true;
                }
                

                // NTSTATUS EtwWrite*(REGHANDLE RegHandle, PCEVENT_DESCRIPTOR EventDescriptor, LPCGUID ActivityId, ULONG UserDataCount, PEVENT_DATA_DESCRIPTOR UserData);
                Address event = null;
                if(pcodeOp.getNumInputs() > 2) {
                    List<Long> pEvents = new LinkedList<Long>();
                    try
                    {
                        debugPrintf("resolveFunctionParameterToConstant(2)\n");
                        pEvents = resolveFunctionParameterToConstant(pcodeOp, 2, callPath);
                        if(pEvents.size() == 0)
                            logTODO("EtwWrite EVENT_DESCRIPTOR not found in " + callPath.peek());
                    }
                    catch (NotFoundException e)
                    {
                        logTODO("EtwWrite EVENT_DESCRIPTOR not found in " + callPath.peek());
                        etwWriteParameters = new StringBuffer();
                        etwWriteParameters.append(providerGuid + ",");
                        etwWriteParameters.append(providerSymbol + ",");
                        etwWriteParameters.append(reghandleSymbol + ",");
                        etwWriteParameters.append(etwWriteCall + ",");
                        etwWriteParameters.append(",,,,,,,"); // not found
                        etwWriteParametersList.add(etwWriteParameters);
                    }
                    catch (NotYetImplementedException e)
                    {
                        throw new NotYetImplementedException("EVENT_DESCRIPTOR " + e.getMessage());
                    }
                    
                    for(long pEvent : pEvents) {
                        if(pEvent == 0)
                            continue;  // a quirk of ghidra's decompilation? Or because of initialise to zero and error paths?
                        
                        etwWriteParameters = new StringBuffer();
                        etwWriteParameters.append(providerGuid + ",");
                        etwWriteParameters.append(providerSymbol + ",");
                        etwWriteParameters.append(reghandleSymbol + ",");
                        etwWriteParameters.append(etwWriteCall + ",");
                        String eventDescriptorSymbol = SymbolAt(pEvent);
                        etwWriteParameters.append(eventDescriptorSymbol + ",");
                        event = toAddr(pEvent);
                        clearListing(event, event.add(eventDescriptorType.getLength()-1));
                        try {
                            createData(event, eventDescriptorType);
                            appendStructure(event, etwWriteParameters, true);
                        }
                        catch(CodeUnitInsertionException e)
                        {
                            debugPrintf("EVENT_DESCRIPTOR parsing failed @ 0x%x", pEvent);
                            etwWriteParameters.append(",,,,,,");
                        }
                        etwWriteParametersList.add(etwWriteParameters);
                    }                    
                }                            
                found = true;
            }
        }

        // search children until call(s) found
        for (int j = 0; j < node.numChildren(); j++)
            found |= getEtwWriteParameters(etwWriteCall, node.Child(j), etwWriteParametersList, callPath, depth + 1);
        
        if(!found && depth == 0)
            throw new Exception("didn't find " + etwWriteCall);
        
        return found;
    }
    
    private boolean getTlgWriteParameters(String tlgWriteCall, ClangNode node, List<StringBuffer> tlgWriteParametersList, Stack<Function> callPath, int depth) throws Exception {   
        if(node == null || node.getMinAddress() == null)
            return false;  // leaf node
        if (node.getMaxAddress() == null)
            throw new InvalidInputException("ClangNode.getMaxAddress() is null");
        
        boolean found = false;
               
        // have we found the right CALL yet?
        if(node instanceof ClangStatement) {
            ClangStatement stmt = (ClangStatement) node;
            
            PcodeOp pcodeOp = stmt.getPcodeOp();
            if (pcodeOp != null &&
            pcodeOp.getOpcode() == PcodeOp.CALL && 
            getSymbolAt(pcodeOp.getInput(0).getAddress()) != null &&
            getSymbolAt(pcodeOp.getInput(0).getAddress()).getName().endsWith(tlgWriteCall)) {
                if(pcodeOp.getNumInputs() < 2) {
                    printf("[WARNING] Incomplete Decompilation @ 0x%x - %s\n", node.getMaxAddress().getOffset(), stmt.toString());
                }
                found = true;
                
                if(tlgWriteCall.startsWith("_tlgWriteEx"))
                    tlgWriteCall = "_tlgWriteEx";
                else if(tlgWriteCall.startsWith("_tlgWriteTransfer"))
                    tlgWriteCall = "_tlgWriteTransfer";
                
                debugPrintf("%s :: %s\n", tlgWriteCall, stmt);

                // _tlgWrite(PTLG_REGISTRATION, PTLG_EVENT, ...) 
                
                long reghandle = 0;
                if(pcodeOp.getNumInputs() > 1) {
                    List<Long> reghandles = null;
                    try
                    {
                        reghandles = resolveFunctionParameterToConstant(pcodeOp, 1, callPath);
                        if(reghandles.size() == 0)
                            throw new NotFoundException("TLG write with no REGHANDLE");
                        if(reghandles.size() > 1)
                            throw new NotYetImplementedException("TLG write with multiple REGHANDLE");
                        // REGHANDLE is at offset 0x20 in TLG_REGISTRATION 
                        reghandle = reghandles.get(0) + 0x20;
                    }
                    catch (NotFoundException e)
                    {
                        // non fatal
                        logTODO("_tlgWrite REGHANDLE not found in " + callPath.peek());
                    }
                    catch (NotYetImplementedException e) {
                        // non fatal
                        logTODO("REGHANDLE " + e.getMessage());
                    }
                }
                
                String providerGuid = "???";
                String providerName = "";
                Pair<String,String> providerRegistration = providerGuidMap.get(reghandle);
                if ( providerRegistration != null) {
                    providerGuid = providerRegistration.first;
                    providerName = providerRegistration.second;
                }
                String reghandleSymbol = SymbolAt(reghandle);
                if(reghandleSymbol.startsWith("DAT_"))
                    reghandleSymbol = "";
                
                if(pcodeOp.getNumInputs() > 2) {
                    List<Long> pTlgEvents = null; // TLG_EVENT pointers
                    try
                    {
                        pTlgEvents = resolveFunctionParameterToConstant(pcodeOp, 2, callPath);
                    }
                    catch (NotFoundException e)
                    {
                        throw new NotYetImplementedException("TLG write EVENT_DESCRIPTOR resolves to local variable in " + callPath.peek()); // :TODO:
                    }
                    catch (NotYetImplementedException e)
                    {
                        throw new NotYetImplementedException("EVENT_DESCRIPTOR " + e.getMessage());
                    }
                    if(pTlgEvents.size() == 0)
                        throw new NotFoundException("TLG write with no EVENT_DESCRIPTOR");
                    
                    for(long pEvent : pTlgEvents) {
                        if(pEvent == 0)
                            continue;  // a quirk of ghidra's decompilation? Or because of initialise to zero and error paths?
                        StringBuffer tlgWriteParameters = new StringBuffer();
                        tlgWriteParameters.append(providerGuid + ",");
                        tlgWriteParameters.append(providerName + ",");
                        tlgWriteParameters.append(reghandleSymbol + ","); // usually empty for TLG
                        tlgWriteParameters.append(tlgWriteCall + ",");
                        
                        // https://posts.specterops.io/data-source-analysis-and-dynamic-windows-re-using-wpp-and-tracelogging-e465f8b653f7
                        // UCHAR Channel
                        // UCHAR Level
                        // UCHAR OpCode
                        // UINT64 Keyword
                        // UINT16 Size
                        // UCHAR Zero
                        // CSTR EventName
                        Byte channel = getByte(toAddr(pEvent));
                        Byte level =  getByte(toAddr(pEvent + 1));
                        Byte opcode =  getByte(toAddr(pEvent + 2));
                        Long keyword = getLong(toAddr(pEvent + 3));

                        Address nameAddr = toAddr(pEvent + 15);
                        clearListing(nameAddr);
                        createData(nameAddr, stringType);
                        String eventName = getDataAt(nameAddr).toString().substring(3); // strip type
                        
                        // TraceLogging doesn't have equivalent fields for id, task and version. 
                        tlgWriteParameters.append(eventName + ",");
                        tlgWriteParameters.append("-,-,"); // Id, Version
                        tlgWriteParameters.append(channel + ",");
                        tlgWriteParameters.append(level + ",");
                        tlgWriteParameters.append(opcode + ",");
                        tlgWriteParameters.append("-,"); // Task
                        tlgWriteParameters.append(String.format("0x%x", keyword));
                        tlgWriteParametersList.add(tlgWriteParameters);
                    }       
                }
                else
                {
                    StringBuffer tlgWriteParameters = new StringBuffer();
                    tlgWriteParameters.append(providerGuid + ",");
                    tlgWriteParameters.append(providerName + ",");
                    tlgWriteParameters.append(reghandleSymbol + ",");
                    tlgWriteParameters.append(tlgWriteCall + ",");
                    tlgWriteParameters.append(",,,,,,,");
                    tlgWriteParametersList.add(tlgWriteParameters);
                }
            }
        }

        // search children until call(s) found
        for (int j = 0; j < node.numChildren(); j++)
            found |= getTlgWriteParameters(tlgWriteCall, node.Child(j), tlgWriteParametersList, callPath, depth + 1);

        if(!found && depth == 0)
            throw new Exception("didn't find " + tlgWriteCall);

        return found; 
    }
    
    
    private List<String> getWppWriteParameters(String wppWriteCall, Function callingFunction, Stack<Function> callPath) throws Exception {
        
        HighFunction hf = decomplib.decompileFunction(callingFunction, decompileTimeoutSeconds, monitor).getHighFunction();
        if (hf == null)
            throw new Exception("[CALL WppWrite] Decompile Error: " + decomplib.getLastMessage());

        List<String> wppWriteParametersList = new LinkedList<String>();
        boolean found = false;
    
        Iterator<PcodeOpAST> ops = hf.getPcodeOps();
        while (ops.hasNext() && !monitor.isCancelled()) {
            PcodeOpAST pcodeOp = ops.next();
            
            if (pcodeOp.getOpcode() == PcodeOp.CALL && 
            getSymbolAt(pcodeOp.getInput(0).getAddress()) != null &&
            getSymbolAt(pcodeOp.getInput(0).getAddress()).getName().endsWith(wppWriteCall)) {
                if(pcodeOp.getNumInputs() < 4) {
                    printf("[WARNING] Incomplete Decompilation of " + callingFunction.getName());
                }
                
                // ULONG TraceMessage(TRACEHANDLE LoggerHandle, ULONG MessageFlags, LPCGUID MessageGuid, USHORT MessageNumber, ...);
                StringBuffer wppWriteParameters = new StringBuffer();
                found = true;
                
                try {
                    long tracehandle = resolveParameterToConstant(pcodeOp, wppWriteCall, "TRACEHANDLE", 1, callPath);
                    long messageFlags = resolveParameterToConstant(pcodeOp, wppWriteCall, "MessageFlags", 2, callPath);
                    long _messageGuid = resolveParameterToConstant(pcodeOp, wppWriteCall, "MessageGuid", 3, callPath);
                    long messageId = pcodeOp.getNumInputs() == 4 ? 0 : resolveParameterToConstant(pcodeOp, wppWriteCall, "MessageId", 4, callPath);
                    
    
                    String providerGuid = "???";
                    String providerSymbol = "";
                    String reghandleSymbol = SymbolAt(tracehandle);
                    Pair<String,String> providerRegistration = providerGuidMap.get(tracehandle);
                    if ( providerRegistration != null) {
                        providerGuid = providerRegistration.first;
                        providerSymbol = providerRegistration.second;
                    }
                    
                    String messageGuid = "???";
                    Pair<String,String> guidRegistration = providerGuidMap.get(_messageGuid);
                    if ( guidRegistration != null)
                        messageGuid = guidRegistration.first;
                    
                    wppWriteParameters.append("WPP_"+providerGuid + ",");
                    wppWriteParameters.append(providerSymbol + ",");
                    wppWriteParameters.append(reghandleSymbol + ",");
                    wppWriteParameters.append(wppWriteCall + ",");
                    wppWriteParameters.append(messageGuid + ",");  // EventDescriptorSymbol
                    wppWriteParameters.append(messageId + ","); // Id
                    wppWriteParameters.append(",,,,,"); // Version,Channel,Level,Opcode,Task,
                    wppWriteParameters.append("Flags=" + messageFlags); // Keyword
                } catch(NotFoundException e) {
                    wppWriteParameters.append(",,,,,,,,,,,");
                }
                wppWriteParametersList.add(wppWriteParameters.toString());
            }
        }

        if(!found)
            throw new NotFoundException("didn't find any " + wppWriteCall + " calls  in " + callPath.peek());
        
        return wppWriteParametersList; 
    }
    
    private List<String> getTraceKernelEventParameters(String funcName, Function callingFunction, Stack<Function> callPath) throws Exception {

        HighFunction hf = decomplib.decompileFunction(callingFunction, decompileTimeoutSeconds, monitor).getHighFunction();
        if (hf == null)
            throw new Exception("[CALL " + funcName + "] Decompile Error: " + decomplib.getLastMessage());

        List<String> parametersList = new LinkedList<String>();
        boolean found = false;

        Iterator<PcodeOpAST> ops = hf.getPcodeOps();
        while (ops.hasNext() && !monitor.isCancelled()) {
            PcodeOpAST pcodeOp = ops.next();

            if (pcodeOp.getOpcode() == PcodeOp.CALL &&
            getSymbolAt(pcodeOp.getInput(0).getAddress()) != null &&
            getSymbolAt(pcodeOp.getInput(0).getAddress()).getName().endsWith(funcName)) {
                if(pcodeOp.getNumInputs() < 3) {
                    printf("[WARNING] Incomplete Decompilation of " + callingFunction.getName());
                }

                StringBuffer parameters = new StringBuffer();
                found = true;

                parameters.append("Windows Kernel Trace,");
                try {
                    // EtwTraceKernelEvent(PEVENT_DESCRIPTOR, UINT32, PERFINFO_GROUPMASK, LOG_TYPE, UINT32)
                    long perfinfo = resolveParameterToConstant(pcodeOp, funcName, "PERFINFO_GROUPMASK", 3, callPath);
                    long logtype = resolveParameterToConstant(pcodeOp, funcName, "LOG_TYPE", 4, callPath);
                    // If someone wants to reverse the format then more event metadata could likely be
                    // extracted from the 1st, 2nd and 5th parameters.

                    parameters.append(LookupPerfInfoMask(perfinfo) + ",");
                    parameters.append(LookupTraceGroup(logtype) + ",");
                    parameters.append(funcName + ",");
                    parameters.append(LookupLogType(logtype) + ",");
                    parameters.append(",,,,,,"); // Id,Version,Channel,Level,Opcode,Task,Keyword
                } catch(NotFoundException e) {
                    parameters.append(",,,,,,,,,,");
                }
                parametersList.add(parameters.toString());
            }
        }

        if(!found)
            throw new NotFoundException("didn't find any " + funcName + " calls  in " + callPath.peek());

        return parametersList;
    }

    // resolve an intermediate pcode call parameter to a list of possible constant values 
    public List<Long> resolveFunctionParameterToConstant(PcodeOp call, int paramIndex, Stack<Function> callPath) throws Exception {
        if (call.getOpcode() != PcodeOp.CALL)
            throw new InvalidInputException("Expected a CALL function");

        Varnode calledFunc = call.getInput(0);
        if (calledFunc == null || !calledFunc.isAddress())
            throw new InvalidInputException("Invalid CALL PcodeOp");
        
        if (paramIndex >= call.getNumInputs())
            throw new InvalidInputException("Decompiler discovered insufficient parameters");
        
        Varnode param = call.getInput(paramIndex);
        if (param == null)
            throw new NotFoundException("Missing Parameter");
        
        // else process
        return resolveVarnodeToConstant(param, callPath, 0);
    }
    
    // resolve a variable to a list of possible constant values
    private List<Long> resolveVarnodeToConstant(Varnode node, Stack<Function> callPath, int astDepth) throws Exception {
        if (node.isConstant())
            return new LinkedList<Long>(Arrays.asList(node.getOffset()));
        
        if (node.isAddress())
            return new LinkedList<Long>(Arrays.asList(node.getAddress().getOffset()));
               
        HighVariable hvar = node.getHigh();
        if (hvar instanceof HighParam)
            return resolveToConstant(((HighParam)hvar).getSlot() + 1, callPath);

        if (hvar instanceof HighGlobal)
            debugPrintf(":TODO: found a global... already handled?");
        
        if (hvar instanceof HighLocal) {
            // printf("### HighLocal " + callPath.peek().getName() + " node: " + node.getDef() + "\n");
            return resolvePcodeOpToConstant(node.getDef(), callPath, astDepth);
        }
        
        if (hvar instanceof HighOther) {
            ///printf("### HighOther " + callPath.peek().getName() + " hvar: " + hvar + "\n");
            ///printf("###  getRepresentative: " + hvar.getRepresentative().getDef() + "\n");
            ///printf("###  getDef: " + node.getDef() + "\n");
            if(hvar.getRepresentative().getDef() != null)
                return resolvePcodeOpToConstant(hvar.getRepresentative().getDef(), callPath, astDepth);
            if(node.getDef() != null)
                return resolvePcodeOpToConstant(node.getDef(), callPath, astDepth);
        }
        
        throw new NotFoundException();
    }
    
    // resolve a function call parameter to a list of possible constant values
    private List<Long> resolveToConstant(int parameterIndex, Stack<Function> callPath) throws Exception {
        List<Long> constants = new LinkedList<Long>();
        
        Stack<Function> parentCallPath = (Stack<Function>)callPath.clone();
        Function func = parentCallPath.pop();
        if (callPath.size() > 1) {
            // forward trace - with full call path
            ClangNode astNode = decomplib.decompileFunction(parentCallPath.peek(), decompileTimeoutSeconds, monitor).getCCodeMarkup();
            if (astNode == null)
                throw new Exception("[resolveToConstant] Decompile Error: " + decomplib.getLastMessage());
            constants.addAll(resolveToConstant(astNode, func, parameterIndex, parentCallPath, 0));
        } else {
            // backwards trace - incomplete call path, follow all paths
            for(Function callingFunction : func.getCallingFunctions(monitor)) {    
                ClangNode astNode = decomplib.decompileFunction(callingFunction, decompileTimeoutSeconds, monitor).getCCodeMarkup();
                if (astNode == null)
                    throw new Exception("[resolveToConstant] Decompile Error: " + decomplib.getLastMessage());
                parentCallPath.push(callingFunction);
                constants.addAll(resolveToConstant(astNode, func, parameterIndex, parentCallPath, 0));
                parentCallPath.pop();
            }
        }
        
        if (constants.size() == 0)
            throw new NotFoundException("resolveToConstant(parameter)");
        
        return constants.stream().distinct().collect(Collectors.toList());
    }
    
    // resolve a high level C statement to a list of possible constant values
    private List<Long> resolveToConstant(ClangNode astNode, Function func, int parameterIndex, Stack<Function> callPath, int nodeDepth) throws Exception {
        List<Long> constants = new LinkedList<Long>();
        
        // find the call(s) to func - and back trace all possible parameter values
        if(astNode instanceof ClangStatement) {
            ClangStatement stmt = (ClangStatement) astNode;
            PcodeOp pcodeOp = stmt.getPcodeOp();
            if (pcodeOp != null &&
                pcodeOp.getOpcode() == PcodeOp.CALL && 
                getFunctionAt(pcodeOp.getInput(0).getAddress()) != null &&    
                getFunctionAt(pcodeOp.getInput(0).getAddress()).getName().equals(func.getName()))
            {
                if(parameterIndex >= pcodeOp.getNumInputs()) {
                    // After porting to Ghidra 11 this condition is triggering when it shouldn't.
                    // Recovering programmatically appears to require invalidate the existing 
                    // decompilation result so isn't trivial.
                    // Print (likely) manual recovery instructions for now.
                    printf("Navigate to " + pcodeOp.getInput(0).getAddress() + " " + stmt + "\n");
                    printf("P 'Commit Params/Return' for this function and retry\n");
                    printf("Or try Auto Analyze again if it keeps happening\n");
                    throw new ArrayIndexOutOfBoundsException(astNode.getMinAddress() + " CALL " +
                            stmt + " parameterIndex=" + parameterIndex + 
                            " of " + (pcodeOp.getNumInputs() - 1));
                }
                constants.addAll(resolveVarnodeToConstant(pcodeOp.getInput(parameterIndex), callPath, 0));
            }
        }

        // also traverse all children to find call(s)
        for (int i = 0; i < astNode.numChildren(); i++)
            constants.addAll(resolveToConstant(astNode.Child(i), func, parameterIndex, callPath, nodeDepth + 1));
        
        if(nodeDepth == 0 && constants.isEmpty())
            throw new NotFoundException("resolveToConstant(parameter)");

        return constants.stream().distinct().collect(Collectors.toList());
    }
        
    // resolve an intermediate pcode operation to a list of possible constant values
    private List<Long> resolvePcodeOpToConstant(PcodeOp node, Stack<Function> callPath, int astDepth) throws Exception {        
        if(node == null)
            throw new NotFoundException("node == null");
        
        if(astDepth > 128)
            throw new NotFoundException("Pcode AST depth > 128 in " + callPath.peek());
        
        debugPrintf("%s (depth=%d)\n", node.toString(), astDepth);
        
        List<Long> input0;
        List<Long> input1;
        List<Long> output = new LinkedList<Long>();
        
        int opcode = node.getOpcode();
        switch (opcode) {
            case PcodeOp.CAST:
            case PcodeOp.COPY:
            case PcodeOp.INT_ZEXT: // zero-extend
                output = resolveVarnodeToConstant(node.getInput(0), callPath, astDepth+1);
                break;
                
            case PcodeOp.INT_2COMP: // twos complement
                input0 = resolveVarnodeToConstant(node.getInput(0), callPath, astDepth+1);
                output = input0.stream().map(a->-a).collect(Collectors.toList());
                break;
            
            case PcodeOp.INT_NEGATE:
                input0 = resolveVarnodeToConstant(node.getInput(0), callPath, astDepth+1);
                output = input0.stream().map(a->~a).collect(Collectors.toList());
                break;
            
            case PcodeOp.LOAD:
                output =  resolveVarnodeToConstant(node.getInput(1), callPath, astDepth+1);
                break;
                    
            case PcodeOp.INT_ADD:
            case PcodeOp.PTRSUB:  // pointer to structure and offset to subcomponent
                input0 = resolveVarnodeToConstant(node.getInput(0), callPath, astDepth+1);
                input1 = resolveVarnodeToConstant(node.getInput(1), callPath, astDepth+1);
                for(int i = 0; i < input0.size(); i++)
                    for(int j = 0; j < input1.size(); j++)
                        output.add(input0.get(i) + input1.get(j));
                break;
            
            case PcodeOp.INT_MULT:
                input0 = resolveVarnodeToConstant(node.getInput(0), callPath, astDepth+1);
                input1 = resolveVarnodeToConstant(node.getInput(1), callPath, astDepth+1);
                for(int i = 0; i < input0.size(); i++)
                    for(int j = 0; j < input1.size(); j++)
                        output.add(input0.get(i) * input1.get(j));
                break;
                
            case PcodeOp.INT_NOTEQUAL:
            input0 = resolveVarnodeToConstant(node.getInput(0), callPath, astDepth+1);
            input1 = resolveVarnodeToConstant(node.getInput(1), callPath, astDepth+1);
            for(int i = 0; i < input0.size(); i++)
                for(int j = 0; j < input1.size(); j++)
                    output.add((input0.get(i) != input1.get(j)) ? 1L : 0L);
            break;
                
            case PcodeOp.PTRADD:  
                input0 = resolveVarnodeToConstant(node.getInput(0), callPath, astDepth+1);
                input1 = resolveVarnodeToConstant(node.getInput(1), callPath, astDepth+1);
                List<Long> elementSize = resolveVarnodeToConstant(node.getInput(2), callPath, astDepth+1);
                for(int i = 0; i < input0.size(); i++)
                    for(int j = 0; j < input1.size(); j++)
                        for(int k = 0; k < elementSize.size(); k++)
                            output.add(input0.get(i) + (input1.get(j) * elementSize.get(k)));
                break;
                
            case PcodeOp.INT_AND:
                input0 = resolveVarnodeToConstant(node.getInput(0), callPath, astDepth+1);
                input1 = resolveVarnodeToConstant(node.getInput(1), callPath, astDepth+1);
                for(int i = 0; i < input0.size(); i++)
                    for(int j = 0; j < input1.size(); j++)
                        output.add(input0.get(i) & input1.get(j));
                break;
                
            case PcodeOp.MULTIEQUAL:
                for(Varnode n : node.getInputs())
                    output.addAll(resolveVarnodeToConstant(n, callPath, astDepth+1));
                break;
            
            case PcodeOp.INDIRECT:
                debugPrintf("ignoring possible indirect effects in %s\n", callPath.peek());
                output = resolveVarnodeToConstant(node.getInput(0), callPath, astDepth+1);
                break;
            
            case PcodeOp.CALL:
                debugPrintf("guessing TRUE for CALL in %s\n", callPath.peek());                
                output.add(1L); // TRUE
                break;
                
            default:
                throw new NotYetImplementedException("PcodeOp " + node.toString() + " in " + callPath.peek());
        }
        
        // remove duplicates
        return output.stream().distinct().collect(Collectors.toList());
    }
        
    private void appendStructure(Address addr, StringBuffer buff, Boolean valuesOnly) throws Exception {       
        Data struct = getDataAt(addr);
    
        for(int i = 0; i < struct.getNumComponents(); i++) {
            if(i != 0)
                buff.append(",");
            Data component = struct.getComponent(i);
            if(!valuesOnly)
                buff.append(component.getComponentPathName() + "=");
            
            DataType dt = component.getDataType();
            
            if (dt.isEquivalent(ucharType)) {
                buff.append(component.getUnsignedByte(0));
            
            } else if (dt.isEquivalent(ushortType)) {
                buff.append(component.getUnsignedShort(0));
            
            } else if (dt.isEquivalent(ulonglongType)) {
                buff.append(String.format("0x%x", component.getBigInteger(0, 8, false)));
            
            } else
                throw new Exception("Unsupported Type:" + dt.toString() + " (DataTypeManager=" + dt.getDataTypeManager().getName() + "CategoryPath=" + dt.getCategoryPath() + ")");
        }
    }
    
    private long resolveParameterToConstant(PcodeOp pcodeOp, String function, String parameterType, int parameterIndex, Stack<Function> callPath) throws Exception {
    
        if(pcodeOp.getNumInputs() <= parameterIndex)
            throw new Exception("Decompilation failure in " + function);
            
            List<Long> constants = null;
            try
            {
                constants = resolveFunctionParameterToConstant(pcodeOp, parameterIndex, callPath);
                if(constants.size() == 0)
                    throw new NotFoundException(parameterType + " not found in " + callPath.peek() + "->" + function);
                if(constants.size() > 1)
                    throw new NotYetImplementedException(parameterType + " with multiple values in " + callPath.peek() + "->" + function);
                return constants.get(0);
            }
            catch (NotFoundException e) {
                logTODO(parameterType + " resolves to local variable in " + callPath.peek() + "->" + function);
            }
            catch (NotYetImplementedException e) { 
                logTODO(parameterType + " failed to resolve to constant in " + callPath.peek() + "->" + function + " due to " + e.getMessage());
            }
            
            throw new NotFoundException(parameterType + " not found in " + callPath.peek() + "->" + function);
    }
    
    
    private String SymbolAt(long address)
    {
        String strSymbol = "";
        Symbol symbol = this.getSymbolAt(toAddr(address));
        if (symbol != null)
            strSymbol = symbol.toString();
        if (strSymbol.startsWith("DAT_"))
            strSymbol = "";
        return strSymbol;
    }
    
    private void setUpDecompiler(Program program) {
        decomplib = new DecompInterface();
        
        DecompileOptions options;
        options = new DecompileOptions(); 
        OptionsService service = state.getTool().getService(OptionsService.class);
        if (service != null) {
            ToolOptions opt = service.getOptions("Decompiler");
            options.grabFromToolAndProgram(null,opt,program);
        }
        decomplib.setOptions(options);
        
        decomplib.toggleCCode(true);
        decomplib.toggleSyntaxTree(true);
        decomplib.setSimplificationStyle("decompile");
    }
    
    private void setUpDataTypes() throws NotFoundException {          
          eventDescriptorType = getDataType("EVENT_DESCRIPTOR");
          ulonglongType = getDataType("ULONGLONG");
          ushortType = getDataType("USHORT");
          ucharType = getDataType("UCHAR");
          guidType = getDataType("GUID");
          stringType = getDataType("TerminatedCString");
    }
   
    private DataType getDataType(String name) throws NotFoundException {
        DataTypeManagerService service = state.getTool().getService(DataTypeManagerService.class);

        // Loop through all managers in the data type manager service
        for (DataTypeManager manager : service.getDataTypeManagers()) {
            List<DataType> dataTypes = new ArrayList<DataType>();
            manager.findDataTypes(name, dataTypes);
            if(dataTypes.size() != 0)
                return dataTypes.get(0);
        }
        throw new NotFoundException(name);
    }
    
    private void debugPrintf(String template, Object... args) {    
        if(debugPrint)
            printf("[DEBUG] " + template, args);
    }
    
    private void logTODO(String message) {
        if(!notYetImplemented.contains(message))
            notYetImplemented.add(message);
    }
    
    public class QueuedFunction
    {
        public Function queuedFunction;
        public Function callingFunction;
        public int callDepth;
        public int exportedCallDepth;
        public Stack<Function> callPath;
        public QueuedFunction(Function queuedFunction, Function callingFunction, int callDepth, int exportedCallDepth, Stack<Function> callPath )
        {
            this.queuedFunction = queuedFunction;
            this.callingFunction = callingFunction;
            this.callDepth = callDepth;
            this.exportedCallDepth = exportedCallDepth;
            this.callPath = callPath;
        }
    }

    //
    // Some helpful constants from Windows headers
    //

    public String LookupPerfInfoMask(long perfinfo) {
        switch((int)perfinfo) {
          case 0x00000001: return "PROCESS";
          case 0x00000002: return "THREAD";
          case 0x00000004: return "LOADER";
          case 0x00000200: return "FILENAME";
          case 0x00001000: return "ALL_FAULTS";
          case 0x00002000: return "HARD_FAULTS";
          case 0x00010000: return "NETWORK";
          case 0x00020000: return "REGISTRY";
          case 0x00040000: return "DBGPRINT";
          case 0x00000008: return "COUNTER";
          case 0x00000400: return "DISK_IO_INIT";
          case 0x00100000: return "ALPC";
          case 0x00200000: return "SPLIT_IO";
          case 0x02000000: return "FILE_IO";
          case 0x04000000: return "FILE_IO_INIT";
          case 0x00008000: return "VAMAP";

          case 0x20000001: return "MEMORY";
          case 0x20000002: return "PROFILE";
          case 0x20000004: return "CONTEXT_SWITCH";
          case 0x20000008: return "FOOTPRINT";
          case 0x20000010: return "DRIVERS";
          case 0x20000020: return "REFSET";
          case 0x20000040: return "POOL";
          case 0x20000041: return "POOLTRACE";
          case 0x20000080: return "DPC";
          case 0x20000100: return "COMPACT_CSWITCH";
          case 0x20000200: return "DISPATCHER";
          case 0x20000400: return "PMC_PROFILE";
          case 0x20000402: return "PROFILING";
          case 0x20000800: return "PROCESS_INSWAP";
          case 0x20001000: return "AFFINITY";
          case 0x20002000: return "PRIORITY";
          case 0x20004000: return "INTERRUPT";
          case 0x20008000: return "VIRTUAL_ALLOC";
          case 0x20010000: return "SPINLOCK";
          case 0x20020000: return "SYNC_OBJECTS";
          case 0x20040000: return "DPC_QUEUE";
          case 0x20080000: return "MEMINFO";
          case 0x20100000: return "CONTMEM_GEN";
          case 0x20200000: return "SPINLOCK_CNTRS";
          case 0x20210000: return "SPININSTR";
          case 0x20400000: return "SESSION";
          case 0x20800000: return "MEMINFO_WS";
          case 0x21000000: return "KERNEL_QUEUE";
          case 0x22000000: return "INTERRUPT_STEER";
          case 0x24000000: return "SHOULD_YIELD";
          case 0x28000000: return "WS";

          case 0x40000001: return "ANTI_STARVATION";
          case 0x40000002: return "PROCESS_FREEZE";
          case 0x40000004: return "PFN_LIST";
          case 0x40000008: return "WS_DETAIL";
          case 0x40000010: return "WS_ENTRY";
          case 0x40000020: return "HEAP";
          case 0x40000040: return "SYSCALL";
          case 0x40000080: return "UMS";
          case 0x40000100: return "BACKTRACE";
          case 0x40000200: return "VULCAN";
          case 0x40000400: return "OBJECTS";
          case 0x40000800: return "EVENTS";
          case 0x40001000: return "FULLTRACE";
          case 0x40002000: return "DFSS";
          case 0x40004000: return "PREFETCH";
          case 0x40008000: return "PROCESSOR_IDLE";
          case 0x40010000: return "CPU_CONFIG";
          case 0x40020000: return "TIMER";
          case 0x40040000: return "CLOCK_INTERRUPT";
          case 0x40080000: return "LOAD_BALANCER";
          case 0x40100000: return "CLOCK_TIMER";
          case 0x40200000: return "IDLE_SELECTION";
          case 0x40400000: return "IPI";
          case 0x40800000: return "IO_TIMER";
          case 0x41000000: return "REG_HIVE";
          case 0x42000000: return "REG_NOTIF";
          case 0x44000000: return "PPM_EXIT_LATENCY";
          case 0x48000000: return "WORKER_THREAD";

          case 0x80000001: return "OPTICAL_IO";
          case 0x80000002: return "OPTICAL_IO_INIT";
          case 0x80000008: return "DLL_INFO";
          case 0x80000010: return "DLL_FLUSH_WS";
          case 0x80000040: return "OB_HANDLE";
          case 0x80000080: return "OB_OBJECT";
          case 0x80000200: return "WAKE_DROP";
          case 0x80000400: return "WAKE_EVENT";
          case 0x80000800: return "DEBUGGER";
          case 0x80001000: return "PROC_ATTACH";
          case 0x80002000: return "WAKE_COUNTER";
          case 0x80008000: return "POWER";
          case 0x80010000: return "SOFT_TRIM";
          case 0x80020000: return "CC";
          case 0x80080000: return "FLT_IO_INIT";
          case 0x80100000: return "FLT_IO";
          case 0x80200000: return "FLT_FASTIO";
          case 0x80400000: return "FLT_IO_FAILURE";
          case 0x80800000: return "HV_PROFILE";
          case 0x81000000: return "WDF_DPC";
          case 0x82000000: return "WDF_INTERRUPT";
          case 0x84000000: return "CACHE_FLUSH";
          case 0xA0000001: return "HIBER_RUNDOWN";
          case 0x00000000: return "SYSCFG_SYSTEM";
          case 0xC0000001: return "SYSCFG_GRAPHICS";
          case 0xC0000004: return "SYSCFG_STORAGE";
          case 0xC0000008: return "SYSCFG_NETWORK";
          case 0xC0000010: return "SYSCFG_SERVICES";
          case 0xC0000020: return "SYSCFG_PNP";
          case 0xC0000040: return "SYSCFG_OPTICAL";
        }

        return "PERF_" + String.format("0x%x", perfinfo);
    }

    public String LookupTraceGroup(long logtype) {
        switch((int)logtype & 0xFF00 ) {
            case 0x0000: return "HEADER";
            case 0x0100: return "IO";
            case 0x0200: return "MEMORY";
            case 0x0300: return "PROCESS";
            case 0x0400: return "FILE";
            case 0x0500: return "THREAD";
            case 0x0600: return "TCPIP";
            case 0x0700: return "JOB";
            case 0x0800: return "UDPIP";
            case 0x0900: return "REGISTRY";
            case 0x0A00: return "DBGPRINT";
            case 0x0B00: return "CONFIG";
            case 0x0D00: return "WNF";
            case 0x0E00: return "POOL";
            case 0x0F00: return "PERFINFO";
            case 0x1000: return "HEAP";
            case 0x1100: return "OBJECT";
            case 0x1200: return "POWER";
            case 0x1300: return "MODBOUND";
            case 0x1400: return "IMAGE";
            case 0x1500: return "DPC";
            case 0x1600: return "CC";
            case 0x1700: return "CRITSEC";
            case 0x1800: return "STACKWALK";
            case 0x1900: return "UMS";
            case 0x1A00: return "ALPC";
            case 0x1B00: return "SPLITIO";
            case 0x1C00: return "THREAD_POOL";
            case 0x1D00: return "HYPERVISOR";
            case 0x1E00: return "HYPERVISORX";
        }

        return "EVENT_TRACE_GROUP_" + String.format("0x%x", logtype);
    }

    public String LookupLogType(long logtype) {
        switch((int)logtype) {
            case 0x0000: return "HEADER";
            case 0x0005: return "HEADER_EXTENSION";
            case 0x0008: return "RUNDOWN_COMPLETE";
            case 0x0020: return "GROUP_MASKS_END";
            case 0x0030: return "RUNDOWN_BEGIN";
            case 0x0031: return "RUNDOWN_END";
            case 0x0040: return "DBGID_RSDS";
            case 0x0041: return "DBGID_NB10";
            case 0x0042: return "BUILD_LAB";
            case 0x0043: return "BINARY_PATH";

            case 0x010A: return "IO_READ";
            case 0x010B: return "IO_WRITE";
            case 0x010C: return "IO_READ_INIT";
            case 0x010D: return "IO_WRITE_INIT";
            case 0x010E: return "IO_FLUSH";
            case 0x010F: return "IO_FLUSH_INIT";
            case 0x0110: return "IO_REDIRECTED_INIT";
            case 0x0120: return "DRIVER_INIT";
            case 0x0121: return "DRIVER_INIT_COMPLETE";
            case 0x0122: return "DRIVER_MAJORFUNCTION_CALL";
            case 0x0123: return "DRIVER_MAJORFUNCTION_RETURN";
            case 0x0124: return "DRIVER_COMPLETIONROUTINE_CALL";
            case 0x0125: return "DRIVER_COMPLETIONROUTINE_RETURN";
            case 0x0126: return "DRIVER_ADD_DEVICE_CALL";
            case 0x0127: return "DRIVER_ADD_DEVICE_RETURN";
            case 0x0128: return "DRIVER_STARTIO_CALL";
            case 0x0129: return "DRIVER_STARTIO_RETURN";
            case 0x0130: return "PREFETCH_ACTION";
            case 0x0131: return "PREFETCH_REQUEST";
            case 0x0132: return "PREFETCH_READLIST";
            case 0x0133: return "PREFETCH_READ";
            case 0x0134: return "DRIVER_COMPLETE_REQUEST";
            case 0x0135: return "DRIVER_COMPLETE_REQUEST_RETURN";
            case 0x0136: return "BOOT_PREFETCH_INFORMATION";
            case 0x0137: return "OPTICAL_IO_READ";
            case 0x0138: return "OPTICAL_IO_WRITE";
            case 0x0139: return "OPTICAL_IO_FLUSH";
            case 0x013A: return "OPTICAL_IO_READ_INIT";
            case 0x013B: return "OPTICAL_IO_WRITE_INIT";
            case 0x013C: return "OPTICAL_IO_FLUSH_INIT";

            case 0x020A: return "PAGE_FAULT_TRANSITION";
            case 0x020B: return "PAGE_FAULT_DEMAND_ZERO";
            case 0x020C: return "PAGE_FAULT_COPY_ON_WRITE";
            case 0x020D: return "PAGE_FAULT_GUARD_PAGE";
            case 0x020E: return "PAGE_FAULT_HARD_PAGE_FAULT";
            case 0x020F: return "PAGE_FAULT_ACCESS_VIOLATION";
            case 0x0220: return "HARDFAULT";
            case 0x0221: return "REMOVEPAGEBYCOLOR";
            case 0x0222: return "REMOVEPAGEFROMLIST";
            case 0x0223: return "PAGEINMEMORY";
            case 0x0224: return "INSERTINFREELIST";
            case 0x0225: return "INSERTINMODIFIEDLIST";
            case 0x0226: return "INSERTINLIST";
            case 0x0228: return "INSERTATFRONT";
            case 0x0229: return "UNLINKFROMSTANDBY";
            case 0x022A: return "UNLINKFFREEORZERO";
            case 0x022B: return "WORKINGSETMANAGER";
            case 0x022C: return "TRIMPROCESS";
            case 0x022E: return "ZEROSHARECOUNT";
            case 0x023C: return "WSINFOPROCESS";
            case 0x0245: return "FAULTADDR_WITH_IP";
            case 0x0246: return "TRIMSESSION";
            case 0x0247: return "MEMORYSNAPLITE";
            case 0x0248: return "PFMAPPED_SECTION_RUNDOWN";
            case 0x0249: return "PFMAPPED_SECTION_CREATE";
            case 0x024A: return "WSINFOSESSION";
            case 0x024B: return "CREATE_SESSION";
            case 0x024C: return "SESSION_RUNDOWN_DC_END";
            case 0x024D: return "SESSION_RUNDOWN_DC_START";
            case 0x024E: return "SESSION_DELETE";
            case 0x024F: return "PFMAPPED_SECTION_DELETE";
            case 0x0262: return "VIRTUAL_ALLOC";
            case 0x0263: return "VIRTUAL_FREE";
            case 0x0264: return "HEAP_RANGE_RUNDOWN";
            case 0x0265: return "HEAP_RANGE_CREATE";
            case 0x0266: return "HEAP_RANGE_RESERVE";
            case 0x0267: return "HEAP_RANGE_RELEASE";
            case 0x0268: return "HEAP_RANGE_DESTROY";
            case 0x0269: return "PAGEFILE_BACK";
            case 0x0270: return "MEMINFO";
            case 0x0271: return "CONTMEM_GENERATE";
            case 0x0272: return "FILE_STORE_FAULT";
            case 0x0273: return "INMEMORY_STORE_FAULT";
            case 0x0274: return "COMPRESSED_PAGE";
            case 0x0275: return "PAGEINMEMORY_ACTIVE";
            case 0x0276: return "PAGE_ACCESS";
            case 0x0277: return "PAGE_RELEASE";
            case 0x0278: return "PAGE_RANGE_ACCESS";
            case 0x0279: return "PAGE_RANGE_RELEASE";
            case 0x027A: return "PAGE_COMBINE";
            case 0x027B: return "KERNEL_MEMUSAGE";
            case 0x027C: return "MM_STATS";
            case 0x027D: return "MEMINFOEX_WS";
            case 0x027E: return "MEMINFOEX_SESSIONWS";
            case 0x027F: return "VIRTUAL_ROTATE";
            case 0x0280: return "VIRTUAL_ALLOC_DC_START";
            case 0x0281: return "VIRTUAL_ALLOC_DC_END";
            case 0x0282: return "PAGE_ACCESS_EX";
            case 0x0283: return "REMOVEFROMWS";
            case 0x0284: return "WSSHAREABLE_RUNDOWN";
            case 0x0285: return "INMEMORYACTIVE_RUNDOWN";
            case 0x0286: return "MEM_RESET_INFO";
            case 0x0287: return "PFMAPPED_SECTION_OBJECT_CREATE";
            case 0x0288: return "PFMAPPED_SECTION_OBJECT_DELETE";

            case 0x0301: return "PROCESS_CREATE";
            case 0x0302: return "PROCESS_DELETE";
            case 0x0303: return "PROCESS_DC_START";
            case 0x0304: return "PROCESS_DC_END";
            case 0x030A: return "PROCESS_LOAD_IMAGE";
            case 0x030B: return "PROCESS_TERMINATE";
            case 0x0320: return "PROCESS_PERFCTR_END";
            case 0x0321: return "PROCESS_PERFCTR_RD";
            case 0x0323: return "INSWAPPROCESS";
            case 0x0324: return "PROCESS_FREEZE";
            case 0x0325: return "PROCESS_THAW";
            case 0x0326: return "BOOT_PHASE_START";
            case 0x0327: return "ZOMBIE_PROCESS";
            case 0x0328: return "PROCESS_SET_AFFINITY";
            case 0x0330: return "CHARGE_WAKE_COUNTER_USER";
            case 0x0331: return "CHARGE_WAKE_COUNTER_EXECUTION";
            case 0x0332: return "CHARGE_WAKE_COUNTER_KERNEL";
            case 0x0333: return "CHARGE_WAKE_COUNTER_INSTRUMENTATION";
            case 0x0334: return "CHARGE_WAKE_COUNTER_PRESERVE_PROCESS";
            case 0x0340: return "RELEASE_WAKE_COUNTER_USER";
            case 0x0341: return "RELEASE_WAKE_COUNTER_EXECUTION";
            case 0x0342: return "RELEASE_WAKE_COUNTER_KERNEL";
            case 0x0343: return "RELEASE_WAKE_COUNTER_INSTRUMENTATION";
            case 0x0344: return "RELEASE_WAKE_COUNTER_PRESERVE_PROCESS";
            case 0x0350: return "WAKE_DROP_USER";
            case 0x0351: return "WAKE_DROP_EXECUTION";
            case 0x0352: return "WAKE_DROP_KERNEL";
            case 0x0353: return "WAKE_DROP_INSTRUMENTATION";
            case 0x0354: return "WAKE_DROP_PRESERVE_PROCESS";
            case 0x0360: return "WAKE_EVENT_USER";
            case 0x0361: return "WAKE_EVENT_EXECUTION";
            case 0x0362: return "WAKE_EVENT_KERNEL";
            case 0x0363: return "WAKE_EVENT_INSTRUMENTATION";
            case 0x0364: return "WAKE_EVENT_PRESERVE_PROCESS";
            case 0x0370: return "DEBUG_EVENT";

            case 0x0400: return "FILENAME";
            case 0x0420: return "FILENAME_CREATE";
            case 0x0421: return "FILENAME_SAME";
            case 0x0422: return "FILENAME_NULL";
            case 0x0423: return "FILENAME_DELETE";
            case 0x0424: return "FILENAME_RUNDOWN";
            case 0x0425: return "MAPFILE";
            case 0x0426: return "UNMAPFILE";
            case 0x0427: return "MAPFILE_DC_START";
            case 0x0428: return "MAPFILE_DC_END";
            case 0x0440: return "FILE_IO_CREATE";
            case 0x0441: return "FILE_IO_CLEANUP";
            case 0x0442: return "FILE_IO_CLOSE";
            case 0x0443: return "FILE_IO_READ";
            case 0x0444: return "FILE_IO_WRITE";
            case 0x0445: return "FILE_IO_SET_INFORMATION";
            case 0x0446: return "FILE_IO_DELETE";
            case 0x0447: return "FILE_IO_RENAME";
            case 0x0448: return "FILE_IO_DIRENUM";
            case 0x0449: return "FILE_IO_FLUSH";
            case 0x044A: return "FILE_IO_QUERY_INFORMATION";
            case 0x044B: return "FILE_IO_FS_CONTROL";
            case 0x044C: return "FILE_IO_OPERATION_END";
            case 0x044D: return "FILE_IO_DIRNOTIFY";
            case 0x044E: return "FILE_IO_CREATE_NEW";
            case 0x044F: return "FILE_IO_DELETE_PATH";
            case 0x0450: return "FILE_IO_RENAME_PATH";
            case 0x0451: return "FILE_IO_SETLINK_PATH";
            case 0x0452: return "FILE_IO_SETLINK";
            case 0x0460: return "FLT_PREOP_INIT";
            case 0x0461: return "FLT_POSTOP_INIT";
            case 0x0462: return "FLT_PREOP_COMPLETION";
            case 0x0463: return "FLT_POSTOP_COMPLETION";
            case 0x0464: return "FLT_PREOP_FAILURE";
            case 0x0465: return "FLT_POSTOP_FAILURE";

            case 0x0501: return "THREAD_CREATE";
            case 0x0502: return "THREAD_DELETE";
            case 0x0503: return "THREAD_DC_START";
            case 0x0504: return "THREAD_DC_END";
            case 0x0524: return "CONTEXTSWAP";
            case 0x0525: return "CONTEXTSWAP_BATCH";
            case 0x0529: return "SPINLOCK";
            case 0x052A: return "QUEUE";
            case 0x052B: return "RESOURCE";
            case 0x052C: return "PUSHLOCK";
            case 0x052D: return "WAIT_SINGLE";
            case 0x052E: return "WAIT_MULTIPLE";
            case 0x052F: return "DELAY_EXECUTION";
            case 0x0530: return "THREAD_SET_PRIORITY";
            case 0x0531: return "THREAD_SET_BASE_PRIORITY";
            case 0x0532: return "READY_THREAD";
            case 0x0533: return "THREAD_SET_PAGE_PRIORITY";
            case 0x0534: return "THREAD_SET_IO_PRIORITY";
            case 0x0535: return "THREAD_SET_AFFINITY";
            case 0x0539: return "WORKER_THREAD_ITEM";
            case 0x053A: return "DFSS_START_NEW_INTERVAL";
            case 0x053B: return "DFSS_PROCESS_IDLE_ONLY_QUEUE";
            case 0x053C: return "ANTI_STARVATION_BOOST";
            case 0x053D: return "THREAD_MIGRATION";
            case 0x053E: return "KQUEUE_ENQUEUE";
            case 0x053F: return "KQUEUE_DEQUEUE";
            case 0x0540: return "WORKER_THREAD_ITEM_START";
            case 0x0541: return "WORKER_THREAD_ITEM_END";
            case 0x0542: return "AUTO_BOOST_SET_FLOOR";
            case 0x0543: return "AUTO_BOOST_CLEAR_FLOOR";
            case 0x0544: return "AUTO_BOOST_NO_ENTRIES";
            case 0x0545: return "THREAD_SUBPROCESSTAG_CHANGED";

            case 0x060A: return "TCPIP_SEND";
            case 0x060B: return "TCPIP_RECEIVE";
            case 0x060C: return "TCPIP_CONNECT";
            case 0x060D: return "TCPIP_DISCONNECT";
            case 0x060E: return "TCPIP_RETRANSMIT";
            case 0x060F: return "TCPIP_ACCEPT";
            case 0x0610: return "TCPIP_RECONNECT";
            case 0x0611: return "TCPIP_FAIL";
            case 0x0612: return "TCPIP_TCPCOPY";
            case 0x0613: return "TCPIP_ARPCOPY";
            case 0x0614: return "TCPIP_FULLACK";
            case 0x0615: return "TCPIP_PARTACK";
            case 0x0616: return "TCPIP_DUPACK";
            case 0x061A: return "TCPIP_SEND_IPV6";
            case 0x061B: return "TCPIP_RECEIVE_IPV6";
            case 0x061C: return "TCPIP_CONNECT_IPV6";
            case 0x061D: return "TCPIP_DISCONNECT_IPV6";
            case 0x061E: return "TCPIP_RETRANSMIT_IPV6";
            case 0x061F: return "TCPIP_ACCEPT_IPV6";
            case 0x0620: return "TCPIP_RECONNECT_IPV6";
            case 0x0621: return "TCPIP_FAIL_IPV6";
            case 0x0622: return "TCPIP_TCPCOPY_IPV6";
            case 0x0623: return "TCPIP_ARPCOPY_IPV6";
            case 0x0624: return "TCPIP_FULLACK_IPV6";
            case 0x0625: return "TCPIP_PARTACK_IPV6";
            case 0x0626: return "TCPIP_DUPACK_IPV6";

            case 0x0720: return "JOB_CREATE";
            case 0x0721: return "JOB_TERMINATE";
            case 0x0722: return "JOB_OPEN";
            case 0x0723: return "JOB_ASSIGN_PROCESS";
            case 0x0724: return "JOB_REMOVE_PROCESS";
            case 0x0725: return "JOB_SET";
            case 0x0726: return "JOB_QUERY";
            case 0x0727: return "JOB_SET_FAILED";
            case 0x0728: return "JOB_QUERY_FAILED";
            case 0x0729: return "JOB_SET_NOTIFICATION";
            case 0x072A: return "JOB_SEND_NOTIFICATION";
            case 0x072B: return "JOB_QUERY_VIOLATION";
            case 0x072C: return "JOB_SET_CPU_RATE";
            case 0x072D: return "JOB_SET_NET_RATE";

            case 0x080A: return "UDP_SEND";
            case 0x080B: return "UDP_RECEIVE";
            case 0x0811: return "UDP_FAIL";
            case 0x081A: return "UDP_SEND_IPV6";
            case 0x081B: return "UDP_RECEIVE_IPV6";

            case 0x0918: return "REG_RUNDOWNBEGIN";
            case 0x0919: return "REG_RUNDOWNEND";
            case 0x0920: return "CMCELLREFERRED";
            case 0x0921: return "REG_SET_VALUE";
            case 0x0922: return "REG_COUNTERS";
            case 0x0923: return "REG_CONFIG";
            case 0x0924: return "REG_HIVE_INITIALIZE";
            case 0x0925: return "REG_HIVE_DESTROY";
            case 0x0926: return "REG_HIVE_LINK";
            case 0x0927: return "REG_HIVE_RUNDOWN_DC_END";
            case 0x0928: return "REG_HIVE_DIRTY";
            case 0x0930: return "REG_NOTIF_REGISTER";
            case 0x0931: return "REG_NOTIF_DELIVER";

            case 0x0A20: return "DEBUG_PRINT";

            case 0x0B0A: return "CONFIG_CPU";
            case 0x0B0B: return "CONFIG_PHYSICALDISK";
            case 0x0B0C: return "CONFIG_LOGICALDISK";
            case 0x0B0D: return "CONFIG_NIC";
            case 0x0B0E: return "CONFIG_VIDEO";
            case 0x0B0F: return "CONFIG_SERVICES";
            case 0x0B10: return "CONFIG_POWER";
            case 0x0B12: return "CONFIG_OPTICALMEDIA";
            case 0x0B15: return "CONFIG_IRQ";
            case 0x0B16: return "CONFIG_PNP";
            case 0x0B17: return "CONFIG_IDECHANNEL";
            case 0x0B18: return "CONFIG_NUMANODE";
            case 0x0B19: return "CONFIG_PLATFORM";
            case 0x0B1A: return "CONFIG_PROCESSORGROUP";
            case 0x0B1B: return "CONFIG_PROCESSORNUMBER";
            case 0x0B1C: return "CONFIG_DPI";
            case 0x0B1D: return "CONFIG_CODEINTEGRITY";
            case 0x0B1E: return "CONFIG_MACHINEID";

            case 0x0D20: return "WNF_SUBSCRIBE";
            case 0x0D21: return "WNF_UNSUBSCRIBE";
            case 0x0D22: return "WNF_CALLBACK";
            case 0x0D23: return "WNF_PUBLISH";
            case 0x0D24: return "WNF_NAME_SUB_RUNDOWN";

            case 0x0E20: return "ALLOCATEPOOL";
            case 0x0E21: return "ALLOCATEPOOL_SESSION";
            case 0x0E22: return "FREEPOOL";
            case 0x0E23: return "FREEPOOL_SESSION";
            case 0x0E24: return "ADDPOOLPAGE";
            case 0x0E25: return "ADDPOOLPAGE_SESSION";
            case 0x0E26: return "BIGPOOLPAGE";
            case 0x0E27: return "BIGPOOLPAGE_SESSION";
            case 0x0E28: return "POOLSNAP_DC_START";
            case 0x0E29: return "POOLSNAP_DC_END";
            case 0x0E2A: return "BIGPOOLSNAP_DC_START";
            case 0x0E2B: return "BIGPOOLSNAP_DC_END";
            case 0x0E2C: return "POOLSNAP_SESSION_DC_START";
            case 0x0E2D: return "POOLSNAP_SESSION_DC_END";
            case 0x0E2E: return "SESSIONBIGPOOLSNAP_DC_START";
            case 0x0E2F: return "SESSIONBIGPOOLSNAP_DC_END";

            case 0x0F20: return "RUNDOWN_CHECKPOINT";
            case 0x0F22: return "MARK";
            case 0x0F24: return "ASYNCMARK";
            case 0x0F26: return "IMAGENAME";
            case 0x0F27: return "DELAYS_CC_CAN_I_WRITE";
            case 0x0F2E: return "SAMPLED_PROFILE";
            case 0x0F2F: return "PMC_INTERRUPT";
            case 0x0F30: return "PMC_CONFIG";
            case 0x0F32: return "MSI_INTERRUPT";
            case 0x0F33: return "SYSCALL_ENTER";
            case 0x0F34: return "SYSCALL_EXIT";
            case 0x0F35: return "BACKTRACE";
            case 0x0F36: return "BACKTRACE_USERSTACK";
            case 0x0F37: return "SAMPLED_PROFILE_CACHE";
            case 0x0F38: return "EXCEPTION_STACK";
            case 0x0F39: return "BRANCH_TRACE";
            case 0x0F3A: return "DEBUGGER_ENABLED";
            case 0x0F3B: return "DEBUGGER_EXIT";
            case 0x0F40: return "BRANCH_TRACE_DEBUG";
            case 0x0F41: return "BRANCH_ADDRESS_DEBUG";
            case 0x0F42: return "THREADED_DPC";
            case 0x0F43: return "INTERRUPT";
            case 0x0F44: return "DPC";
            case 0x0F45: return "TIMERDPC";
            case 0x0F46: return "IOTIMER_EXPIRATION";
            case 0x0F47: return "SAMPLED_PROFILE_NMI";
            case 0x0F48: return "SAMPLED_PROFILE_SET_INTERVAL";
            case 0x0F49: return "SAMPLED_PROFILE_DC_START";
            case 0x0F4A: return "SAMPLED_PROFILE_DC_END";
            case 0x0F4B: return "SPINLOCK_DC_START";
            case 0x0F4C: return "SPINLOCK_DC_END";
            case 0x0F4D: return "ERESOURCE_DC_START";
            case 0x0F4E: return "ERESOURCE_DC_END";
            case 0x0F4F: return "CLOCK_INTERRUPT";
            case 0x0F50: return "TIMER_EXPIRATION_START";
            case 0x0F51: return "TIMER_EXPIRATION";
            case 0x0F52: return "TIMER_SET_PERIODIC";
            case 0x0F53: return "TIMER_SET_ONE_SHOT";
            case 0x0F54: return "TIMER_SET_THREAD";
            case 0x0F55: return "TIMER_CANCEL";
            case 0x0F56: return "TIME_ADJUSTMENT";
            case 0x0F57: return "CLOCK_MODE_SWITCH";
            case 0x0F58: return "CLOCK_TIME_UPDATE";
            case 0x0F59: return "CLOCK_DYNAMIC_TICK_VETO";
            case 0x0F5A: return "CLOCK_CONFIGURATION";
            case 0x0F5B: return "IPI";
            case 0x0F5C: return "UNEXPECTED_INTERRUPT";
            case 0x0F5D: return "IOTIMER_START";
            case 0x0F5E: return "IOTIMER_STOP";
            case 0x0F5F: return "PASSIVE_INTERRUPT";
            case 0x0F60: return "WDF_INTERRUPT";
            case 0x0F61: return "WDF_PASSIVE_INTERRUPT";
            case 0x0F62: return "WDF_DPC";
            case 0x0F63: return "CPU_CACHE_FLUSH";
            case 0x0F64: return "DPC_ENQUEUE";
            case 0x0F65: return "DPC_EXECUTION";
            case 0x0F66: return "INTERRUPT_STEERING";
            case 0x0F67: return "WDF_WORK_ITEM";
            case 0x0F68: return "KTIMER2_SET";
            case 0x0F69: return "KTIMER2_EXPIRATION";
            case 0x0F6A: return "KTIMER2_CANCEL";
            case 0x0F6B: return "KTIMER2_DISABLE";
            case 0x0F6C: return "KTIMER2_FINALIZATION";
            case 0x0F6D: return "SHOULD_YIELD_PROCESSOR";
            case 0x0F80: return "FUNCTION_CALL";
            case 0x0F81: return "FUNCTION_RETURN";
            case 0x0F82: return "FUNCTION_ENTER";
            case 0x0F83: return "FUNCTION_EXIT";
            case 0x0F84: return "TAILCALL";
            case 0x0F85: return "TRAP";
            case 0x0F86: return "SPINLOCK_ACQUIRE";
            case 0x0F87: return "SPINLOCK_RELEASE";
            case 0x0F88: return "CAP_COMMENT";
            case 0x0F89: return "CAP_RUNDOWN";

            case 0x1020: return "HEAP_CREATE";
            case 0x1021: return "HEAP_ALLOC";
            case 0x1022: return "HEAP_REALLOC";
            case 0x1023: return "HEAP_DESTROY";
            case 0x1024: return "HEAP_FREE";
            case 0x1025: return "HEAP_EXTEND";
            case 0x1026: return "HEAP_SNAPSHOT";
            case 0x1027: return "HEAP_CREATE_SNAPSHOT";
            case 0x1028: return "HEAP_DESTROY_SNAPSHOT";
            case 0x1029: return "HEAP_EXTEND_SNAPSHOT";
            case 0x102A: return "HEAP_CONTRACT";
            case 0x102B: return "HEAP_LOCK";
            case 0x102C: return "HEAP_UNLOCK";
            case 0x102D: return "HEAP_VALIDATE";
            case 0x102E: return "HEAP_WALK";
            case 0x102F: return "HEAP_SUBSEGMENT_ALLOC";
            case 0x1030: return "HEAP_SUBSEGMENT_FREE";
            case 0x1031: return "HEAP_SUBSEGMENT_ALLOC_CACHE";
            case 0x1032: return "HEAP_SUBSEGMENT_FREE_CACHE";
            case 0x1033: return "HEAP_COMMIT";
            case 0x1034: return "HEAP_DECOMMIT";
            case 0x1035: return "HEAP_SUBSEGMENT_INIT";
            case 0x1036: return "HEAP_AFFINITY_ENABLE";
            case 0x1038: return "HEAP_SUBSEGMENT_ACTIVATED";
            case 0x1039: return "HEAP_AFFINITY_ASSIGN";
            case 0x103A: return "HEAP_REUSE_THRESHOLD_ACTIVATED";

            case 0x1120: return "CREATE_HANDLE";
            case 0x1121: return "CLOSE_HANDLE";
            case 0x1122: return "DUPLICATE_HANDLE";
            case 0x1124: return "OBJECT_TYPE_DC_START";
            case 0x1125: return "OBJECT_TYPE_DC_END";
            case 0x1126: return "OBJECT_HANDLE_DC_START";
            case 0x1127: return "OBJECT_HANDLE_DC_END";
            case 0x1130: return "CREATE_OBJECT";
            case 0x1131: return "DELETE_OBJECT";
            case 0x1132: return "REFERENCE_OBJECT";
            case 0x1133: return "DEREFERENCE_OBJECT";

            case 0x1220: return "BATTERY_LIFE_INFO";
            case 0x1221: return "IDLE_STATE_CHANGE";
            case 0x1222: return "SET_POWER_ACTION";
            case 0x1223: return "SET_POWER_ACTION_RET";
            case 0x1224: return "SET_DEVICES_STATE";
            case 0x1225: return "SET_DEVICES_STATE_RET";
            case 0x1226: return "PO_NOTIFY_DEVICE";
            case 0x1227: return "PO_NOTIFY_DEVICE_COMPLETE";
            case 0x1228: return "PO_SESSION_CALLOUT";
            case 0x1229: return "PO_SESSION_CALLOUT_RET";
            case 0x1230: return "PO_PRESLEEP";
            case 0x1231: return "PO_POSTSLEEP";
            case 0x1232: return "PO_CALIBRATED_PERFCOUNTER";
            case 0x1233: return "PPM_PERF_STATE_CHANGE";
            case 0x1234: return "PPM_THROTTLE_STATE_CHANGE";
            case 0x1235: return "PPM_IDLE_STATE_CHANGE";
            case 0x1236: return "PPM_THERMAL_CONSTRAINT";
            case 0x1237: return "PO_SIGNAL_RESUME_UI";
            case 0x1238: return "PO_SIGNAL_VIDEO_ON";
            case 0x1239: return "PPM_IDLE_STATE_ENTER";
            case 0x123A: return "PPM_IDLE_STATE_EXIT";
            case 0x123B: return "PPM_PLATFORM_IDLE_STATE_ENTER";
            case 0x123C: return "PPM_IDLE_EXIT_LATENCY";
            case 0x123D: return "PPM_IDLE_PROCESSOR_SELECTION";
            case 0x123E: return "PPM_IDLE_PLATFORM_SELECTION";
            case 0x123F: return "PPM_COORDINATED_IDLE_ENTER";
            case 0x1240: return "PPM_COORDINATED_IDLE_EXIT";

            case 0x1318: return "COWHEADER";
            case 0x1319: return "COWBLOB";
            case 0x131A: return "COWBLOB_CLOSED";
            case 0x1320: return "MODULEBOUND_ENT";
            case 0x1321: return "MODULEBOUND_JUMP";
            case 0x1322: return "MODULEBOUND_RET";
            case 0x1323: return "MODULEBOUND_CALL";
            case 0x1324: return "MODULEBOUND_CALLRET";
            case 0x1325: return "MODULEBOUND_INT2E";
            case 0x1326: return "MODULEBOUND_INT2B";
            case 0x1327: return "MODULEBOUND_FULLTRACE";

            case 0x1401: return "IMAGE_LOAD";
            case 0x1402: return "IMAGE_UNLOAD";
            case 0x1403: return "IMAGE_DC_START";
            case 0x1404: return "IMAGE_DC_END";
            case 0x1420: return "IMAGE_RELOCATION";
            case 0x1421: return "IMAGE_KERNEL_BASE";
            case 0x1422: return "IMAGE_HYPERCALL_PAGE";
            case 0x1480: return "LDR_LOCK_ACQUIRE_ATTEMPT";
            case 0x1481: return "LDR_LOCK_ACQUIRE_SUCCESS";
            case 0x1482: return "LDR_LOCK_ACQUIRE_FAIL";
            case 0x1483: return "LDR_LOCK_ACQUIRE_WAIT";
            case 0x1484: return "LDR_PROC_INIT_DONE";
            case 0x1485: return "LDR_CREATE_SECTION";
            case 0x1486: return "LDR_SECTION_CREATED";
            case 0x1487: return "LDR_MAP_VIEW";
            case 0x1490: return "LDR_RELOCATE_IMAGE";
            case 0x1491: return "LDR_IMAGE_RELOCATED";
            case 0x1492: return "LDR_HANDLE_OLD_DESCRIPTORS";
            case 0x1493: return "LDR_OLD_DESCRIPTORS_HANDLED";
            case 0x1494: return "LDR_HANDLE_NEW_DESCRIPTORS";
            case 0x1495: return "LDR_NEW_DESCRIPTORS_HANDLED";
            case 0x1496: return "LDR_DLLMAIN_EXIT";
            case 0x14A0: return "LDR_FIND_DLL";
            case 0x14A1: return "LDR_VIEW_MAPPED";
            case 0x14A2: return "LDR_LOCK_RELEASE";
            case 0x14A3: return "LDR_DLLMAIN_ENTER";
            case 0x14A4: return "LDR_ERROR";
            case 0x14A5: return "LDR_VIEW_MAPPING";
            case 0x14A6: return "LDR_SNAPPING";
            case 0x14A7: return "LDR_SNAPPED";
            case 0x14A8: return "LDR_LOADING";
            case 0x14A9: return "LDR_LOADED";
            case 0x14AA: return "LDR_FOUND_KNOWN_DLL";
            case 0x14AB: return "LDR_ABNORMAL";
            case 0x14AC: return "LDR_PLACEHOLDER";
            case 0x14AD: return "LDR_RDY_TO_INIT";
            case 0x14AE: return "LDR_RDY_TO_RUN";
            case 0x14B0: return "LDR_NEW_DLL_LOAD";
            case 0x14B1: return "LDR_NEW_DLL_AS_DATA";
            case 0x14C0: return "LDR_EXTERNAL_PATH";
            case 0x14C1: return "LDR_GENERATED_PATH";
            case 0x14D0: return "LDR_APISET_RESOLVING";
            case 0x14D1: return "LDR_APISET_HOSTED";
            case 0x14D2: return "LDR_APISET_UNHOSTED";
            case 0x14D3: return "LDR_APISET_UNRESOLVED";
            case 0x14D4: return "LDR_SEARCH_SECURITY";
            case 0x14D5: return "LDR_SEARCH_PATH_SECURITY";

            case 0x1600: return "CC_WORKITEM_ENQUEUE";
            case 0x1601: return "CC_WORKITEM_DEQUEUE";
            case 0x1602: return "CC_WORKITEM_COMPLETE";
            case 0x1603: return "CC_READ_AHEAD";
            case 0x1604: return "CC_WRITE_BEHIND";
            case 0x1605: return "CC_LAZY_WRITE_SCAN";
            case 0x1606: return "CC_CAN_I_WRITE_FAIL";
            case 0x1609: return "CC_FLUSH_CACHE";
            case 0x160A: return "CC_FLUSH_SECTION";
            case 0x160B: return "CC_READ_AHEAD_PREFETCH";
            case 0x160C: return "CC_SCHEDULE_READ_AHEAD";
            case 0x160D: return "CC_LOGGED_STREAM_INFO";
            case 0x160E: return "CC_EXTRA_WRITEBEHIND_THREAD";

            case 0x1720: return "CRITSEC_ENTER";
            case 0x1721: return "CRITSEC_LEAVE";
            case 0x1722: return "CRITSEC_COLLISION";
            case 0x1723: return "CRITSEC_INITIALIZE";

            case 0x1820: return "STACKWALK";
            case 0x1822: return "STACKTRACE_CREATE";
            case 0x1823: return "STACKTRACE_DELETE";
            case 0x1824: return "STACKTRACE_RUNDOWN";
            case 0x1825: return "STACKTRACE_KEY_KERNEL";
            case 0x1826: return "STACKTRACE_KEY_USER";

            case 0x1920: return "UMS_DIRECTED_SWITCH_START";
            case 0x1921: return "UMS_DIRECTED_SWITCH_END";
            case 0x1922: return "UMS_PARK";
            case 0x1923: return "UMS_DISASSOCIATE";
            case 0x1924: return "UMS_CONTEXT_SWITCH";

            case 0x1A21: return "ALPC_SEND_MESSAGE";
            case 0x1A22: return "ALPC_RECEIVE_MESSAGE";
            case 0x1A23: return "ALPC_WAIT_FOR_REPLY";
            case 0x1A24: return "ALPC_WAIT_FOR_NEW_MESSAGE";
            case 0x1A25: return "ALPC_UNWAIT";
            case 0x1A26: return "ALPC_CONNECT_REQUEST";
            case 0x1A27: return "ALPC_CONNECT_SUCCESS";
            case 0x1A28: return "ALPC_CONNECT_FAIL";
            case 0x1A29: return "ALPC_CLOSE_PORT";

            case 0x1B20: return "SPLITIO_VOLMGR";

            case 0x1C20: return "TP_CALLBACK_ENQUEUE";
            case 0x1C21: return "TP_CALLBACK_DEQUEUE";
            case 0x1C22: return "TP_CALLBACK_START";
            case 0x1C23: return "TP_CALLBACK_STOP";
            case 0x1C24: return "TP_CALLBACK_CANCEL";
            case 0x1C25: return "TP_POOL_CREATE";
            case 0x1C26: return "TP_POOL_CLOSE";
            case 0x1C27: return "TP_POOL_TH_MIN_SET";
            case 0x1C28: return "TP_POOL_TH_MAX_SET";
            case 0x1C29: return "TP_WORKER_NUMANODE_SWITCH";
            case 0x1C2A: return "TP_TIMER_SET";
            case 0x1C2B: return "TP_TIMER_CANCELLED";
            case 0x1C2C: return "TP_TIMER_SET_NTTIMER";
            case 0x1C2D: return "TP_TIMER_CANCEL_NTTIMER";
            case 0x1C2E: return "TP_TIMER_EXPIRATION_BEGIN";
            case 0x1C2F: return "TP_TIMER_EXPIRATION_END";
            case 0x1C30: return "TP_TIMER_EXPIRATION";
        }
        
        return "PERFINFO_LOG_TYPE_" + String.format("0x%x", logtype);
    }
}