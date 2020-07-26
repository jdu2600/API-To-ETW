
/* ###
 * IP: jdu2600
 * IP: GHIDRA
 *
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

// Given a list of functions, show all calls to EtwWrite* reachable from each function.
//    Execute the script.
//    For each function, all calls to EtwWrite* functions will be output
//    along with provider and event details.
//
// kernel-mode ETW functions are prefixed with Etw, the Win32 equivalents with Event and the native API ones with EtwEvent.
// All APIs take the same parameters... so this script should work everywhere. :-)
//
//@category Functions.ETW

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.*;
import generic.stl.Pair;

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
import ghidra.util.exception.*;

public class DumpEtwWrites extends GhidraScript {

	private Boolean quickScan = false;	// stop processing after maxEvents have been found, or maxCallDepth/maxExportCallDepth has been reached
	private int maxEvents = 10;
	private int maxCallDepth = 7;
	private int maxExportCallDepth = 1;

	private String functionsFile = "functions.txt"; // analyse these functions
	private String ignoreFile = "ignore.txt";       // ignore these functions

	private Boolean debugPrint = true;

	private DataType eventDescriptorType = null;
	private DataType ucharType = null;
	private DataType ushortType = null;
	private DataType ulonglongType = null;
	private DataType guidType = null;
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
	    	printf(" * quick scan mode - maxEvents=%d maxCallDepth=%d maxExportCallDepth=%d\n", maxEvents, maxCallDepth, maxExportCallDepth);
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
	    	printf(" * analysing %d functions\n", functions.size());
	    }
	    catch(Exception e) {
	    	printf(" * %s not provided - analysing all exports instead\n", functionsFile);
	    	functions = exports;
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
	    String csvFilename = currentProgram.getName() + ".csv";
	    printf(" * output will be written to %s\n", csvFilename);
	    new File(csvFilename).delete();
    	csv = new PrintWriter(new File(csvFilename));
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
        	for(String etwRegisterFuncName : etwRegisterFuncs)	{
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
        	for(String functionName : functions)	{
        		List<Function> functionList = getGlobalFunctions(functionName);
        		if(functionList.size() == 0) {
        			printf("   --> found 0 instances of %s\n", functionName);
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
        if (refData != null && (refData.getDataType().isEquivalent(new ImageBaseOffset32DataType()) || refData.getDataType().isEquivalent(new DWordDataType()))) 
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
        
		ClangTokenGroup cCode = decomplib.decompileFunction(refFunc, decomplib.getOptions().getDefaultTimeout(), monitor).getCCodeMarkup();
        if (cCode == null)
        	throw new Exception("[CALL EtwRegister] Decompile Error: " + decomplib.getLastMessage());
        
        try {
        	cacheProviderReghandle(refFunc, cCode, refAddr);
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
        		String etwRegisterCall = getFunctionAt(pcodeOp.getInput(0).getAddress()).getName();
        		
        		if(etwRegisterCall.endsWith("NotificationRegister")) {
        			// NTSTATUS EtwNotificationRegister (LPCGUID Guid, ULONG Type, PETW_NOTIFICATION_CALLBACK Callback, PVOID Context, PREGHANDLE RegHandle);
		    		throw new NotYetImplementedException(etwRegisterCall);
    			}
        		
        		if(pcodeOp.getNumInputs() < 5) {
	        		printf("[WARNING] Incomplete Decompilation @ 0x%x - %s\n", astNode.getMaxAddress().getOffset(),  stmt.toString());
	        		return false;
	        	}
	        	
  	        	debugPrintf("%s :: %s\n", refAddr.toString(), stmt);

  	        	// we need to pass the calling function in order to back trace through any parameters
  	        	Stack<Function> callingFunc = new Stack<Function>();
  	        	callingFunc.push(f);
  	        	

	        	List<Long> pGuids = null;
	        	List<Long> reghandles = null;
	        	try {
	        		pGuids = resolveFunctionParameterToConstant(pcodeOp, 1, callingFunc);
	        		reghandles = resolveFunctionParameterToConstant(pcodeOp, 4, callingFunc);
	        	 } catch (NotFoundException e) {	        		
	        		printf("   --> skipping %s due to local variable storage\n", etwRegisterCall);
	        		return true;
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
		        		guid = getDataAt(guidAddr).toString().substring(5);
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
		printf(" * analysing %s\n", func.getName());
				
     	Queue<QueuedFunction> queue = new LinkedList<QueuedFunction>();
     	List<String> processed = new LinkedList<String>();
     	Stack<Function> callPath = new Stack<Function>(); // helps with back tracing constants, and determining relevance  
     	callPath.push(func);
     	
     	int eventCount = 0;
     	int depth = 0;
     	int exportDepth = 0;
        
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
	    	
	    	if (processed.contains(funcName) || ignored.contains(funcName))
        		continue;
	    		    	
	    	if(quickScan && (depth > maxCallDepth || exportDepth > maxExportCallDepth || eventCount == maxEvents))
    			continue;
	    	
        	if(etwRegisterFuncs.contains(funcName)) {
        		printf("   --> %s()\n", funcName);  // :TODO: handle local calls to EtwRegister...
        	}
        	else if(funcName.startsWith("_TlgWrite")) {
        		logTODO("implement TraceLogging support");
        		String containingFunction = callingFunction.getName();
        		if( containingFunction.startsWith("FUN_"))
        			containingFunction = "";
        		csv.printf("%s,???,,,%s,,???,,,,,,,%s,%d,%d,%s\n", func.getName(), funcName, containingFunction, depth, exportDepth, callPath.toString().replace(',','-').replace(' ','>') );
        	}
        	else if(classicEventFuncs.contains(funcName)) {
        		logTODO("implement classic provider support - " + funcName);
        	}
        	else if(classicMessageFuncs.contains(funcName)) {
        		logTODO("improve classic provider (especially WPP) support");
        		
        		List<String> wppWriteParametersList = getWppWriteParameters(funcName, callingFunction, callPath);
        		for(String wppWriteParameters : wppWriteParametersList) {
            		printf("   --> %s(%s)\n", funcName, wppWriteParameters);
        			csv.printf("%s,%s,%s,%d,%d,%s\n", func.getName(), wppWriteParameters, callingFunction.getName(), depth, exportDepth, callPath.toString().replace(',','-').replace(' ','>') );
        			eventCount++;
        		}
        	}
        	else if(etwWriteFuncs.contains(funcName)) {
    			ClangTokenGroup cCode = decomplib.decompileFunction(callingFunction, decomplib.getOptions().getDefaultTimeout(), monitor).getCCodeMarkup();
    	        if (cCode == null)
    	        	throw new Exception("[CALL EtwWrite] Decompile Error: " + decomplib.getLastMessage());
    	        List<StringBuffer> etwWriteParametersList = new LinkedList<StringBuffer>();
        		try {
                	getEtwWriteParameters(funcName, cCode, etwWriteParametersList, callPath, 0);
                	String lastParameters = null; 
                	for(StringBuffer etwWriteParameters : etwWriteParametersList) {
                		if(etwWriteParameters.toString().equals(lastParameters))
                			continue; // remove duplicates
                		lastParameters = etwWriteParameters.toString();
                		
                		printf("   --> %s(%s)\n", funcName, etwWriteParameters);
                		if(lastParameters.endsWith(","))
        	    			throw new Exception("recovered bad parameters - @ 0x" + thisFunction.getEntryPoint().toString());

                		csv.printf("%s,%s,%s,%d,%d,%s\n", func.getName(), etwWriteParameters, callingFunction.getName(), depth, exportDepth, callPath.toString().replace(',','-').replace(' ','>') );
	                	eventCount++;
                	}
                } catch(NotYetImplementedException e) {
                	logTODO("getEtwWriteParameters() " + e.getMessage());
                }
        	}
        	else {
        		if(exports.contains(funcName))
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
                	callPath.add(thisFunction);
                	queue.add(new QueuedFunction(calledFunction, thisFunction, depth+1, exportDepth, callPath));
        		}
        	}
    	}
	    if(quickScan && (depth > maxCallDepth || exportDepth > maxExportCallDepth || eventCount == maxEvents))
    		printf("   --> quickscan limit reached. callDepth=%d exportCallDepth=%d eventCount=%d\n", depth, exportDepth, eventCount);
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
	        			// non fatal
	        			logTODO("ETW write REGHANDLE resolves to local variable in " + callPath.peek()); // :TODO:
	        		}
	        		catch (NotYetImplementedException e) {
	        			// non fatal
	        			logTODO("REGHANDLE " + e.getMessage());
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
		    		// NTSTATUS EtwWriteString(REGHANDLE RegHandle,UCHAR Level, ULONGLONG Keyword, LPCGUID ActivityId, PCWSTR String)
					etwWriteParameters.append(providerGuid + ",");
			    	etwWriteParameters.append(providerSymbol + ",");
			    	etwWriteParameters.append(reghandleSymbol + ",");
			    	etwWriteParameters.append(etwWriteCall + ",");
		    		List<Long> levels = resolveFunctionParameterToConstant(pcodeOp, 2, callPath);
		    		List<Long> keywords = resolveFunctionParameterToConstant(pcodeOp, 2, callPath);
		    		List<Long> strings = resolveFunctionParameterToConstant(pcodeOp, 4, callPath);
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
	        		List<Long> pEvents = null;
	        		try
	        		{
	        			debugPrintf("resolveFunctionParameterToConstant(2)\n");
	        			pEvents = resolveFunctionParameterToConstant(pcodeOp, 2, callPath);
	        		}
	        		catch (NotFoundException e)
	        		{
	        			throw new NotYetImplementedException("ETW write EVENT_DESCRIPTOR resolves to local variable in " + callPath.peek()); // :TODO:
	        		}
	        		catch (NotYetImplementedException e)
	        		{
	        			throw new NotYetImplementedException("EVENT_DESCRIPTOR " + e.getMessage());
	        		}
	        		if(pEvents.size() == 0)
	        			throw new NotFoundException("ETW write with no EVENT_DESCRIPTOR");
	        		
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
		    			createData(event, eventDescriptorType);
		    			appendStructure(event, etwWriteParameters, true);
		    			etwWriteParametersList.add(etwWriteParameters);

		    			if(etwWriteParameters.toString().endsWith(",")) {
	        				throw new NotFoundException("EVENT_DESCRIPTOR parsing failed @ " + pEvent);
	        			}
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
    
    
    private List<String> getWppWriteParameters(String wppWriteCall, Function callingFunction, Stack<Function> callPath) throws Exception {
    	
		HighFunction hf = decomplib.decompileFunction(callingFunction, decomplib.getOptions().getDefaultTimeout(), monitor).getHighFunction();
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
    
    public List<Long> resolveFunctionParameterToConstant(PcodeOp call, int paramIndex, Stack<Function> callPath) throws Exception {
//    	debugPrintf("resolveFunctionParameterToConstant(%d)\n", paramIndex);
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
    
    private List<Long> resolveVarnodeToConstant(Varnode node, Stack<Function> callPath, int astDepth) throws Exception {
    	if (node.isConstant())
			return new LinkedList<Long>(Arrays.asList(node.getOffset()));
    	
    	if (node.isAddress())
    		return new LinkedList<Long>(Arrays.asList(node.getAddress().getOffset()));
		   	
		// "node.isParameter()"
    	// note - isParameter check must occur before isRegister check
    	HighVariable hvar = node.getHigh();
		if (hvar instanceof HighParam)
			return resolveToConstant(((HighParam)hvar).getSlot() + 1, callPath);

		if(hvar instanceof HighGlobal)
			debugPrintf(":TODO: found a global... already handled?");
		
    	if(node.isRegister() && node.getDef() == null)
    		throw new NotFoundException("not a constant - resolves to a register");
		
		// else, trace varnode backwards to constant
    	return resolvePcodeOpToConstant(node.getDef(), callPath, astDepth);
    }
    
    private List<Long> resolveToConstant(int parameterIndex, Stack<Function> callPath) throws Exception {
    	List<Long> constants = new LinkedList<Long>();
    	
    	Stack<Function> parentCallPath = (Stack<Function>)callPath.clone();
    	Function func = parentCallPath.pop();
    	if (callPath.size() > 1) {
    		// forward trace - with full call path
    		ClangNode astNode = decomplib.decompileFunction(parentCallPath.peek(), decomplib.getOptions().getDefaultTimeout(), monitor).getCCodeMarkup();
	        if (astNode == null)
	        	throw new Exception("[resolveToConstant] Decompile Error: " + decomplib.getLastMessage());
	        constants.addAll(resolveToConstant(astNode, func, parameterIndex, parentCallPath, 0));
    	} else {
	    	// backwards trace - incomplete call path, follow all paths
	    	for(Function callingFunction : func.getCallingFunctions(monitor)) {	
		    	ClangNode astNode = decomplib.decompileFunction(callingFunction, decomplib.getOptions().getDefaultTimeout(), monitor).getCCodeMarkup();
		        if (astNode == null)
		        	throw new Exception("[resolveToConstant] Decompile Error: " + decomplib.getLastMessage());	
		        parentCallPath.push(callingFunction);
		        constants.addAll(resolveToConstant(astNode, func, parameterIndex, parentCallPath, 0));
		        parentCallPath.pop();	        
	    	}
    	}
    	
    	if (constants.size() == 0)
    		throw new NotFoundException("resolveToConstant(parameter)");
    	
    	return constants;    		
    }
    
    private List<Long> resolveToConstant(ClangNode astNode, Function func, int parameterIndex, Stack<Function> callPath, int nodeDepth) throws Exception {
    	List<Long> constants = new LinkedList<Long>();
    	
    	// find the call(s) to func - and back trace all possible parameter values
    	if(astNode instanceof ClangStatement) {
			ClangStatement stmt = (ClangStatement) astNode;
			PcodeOp pcodeOp = stmt.getPcodeOp();			
			if (pcodeOp != null &&
			pcodeOp.getOpcode() == PcodeOp.CALL && 
			getFunctionAt(pcodeOp.getInput(0).getAddress()) != null &&	
			getFunctionAt(pcodeOp.getInput(0).getAddress()).getName().equals(func.getName())) {
		    	if(parameterIndex >= pcodeOp.getNumInputs())
		    		throw new ArrayIndexOutOfBoundsException(func.getName() + "() parameterIndex=" + parameterIndex);
		    	constants.addAll(resolveVarnodeToConstant(pcodeOp.getInput(parameterIndex), callPath, 0));
			}
    	}

    	// also traverse all children to find call(s)
        for (int i = 0; i < astNode.numChildren(); i++)
        	constants.addAll(resolveToConstant(astNode.Child(i), func, parameterIndex, callPath, nodeDepth + 1));
        
        if(nodeDepth == 0 && constants.isEmpty())
        	throw new NotFoundException("resolveToConstant(parameter)");

        return constants;
    }
        
    private List<Long> resolvePcodeOpToConstant(PcodeOp node, Stack<Function> callPath, int astDepth) throws Exception {    	
    	if(node == null)
    		throw new NotFoundException("node == null");
    	
    	if(astDepth > 128)
    		throw new NotFoundException("Pcode AST depth > 128 in " + callPath.peek());
    	
    	debugPrintf("%s (depth=%d)\n", node.toString(), astDepth);
    	
    	int opcode = node.getOpcode();
		List<Long> input0;
		List<Long> input1;
		switch (opcode) {
			case PcodeOp.CAST:
			case PcodeOp.COPY:
			case PcodeOp.INT_ZEXT: // zero-extend
				return resolveVarnodeToConstant(node.getInput(0), callPath, astDepth+1);
				
			case PcodeOp.INT_2COMP: // twos complement
				input0 = resolveVarnodeToConstant(node.getInput(0), callPath, astDepth+1);
				return input0.stream().map(a->-a).collect(Collectors.toList());
			
			case PcodeOp.INT_NEGATE:
				input0 = resolveVarnodeToConstant(node.getInput(0), callPath, astDepth+1);
				return input0.stream().map(a->~a).collect(Collectors.toList());
			
			case PcodeOp.LOAD:
				return resolveVarnodeToConstant(node.getInput(1), callPath, astDepth+1); 
					
			case PcodeOp.INT_ADD:
			case PcodeOp.PTRSUB:  // pointer to structure and offset to subcomponent
				input0 = resolveVarnodeToConstant(node.getInput(0), callPath, astDepth+1);
				input1 = resolveVarnodeToConstant(node.getInput(1), callPath, astDepth+1);
				if (input0.size() == input1.size())
					return LongStream.range(0,input0.size()).map(a -> input0.get((int)a) + input1.get((int)a)).boxed().collect(Collectors.toList());
				
				if (input0.size() != input1.size()) {
					// second chance - can we resolve to a single pair of values?
					List<Long> input0_2 = input0.stream().distinct().collect(Collectors.toList());
					List<Long> input1_2 = input1.stream().distinct().collect(Collectors.toList());
					if(input0_2.size() == 1 && input0_2.size() == input1_2.size())
						return LongStream.range(0,input0_2.size()).map(a -> input0_2.get((int)a) + input1_2.get((int)a)).boxed().collect(Collectors.toList());
				}
				throw new InvalidInputException();				
			
			case PcodeOp.INT_MULT:
				input0 = resolveVarnodeToConstant(node.getInput(0), callPath, astDepth+1);
				input1 = resolveVarnodeToConstant(node.getInput(1), callPath, astDepth+1);
				if(input0.size() != input1.size())
					throw new InvalidInputException();			
				return LongStream.range(0,input0.size()).map(a -> input0.get((int)a) * input1.get((int)a)).boxed().collect(Collectors.toList());
				
			case PcodeOp.INT_NOTEQUAL:
			input0 = resolveVarnodeToConstant(node.getInput(0), callPath, astDepth+1);
			input1 = resolveVarnodeToConstant(node.getInput(1), callPath, astDepth+1);
			if(input0.size() != input1.size())
				throw new InvalidInputException();			
			return LongStream.range(0,input0.size()).map(a -> input0.get((int)a) != input1.get((int)a) ? 1 : 0).boxed().collect(Collectors.toList());
				
			case PcodeOp.PTRADD:  
				input0 = resolveVarnodeToConstant(node.getInput(0), callPath, astDepth+1);
				List<Long> index = resolveVarnodeToConstant(node.getInput(1), callPath, astDepth+1);
				List<Long> elementSize = resolveVarnodeToConstant(node.getInput(2), callPath, astDepth+1);
				
				if (input0.size() == index.size() && input0.size() == elementSize.size())
					return LongStream.range(0,input0.size()).map(a -> input0.get((int)a) + index.get((int)a) * elementSize.get((int)a)).boxed().collect(Collectors.toList());
				
				// second chance - can we resolve to distinct values?
				List<Long> input0_2 = input0.stream().distinct().collect(Collectors.toList());
				List<Long> index_2 = index.stream().distinct().collect(Collectors.toList());
				List<Long> elementSize_2 = elementSize.stream().distinct().collect(Collectors.toList());
				if (input0_2.size() == index_2.size() && input0_2.size() == elementSize_2.size())
					return LongStream.range(0,input0_2.size()).map(a -> input0_2.get((int)a) + index_2.get((int)a) * elementSize_2.get((int)a)).boxed().collect(Collectors.toList());

				throw new InvalidInputException();			
		
			case PcodeOp.INT_AND:
				input0 = resolveVarnodeToConstant(node.getInput(0), callPath, astDepth+1);
				input1 = resolveVarnodeToConstant(node.getInput(1), callPath, astDepth+1);
				if(input0.size() != input1.size())
					throw new InvalidInputException();			
				return LongStream.range(0,input0.size()).map(a -> input0.get((int)a) & input1.get((int)a)).boxed().collect(Collectors.toList());

			case PcodeOp.MULTIEQUAL:
				List<Long> output = new LinkedList<Long>();
				for(Varnode n : node.getInputs())
					output.addAll(resolveVarnodeToConstant(n, callPath, astDepth+1));
				return output;
			
			case PcodeOp.INDIRECT:
				throw new NotFoundException("aborting due to possible indirect effects in " + callPath.peek()); // :TODO:
			
			case PcodeOp.CALL:
				String target = getSymbolAt(node.getInput(0).getAddress()).getName();
				throw new NotYetImplementedException("PcodeOp CALL " + target + " in " + callPath.peek());
				
			default:
				throw new NotYetImplementedException("PcodeOp " + node.toString() + " in " + callPath.peek());
		}
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
		  DataTypeManager dtm = getDataTypeManagerByName("windows_vs12_64");
	      if(dtm == null)
	    	  throw new NotFoundException("DataTypeManager(windows_vs12_64) == null");
	    	  
		  eventDescriptorType = dtm.getDataType("/evntprov.h/EVENT_DESCRIPTOR");
	      if(eventDescriptorType == null)
	    	  throw new NotFoundException("eventDescriptorType == null");
	    	  
//	      dtm = getDataTypeManagerByName("ntoskrnl.exe");
//	      if(dtm == null)
//	    	  throw new NotFoundException("DataTypeManager(ntoskrnl.exe) == null");
	      
	      ulonglongType = dtm.getDataType("/winnt.h/ULONGLONG");
	      if(ulonglongType == null)
	    	  throw new NotFoundException("ulonglongType == null");
	        
	      ushortType = dtm.getDataType("/WinDef.h/USHORT");
	      if(ushortType == null)
	    	  throw new NotFoundException("ushortType == null");
	      
	      ucharType = dtm.getDataType("/winsmcrd.h/UCHAR");
	      if(ucharType == null)
	    	  throw new NotFoundException("ucharType == null");
	           
  	      dtm = getDataTypeManagerByName("BuiltInTypes");
  	      if(dtm == null)
  	    	  throw new NotFoundException("DataTypeManager(BuiltInTypes) == null");
	                      
	      guidType = dtm.getDataType("/GUID");
	      if(guidType == null)
	    	  throw new NotFoundException("guidType == null");
	}
   
    //------------------------------------------------------------------------
	// getDataTypeManagerByName
	//
	// Retrieves data type manager by name.
	//
	// Returns:
	//		Success: DataTypeManager
	//		Failure: null
	//------------------------------------------------------------------------
	private DataTypeManager getDataTypeManagerByName(String name) {
		DataTypeManagerService service = state.getTool().getService(DataTypeManagerService.class);

		// Loop through all managers in the data type manager service
		for (DataTypeManager manager : service.getDataTypeManagers()) {
			if (manager.getName().equals(name))
				return manager;
		}
		return null;
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
}