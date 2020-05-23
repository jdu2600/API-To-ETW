
/* ###
 * IP: GHIDRA
 * IP: jdu2600
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
// kernel-mode ETW functions are prefixed with Etw, and the user-mode equivalents with Event.
// Both APIs take the same parameters... so this script should work on both. :-)
//
// References -
//  * Ghidra's ShowCCallsScript.java
//  * Ghidra's ShowConstantUse.java
//  * https://www.riverloopsecurity.com/blog/2019/05/pcode/
//  
// Inspiration -
//  * https://github.com/hunters-forge/API-To-Event
//  * https://twitter.com/mattifestation/status/1140655593318993920 - Microsoft-Windows-Kernel-Audit-API-Calls events
//  * https://twitter.com/pathtofile 
//  * [How do I detect technique X in Windows?](https://drive.google.com/file/d/19AhMG0ZCOt0IVsPZgn4JalkdcUOGq4DK/view), DerbyCon 2019
//  * https://blog.xpnsec.com/analysing-rpc-with-ghidra-neo4j/
//@category Functions.ETW

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.LongStream;

import org.apache.commons.lang3.tuple.Triple;

import generic.stl.Pair;

import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.*;

//:TODO: 
//csv to json 
//handle simple cases - local parameter
//handle complex cases - wrapper functions
//other EtwWrite functions

public class DumpEtwWrites extends GhidraScript {

	
	private Boolean debugPrint = false;
	private Boolean quickScan = false;
	
	private DataType eventDescriptorType = null;
	private DataType ucharType = null;
	private DataType ushortType = null;
	private DataType ulonglongType = null;
	private DataType guidType = null;
	private DecompInterface decomplib = null;
	
	private String functionsFile = "functions.txt";
	private String exportsFile = "exports.txt";
	
	private Set<String> exports = null;
	private Set<String> functions = null;
	private PrintWriter csv = null;
	private Dictionary<Long,Pair<String,String>> providerGuidMap = new Hashtable<Long,Pair<String,String>>(); // Address, (Guid, GuidSymbol)
	
	private List<String> notYetImplemented = new LinkedList<String>();
	
	
    @Override
    public void run() throws Exception {
    	printf("\n\n--==[ DumpEtwWrites ]==--\n");
	    printf(" * %s\n", currentProgram.getName());
    	
    	// we want the names of all exports - as we use these as a measure of relevance 
    	// for a given ETW write
    	// :TODO: how do I list the exports with ghidra??  something something symbols???
    	// instead read in a list of exports for now e.g. generated using python's pefile
	    exports = new HashSet<String>(Files.readAllLines(Paths.get(exportsFile)));
	    printf(" * using %d exports\n", exports.size());

	    
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
        
    	// prepare the output file
	    String csvFilename = currentProgram.getName() + ".csv";
	    printf(" * output will be written to %s\n", csvFilename);
	    new File(csvFilename).delete();
    	csv = new PrintWriter(new File(csvFilename));
    	csv.println("Function,ProviderGuid,ProviderSymbol,ReghandleSymbol,EventDescriptorSymbol,Id,Version,Channel,Level,Opcode,Task,Keyword,CallDepth");
    	
    	
    	setUpDataTypes();
    	setUpDecompiler(currentProgram);
    	if (!decomplib.openProgram(currentProgram)) {
    		println("Decompiler Setup Error: " + decomplib.getLastMessage());
    		return;
    	}
    	
    	try {
        	//
        	// first we cache the REGHANDLE address and the GUID of all register ETW Providers so that we can later 
        	// match ETW events to the Provider GUIDs
        	//
        	// providers are registered via [Etw|Event]Register(LPCGUID ProviderId, .., .., PREGHANDLE RegHandle)
        	//
        	// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-etwregister
        	// https://docs.microsoft.com/en-us/windows/win32/api/evntprov/nf-evntprov-eventregister
        	       	
        	String etwRegisterFuncs[] = { "EtwRegister", "EventRegister" };
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

        	
	        //
        	// for each function, output the parameters of all ETW writes ( GUID, Event Id etc)
        	for(String functionName : functions)	{
        		List<Function> functionList = getGlobalFunctions(functionName);
        		if(functionList.size() == 0) {
        			printf("   --> found 0 instances of %s\n", functionName);
        			continue;
        		}
        		if(functionList.size() > 1)
        			throw new Exception("Script aborted: Found " + functionList.size() + " instances of " + functionName);
        		        		
	            // decompile function & output ETW writes
	            analyseFunction(functionList.get(0), 0, 0);
		    }
        	
        	// :TODO: [Etw|Event]WriteString, EtwEriteEndScenario, EtwWriteStartScenario, SeEtwWriteKMCveEvent, EtwEventWrite, EtwEventWriteFull, EtwWriteUMSecurityEvent
        	// https://geoffchappell.com/studies/windows/win32/ntdll/api/etw/
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

	
    //
    // EtwRegister
    //
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
        if (refFunc == null)
        	throw new NotFoundException("getFunctionContaining == null; refAddr=" + refAddr); // resolving this should be as simple as manually defining the function
//        	Address functionBase = null; // :TODO: find the function base programmatically... it's easy to do visually...
//        	refFunc = createFunction(functionBase, null);
        
		ClangTokenGroup cCode = decomplib.decompileFunction(refFunc, decomplib.getOptions().getDefaultTimeout(), monitor).getCCodeMarkup();
        if (cCode == null)
        	throw new Exception("[CALL EtwRegister] Decompile Error: " + decomplib.getLastMessage());
        
        try {
        	cacheProviderReghandle(refFunc, cCode, refAddr);
        } catch(NotYetImplementedException e) {
        	if (!notYetImplemented.contains(e.getMessage()))
        		notYetImplemented.add(e.getMessage());
        }
    }
	
	private void cacheProviderReghandle(Function f, ClangNode node, Address refAddr) throws Exception {
        if(node == null || node.getMinAddress() == null)
        	return;  // leaf node
        
		if (node.getMaxAddress() == null)
        	throw new InvalidInputException("ClangNode.getMaxAddress() is null");
        
        // have we found the CALL yet?
        if (refAddr.getPhysicalAddress().equals(node.getMaxAddress()) && node instanceof ClangStatement) {
        	ClangStatement stmt = (ClangStatement) node;
        	PcodeOp pcodeOp = stmt.getPcodeOp();
        	if (pcodeOp.getOpcode() == PcodeOp.CALL) {        	
	        	if(pcodeOp.getNumInputs() < 5) {
	        		printf("[WARNING] Incomplete Decompilation @ 0x%x - %s\n", node.getMaxAddress().getOffset(),  stmt.toString());
	        		return;
	        	}
	        	
  	        	debugPrintf("%s :: %s\n", refAddr.toString(), stmt);
	        	
	        	List<Long> pGuids = resolveFunctionParameterToConstant(pcodeOp, 1);
	        	if(pGuids.size() != 1)
	        		throw new NotYetImplementedException("Multiple GUIDs");
	        	long pGuid = pGuids.get(0);
	        	String guid = "";
	        	String guidSymbol = "";
	        	if(pGuid != 0) {
	        		Address guidAddr = toAddr(pGuid);
	        		clearListing(guidAddr, guidAddr.add(guidType.getLength()-1));
	        		createData(guidAddr, guidType);
	        		guid = getDataAt(guidAddr).toString().substring(5);
	        		guidSymbol = SymbolAt(pGuid); 
	        	}
	        	
	        	List<Long> reghandles = resolveFunctionParameterToConstant(pcodeOp, 4);
	        	if(reghandles.size() != 1)
	        		throw new NotYetImplementedException("Multiple REGHANDLE");
	        	long reghandle = reghandles.get(0);
	        	if(reghandle != 0 && pGuid != 0) {
	        		printf("   --> cached %s(%s, %s)\n", getFunctionAt(pcodeOp.getInput(0).getAddress()).getName(), guid, guidSymbol);
	        		providerGuidMap.put(reghandle, new Pair<String,String>(guid, guidSymbol));
	        	}
	        	else
	        	{
	        		printf("[WARNING] 0x%x [Incomplete Recovery] %s\n", node.getMaxAddress().getOffset(),  stmt.toString());
		        	printf("[WARNING] reghandle=0x%x\n", reghandle);
	        		printf("[WARNING] guid=%s\n", guid);
	        		printf("[WARNING] --------------------\n");
	        	}
				return; // CALL found - stop looking
        	}
        }

        // otherwise traverse children to find CALL
        for (int j = 0; j < node.numChildren(); j++) {
        	cacheProviderReghandle(f, node.Child(j), refAddr);
        }
    }
	
	//
	// function
	//
	List<String> etwWriteFuncs = Arrays.asList("EtwWrite", "EventWrite", "EtwWriteEx", "EventWriteEx", "EtwWriteTransfer", "EventWriteTransfer");
	public void analyseFunction(Function func, int exportDepth, int callDepth) throws Exception {
		printf(" * analysing %s\n", func.getName());
		
     	List<String> processed = new LinkedList<String>();
        Queue<Triple<Function, Function, Integer>> queue = new LinkedList<Triple<Function,Function,Integer>>();
     	// Queue<Pair<Function, Integer>> queue = new LinkedList<Pair<Function,Integer>>();        
        
        // find all reachable ETW writes
        for(Function calledFunction : func.getCalledFunctions(monitor))
        	queue.add(Triple.of(func, calledFunction, callDepth+1));
	    while (queue.size() != 0) {
	    	if (monitor.isCancelled())
                break;
	    	Triple<Function, Function, Integer> next = queue.remove();
	    	
	    	Function callingFunction = next.getLeft();
	    	Function thisFunction = next.getMiddle();
	    	String funcName = thisFunction.getName();
	    	Integer depth = next.getRight();
//   	    	debugPrintf("previous=%s current=%s depth=%d processed=%d queue=%d\n", callingFunction.getName(), funcName, depth, processed.size(), queue.size());    	    	

	    	if (processed.contains(funcName))
        		continue;
	    	    	
        	// :TODO: if etwRegister...      	
        	if(etwWriteFuncs.contains(funcName)) {
    			ClangTokenGroup cCode = decomplib.decompileFunction(callingFunction, decomplib.getOptions().getDefaultTimeout(), monitor).getCCodeMarkup();
    	        if (cCode == null)
    	        	throw new Exception("[CALL EtwWrite] Decompile Error: " + decomplib.getLastMessage());
    	        List<StringBuffer> etwWriteParametersList = new LinkedList<StringBuffer>();
        		try {
                	getEtwWriteParameters(thisFunction.getName(), cCode, etwWriteParametersList, 0);
                	for(StringBuffer etwWriteParameters : etwWriteParametersList) {
                		printf("   --> %s(%s)\n", thisFunction.getName(), etwWriteParameters);
                		if(etwWriteParameters.toString().endsWith(","))
        	    			throw new Exception("recovered bad parameters @ 0x" + thisFunction.getEntryPoint().toString());
	                	csv.printf("%s,%s,%d\n", func.getName(), etwWriteParameters, depth);
                	}
                } catch(NotYetImplementedException e) {
                	if(!notYetImplemented.contains(e.getMessage()))
                		notYetImplemented.add(e.getMessage());
                }
        	}
        	else {
            	if(exports.contains(funcName)) {
            		if(quickScan)
            			continue;
            		exportDepth = exportDepth + 1;
            	}
        		
        		processed.add(funcName);
        		for(Function calledFunction : thisFunction.getCalledFunctions(monitor)) {
                	if(calledFunction == null)
                		throw new Exception("Argh!");
                	if(calledFunction.getName() == null)
                		createFunction(calledFunction.getEntryPoint(), null);
                	if(calledFunction.getName() == null)
                		throw new Exception("FUN_" + calledFunction.getEntryPoint().toString() + " is not defined");
            		queue.add(Triple.of(thisFunction, calledFunction, callDepth+1));
        		}
        	}
    	}
        csv.flush();
    }    
	  
    private boolean getEtwWriteParameters(String etwWriteCall, ClangNode node, List<StringBuffer> etwWriteParametersList, int depth) throws Exception {
    	if(node == null || node.getMinAddress() == null)
        	return false;  // leaf node
		if (node.getMaxAddress() == null)
        	throw new InvalidInputException("ClangNode.getMaxAddress() is null");
        
        // have we found the right CALL yet?
		if(node instanceof ClangStatement) {
			ClangStatement stmt = (ClangStatement) node;
			PcodeOp pcodeOp = stmt.getPcodeOp();
			if (pcodeOp != null &&
			pcodeOp.getOpcode() == PcodeOp.CALL && 
			getFunctionAt(pcodeOp.getInput(0).getAddress()) != null &&	
			getFunctionAt(pcodeOp.getInput(0).getAddress()).getName().equals(etwWriteCall)) {
		    	if(pcodeOp.getNumInputs() < 3) {
		    		printf("[WARNING] Incomplete Decompilation @ 0x%x - %s\n", node.getMaxAddress().getOffset(), stmt.toString());
		    	}
		    	
		    	debugPrintf("%s\n", stmt);
		
		    	long reghandle = 0;
		    	if(pcodeOp.getNumInputs() > 1) {
	        		List<Long> reghandles = resolveFunctionParameterToConstant(pcodeOp, 1);
	        		if(reghandles.size() != 1)
	        			throw new NotYetImplementedException("EtwWrite with multiple REGHANDLE");
	        		reghandle = reghandles.get(0);
		    	}
		    	
		    	String providerGuid = "???";
		    	String providerSymbol = "";
		    	String reghandleSymbol = SymbolAt(reghandle);
		    	Pair<String,String> providerRegistration = providerGuidMap.get(reghandle);
		    	if ( providerRegistration != null) {
		    		providerGuid = providerRegistration.first;
		    		providerSymbol = providerRegistration.second;
		    	}
		    	
		    		
		    	Address event = null;
		    	if(pcodeOp.getNumInputs() > 2) {
	        		List<Long> pEvents = resolveFunctionParameterToConstant(pcodeOp, 2);
	        		
	        		for(long pEvent : pEvents) {
	        			if(pEvent == 0)
	        				continue;  // :TODO: a quirk of ghidra's decompilation?
	        			StringBuffer etwWriteParameters = new StringBuffer();
        				etwWriteParameters.append(providerGuid + ",");
        		    	etwWriteParameters.append(providerSymbol + ",");
        		    	etwWriteParameters.append(reghandleSymbol + ",");
	        			try {      				
			        		String eventDescriptorSymbol = SymbolAt(pEvent);
			        		etwWriteParameters.append(eventDescriptorSymbol + ",");
			        		
			        		event = toAddr(pEvent);
			    			clearListing(event, event.add(eventDescriptorType.getLength()-1));
			    			createData(event, eventDescriptorType);
			    			appendStructure(event, etwWriteParameters, true);
			    			etwWriteParametersList.add(etwWriteParameters);
			    		} catch(Exception e) {
	    		    		printf("[WARNING] 0x%x [Incomplete Recovery] %s\n", node.getMaxAddress().getOffset(),  stmt.toString());
	    		    		printf("[WARNING] reghandle=0x%x\n", reghandle);
	    		    		printf("[WARNING] pEvent=0x%x\n", pEvent);
	    					printf("[WARNING] etwWriteParameters=%s\n", etwWriteParameters.toString());
	    					printf("[WARNING] pEvents=%s\n", pEvents.toString());	    					
	    					printf("[WARNING] --------------------\n");
	    		    		
	    		    		throw e;
			    		}
	        			if(etwWriteParameters.toString().endsWith(",")) {
	    		    		printf("[WARNING] 0x%x [Incomplete Recovery] %s\n", node.getMaxAddress().getOffset(),  stmt.toString());
	    		    		printf("[WARNING] reghandle=0x%x\n", reghandle);
	    					printf("[WARNING] pEvent=0x%x\n", pEvent);
	    					printf("[WARNING] etwWriteParameters=%s\n", etwWriteParameters.toString());
	    					printf("[WARNING] pEvents=%s\n", pEvents.toString());
	    		    		printf("[WARNING] --------------------\n");
	        				throw new Exception("EVENT_DESCRIPTOR parsing failed? @" + pEvent);
	        			}
	        		}	        		
	        	}		    		
			    	    	
		    	return true; // CALL found - stop looking
			}
		}

        // search children until CALL found
        boolean found = false;
        for (int j = 0; j < node.numChildren(); j++)
        	found |= getEtwWriteParameters(etwWriteCall, node.Child(j), etwWriteParametersList, depth + 1);
        
        if(!found && depth == 0)
        	throw new Exception("didn't find " + etwWriteCall);
        
        return found;
    }
    
    public List<Long> resolveFunctionParameterToConstant(PcodeOp call, int paramIndex) throws Exception {
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
		return resolveToConstant(param);
	}
    
    private List<Long> resolveToConstant(Varnode node) throws Exception {
    	if(node.isRegister() && node.getDef() == null)
    		throw new NotYetImplementedException("Varnode.isRegister()");
    	
    	if (node.isConstant())
			return new LinkedList<Long>(Arrays.asList(node.getOffset()));
    	
    	if (node.isAddress())
    		return new LinkedList<Long>(Arrays.asList(node.getAddress().getOffset()));
		   	
		HighVariable hvar = node.getHigh();
		if (hvar instanceof HighParam)
			throw new NotYetImplementedException("param_" + ((HighParam)hvar).getSlot());			// :TODO:
			
		// trace backwards to constant
    	return resolveToConstant(node.getDef());
    		 
	}
        
    private List<Long> resolveToConstant(PcodeOp node) throws Exception {    	
    	if(node == null)
    		throw new NotFoundException("node == null");
    	
    	int opcode = node.getOpcode();
		List<Long> input0;
		List<Long> input1;
		switch (opcode) {
			case PcodeOp.CAST:
			case PcodeOp.COPY:
			case PcodeOp.INT_ZEXT: // zero-extend
				return resolveToConstant(node.getInput(0));
				
			case PcodeOp.INT_2COMP: // twos complement
				input0 = resolveToConstant(node.getInput(0));
				return input0.stream().map(a->-a).collect(Collectors.toList());
			
			case PcodeOp.INT_NEGATE:
				input0 = resolveToConstant(node.getInput(0));
				return input0.stream().map(a->~a).collect(Collectors.toList());
			
			case PcodeOp.LOAD:
				return resolveToConstant(node.getInput(1)); 
					
			case PcodeOp.INT_ADD:
			case PcodeOp.PTRSUB:  // pointer to structure and offset to subcomponent
				input0 = resolveToConstant(node.getInput(0));
				input1 = resolveToConstant(node.getInput(1));
				if(input0.size() != input1.size())
					throw new InvalidInputException();			
				return LongStream.range(0,input0.size()).map(a -> input0.get((int)a) + input1.get((int)a)).boxed().collect(Collectors.toList());
			
			case PcodeOp.INT_MULT:
				input0 = resolveToConstant(node.getInput(0));
				input1 = resolveToConstant(node.getInput(1));
				if(input0.size() != input1.size())
					throw new InvalidInputException();			
				return LongStream.range(0,input0.size()).map(a -> input0.get((int)a) * input1.get((int)a)).boxed().collect(Collectors.toList());
				
			case PcodeOp.INT_NOTEQUAL:
			input0 = resolveToConstant(node.getInput(0));
			input1 = resolveToConstant(node.getInput(1));
			if(input0.size() != input1.size())
				throw new InvalidInputException();			
			return LongStream.range(0,input0.size()).map(a -> input0.get((int)a) != input1.get((int)a) ? 1 : 0).boxed().collect(Collectors.toList());
				
			case PcodeOp.PTRADD:  
				input0 = resolveToConstant(node.getInput(0));
				List<Long> index = resolveToConstant(node.getInput(1));
				List<Long> elementSize = resolveToConstant(node.getInput(2));
				if(input0.size() != index.size() || input0.size() != elementSize.size())
					throw new InvalidInputException();			
				return LongStream.range(0,input0.size()).map(a -> input0.get((int)a) + index.get((int)a) * elementSize.get((int)a)).boxed().collect(Collectors.toList());
			
			case PcodeOp.INT_AND:
				input0 = resolveToConstant(node.getInput(0));
				input1 = resolveToConstant(node.getInput(1));
				if(input0.size() != input1.size())
					throw new InvalidInputException();			
				return LongStream.range(0,input0.size()).map(a -> input0.get((int)a) & input1.get((int)a)).boxed().collect(Collectors.toList());

			case PcodeOp.MULTIEQUAL:
				List<Long> output = new LinkedList<Long>();
				for(Varnode n : node.getInputs())
					output.addAll(resolveToConstant(n));
				return output;
				
			default:
				throw new NotYetImplementedException("PcodeOp " + node.toString());
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
    
    private String SymbolAt(long address)
    {
    	String symbol = this.getSymbolAt(toAddr(address)).toString();
    	if (symbol.startsWith("DAT_"))
    		symbol = "";
    	return symbol;
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
	    	  
	      dtm = getDataTypeManagerByName("ntoskrnl.exe");
	      if(dtm == null)
	    	  throw new NotFoundException("DataTypeManager(ntoskrnl.exe) == null");
	      
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
}
