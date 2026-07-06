/*******************************************************************************
 * Copyright (c) 2017 Politecnico di Torino and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License, Version 2.0
 * which accompanies this distribution, and is available at
 * http://www.apache.org/licenses/LICENSE-2.0
 *******************************************************************************/
package it.polito.mito.solver;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.microsoft.z3.BoolExpr;
import com.microsoft.z3.Constructor;
import com.microsoft.z3.Context;
import com.microsoft.z3.DatatypeExpr;
import com.microsoft.z3.DatatypeSort;
import com.microsoft.z3.EnumSort;
import com.microsoft.z3.Expr;
import com.microsoft.z3.FuncDecl;
import com.microsoft.z3.IntExpr;
import com.microsoft.z3.Optimize;
import com.microsoft.z3.Sort;

import it.polito.mito.allocation.AllocationNode;
import it.polito.mito.extra.WildcardManager;
import it.polito.mito.functions.PacketFilter;
import it.polito.mito.graph.Event;
import it.polito.mito.graph.FilteringPolicy;
import it.polito.mito.graph.SecurityRequirement;
import it.polito.mito.jaxb.FunctionalTypes;
import it.polito.mito.utils.PortInterval;
import it.polito.mito.utils.Tuple;

/**
 * Basic fields and other things required for model checking.
 *
 */
public class NetContext {
	public Context ctx;
	public WildcardManager wildcardManager;
	public FuncDecl nodeHasAddr,addrToNode,send,recv;
	public FuncDecl deny, operable, mitigated, omega;
	private HashMap<String, AllocationNode> allocationNodes;
	
    public List<BoolExpr> constraints;
    public List<Tuple<BoolExpr, String>> softConstrAutoConf;
    public List<Tuple<BoolExpr, String>> softConstrAutoPlace;
    public List<Tuple<BoolExpr, String>> softConstrWildcard;
    public List<Tuple<BoolExpr, String>> softConstrProtoWildcard;
    public List<Tuple<BoolExpr, String>> softConstrPorts;

    public HashMap<String,DatatypeExpr> nodeMap; //list of nodes, callable by node name
    public HashMap<String,DatatypeExpr> addressMap; // list of addresses, callable by address name
    public HashMap<String,DatatypeExpr> portMap; // list of port range, callable by string
    public HashMap<String,DatatypeExpr> filteringPolicyMap;
    public HashMap<String,DatatypeExpr> timeMap;
    public HashMap<String,DatatypeExpr> fpMap;
    public HashMap<String,DatatypeExpr> eventMap;
    
    public HashMap<String,FuncDecl> functionsMap;
    public HashMap<String,FuncDecl> portFunctionsMap;
    public HashMap<String,FuncDecl> ipFunctionsMap;    
    
    public EnumSort nodeType;
	public DatatypeSort addressType;
	public DatatypeSort portType;
    public DatatypeSort packetType;
    public EnumSort timeType;
    public EnumSort fpType;
    public EnumSort eventType;
    
    public int eventNumber;
    

    /*   Constants definition */
	public final int MAX_PORT = 65535;
    public final int HTTP_REQUEST    = 1;
    public final int HTTP_RESPONSE   = 2;
    public final int POP3_REQUEST    = 3;
    public final int POP3_RESPONSE   = 4;

    // weights
    public final int WPROTOWILDCARD   = 1000;
    public final int WIPWILDCARD   = -10;
    public final int WAUTOCONF   = 1;
    public final int WAUTOPLACEMENT   = 100000000;
    public final int WPORTS   = 1000;

 
    /**
     * Context for all of the rest that follows. Every network needs one of these
     * @param ctx
     * @param args
     */
    public NetContext(Context ctx, HashMap<String, AllocationNode> allocationNodes, Object[]... args){
          nodeMap = new HashMap<String,DatatypeExpr>(); //list of nodes, callable by node name
          addressMap = new HashMap<String,DatatypeExpr>(); // list of addresses, callable by address name
          portMap = new HashMap<String,DatatypeExpr>();
          filteringPolicyMap = new HashMap<String,DatatypeExpr>();
          timeMap = new HashMap<String,DatatypeExpr>();
          fpMap = new HashMap<String,DatatypeExpr>();
          eventMap = new HashMap<String,DatatypeExpr>();
          functionsMap= new HashMap<String,FuncDecl>() ;
          ipFunctionsMap = new HashMap<String,FuncDecl>();
          portFunctionsMap = new HashMap<String,FuncDecl>();
          constraints = new ArrayList<BoolExpr>();
          softConstrAutoConf = new ArrayList<>();
          softConstrAutoPlace = new ArrayList<>();
          softConstrWildcard = new ArrayList<>(); 
          softConstrProtoWildcard = new ArrayList<>(); 
          softConstrPorts = new ArrayList<>(); 

    	  this.ctx = ctx;
          this.allocationNodes = allocationNodes;
       
          mkTypes((String[])args[0],(String[])args[1], (String[])args[2], (String[])args[3]);
    }
    
    
    
    /*
     * Main Methods of NetContext class
     */

    
    /**
     * This methods adds hard and soft constraints inside the z3 solver
     * @param solver it is the z3 solver
     */
    protected void addConstraints(Optimize solver) {
        BoolExpr[] constr = new BoolExpr[constraints.size()];
        solver.Add(constraints.toArray(constr));
        softConstrAutoConf.forEach(t->solver.AssertSoft(t._1, WAUTOCONF, t._2));
        softConstrAutoPlace.forEach(t->solver.AssertSoft(t._1, WAUTOPLACEMENT, t._2));
    }
    
    /**
     * This method is in charge of creating the z3 types for ports, nodes, addresses and packets 
     * @param nodes it is the array of node names
     * @param addresses it is the array of IP addresses
     * @param srcp_ranges it is the array of source ports -> it can be a single port or a range of ports divided by a "-"
     * @param dstp_ranges it is the array of destination ports
     */
    public void mkTypes (String[] nodes, String[] addresses, String[] srcp_ranges, String[] dstp_ranges){
    	  
        //----------- Nodes in this network
        nodeType = ctx.mkEnumSort("Node", nodes);
        for(int i=0;i<nodeType.getConsts().length;i++){
            DatatypeExpr fd  = (DatatypeExpr)nodeType.getConst(i);   
            nodeMap.put(fd.toString().replace("|", ""),fd);
            AllocationNode n = allocationNodes.get(nodes[i]);
            n.setZ3Name(fd);
        }

      //----------- Deny predicate
      // deny = ctx.mkFuncDecl("deny", new Sort[]{ nodeType, ctx.mkIntSort()},ctx.mkBoolSort());
    }
    
    public void mkTypes2(HashMap<Integer, SecurityRequirement> securityRequirements, HashMap<Integer, Event> events, List<String> times) {
    	
    	//----------- Filtering Policy type
    	List<String> fpNamesList = new ArrayList<>();
    	Map<String, FilteringPolicy> fpMapToSave = new HashMap<>();
    	for(AllocationNode n : allocationNodes.values()) {
    		if(n.getTypeNF() == FunctionalTypes.FIREWALL) {
    			PacketFilter pf = (PacketFilter) n.getPlacedNF();
    			for(int i = 0; i < 2; i++) {
    				FilteringPolicy fp = pf.getFpList().get(i);
    				if(fp.isExisting()) {
    					String fpName = new String("FiltPol_" + n.getIpAddress()+"_index" + i);
    					fp.setFpName(fpName);
    					fpNamesList.add(fpName);
    					fpMapToSave.put(fpName, fp);
    				}
    			}
    		}
    	}
    	String bot = new String("bot");
    	fpNamesList.add(bot);
    	String[] fpNamesArray = fpNamesList.toArray(new String[0]);
    	fpType = ctx.mkEnumSort("FiltPol", fpNamesArray);
        for(int i=0;i<fpType.getConsts().length;i++){
            DatatypeExpr fd  = (DatatypeExpr) fpType.getConst(i);   
            fpMap.put(fd.toString().replace("|", ""),fd);
            if(!fd.toString().equals(bot)) {
                FilteringPolicy fpToSave = fpMapToSave.get(fd.toString());
                fpToSave.setZ3Name(fd);
            }
        }
        
        //---------- Event type
        List<String> eventNamesList = new ArrayList<>();
    	for(Event e : events.values()) {
    		eventNamesList.add(e.getEventName());
    	}
    	String[] eventArray = eventNamesList.toArray(new String[0]);
        eventType = ctx.mkEnumSort("Event", eventArray);
        for(int i=0;i<eventType.getConsts().length;i++){
            DatatypeExpr fd  = (DatatypeExpr)eventType.getConst(i);   
            eventMap.put(fd.toString().replace("|", ""),fd);
            for(Event e : events.values()) {
            	if(e.getEventName().equals(fd.toString().replace("|", ""))) e.setZ3Name(fd);
        	}
            
        }
        eventNumber = eventType.getConsts().length;
        
    	//----------- Time type
    	String[] timeArray = times.toArray(new String[0]);
        timeType = ctx.mkEnumSort("Time", timeArray);
        for(int i=0;i<timeType.getConsts().length;i++){
            DatatypeExpr fd  = (DatatypeExpr)timeType.getConst(i);   
            timeMap.put(fd.toString().replace("|", ""),fd);
        }
        //timeMap.forEach((k, v) -> System.out.println(k + " -> " + v));
        
        //----------- Predicates
        deny = ctx.mkFuncDecl("deny", new Sort[]{ nodeType, fpType, ctx.mkIntSort()},ctx.mkBoolSort());
        operable = ctx.mkFuncDecl("operable", new Sort[]{fpType, timeType},ctx.mkBoolSort());
        mitigated = ctx.mkFuncDecl("mitigated", new Sort[]{ctx.mkIntSort(), timeType},ctx.mkBoolSort());
        omega = ctx.mkFuncDecl("omega", eventType, timeType);
    }
 
    /**
     * This method converts a z3 boolean into a z3 integer
     * @param value it is the z3 boolean
     * @return the converted z3 integer
     */
    public IntExpr bool_to_int(BoolExpr value) {
		IntExpr integer = ctx.mkIntConst("integer_" + value);
		constraints.add((ctx.mkImplies(value, ctx.mkEq(integer, ctx.mkInt(1)))));
		constraints.add((ctx.mkImplies(ctx.mkNot(value), ctx.mkEq(integer, ctx.mkInt(0)))));
		return integer;
	}

    
    
    /**
     * Setter of the wildcard manager
     * @param wildcardManager it is the wildcard manager to set
     */
    public void setWildcardManager(WildcardManager wildcardManager) {
    	this.wildcardManager = wildcardManager;
    }


}