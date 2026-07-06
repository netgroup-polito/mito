package it.polito.mito.functions;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import com.microsoft.z3.ArithExpr;
import com.microsoft.z3.BoolExpr;
import com.microsoft.z3.Context;
import com.microsoft.z3.DatatypeExpr;
import com.microsoft.z3.Expr;
import com.microsoft.z3.FuncDecl;
import com.microsoft.z3.IntExpr;
import com.microsoft.z3.Optimize;

import it.polito.mito.allocation.AllocationNode;
import it.polito.mito.extra.BadGraphError;
import it.polito.mito.extra.WildcardManager;
import it.polito.mito.graph.Event;
import it.polito.mito.graph.FilteringPolicy;
import it.polito.mito.graph.FlowPath;
import it.polito.mito.jaxb.ActionTypes;
import it.polito.mito.jaxb.Configuration;
import it.polito.mito.jaxb.EType;
import it.polito.mito.jaxb.EventType;
import it.polito.mito.jaxb.FunctionalTypes;
import it.polito.mito.jaxb.Node;
import it.polito.mito.jaxb.PName;
import it.polito.mito.solver.NetContext;
import it.polito.mito.utils.Tuple;

/** Represents a Packet Filter with the associated Access Control List
 *
 */
public class PacketFilter extends GenericFunction{
	
	List<FilteringPolicy> fpList;
	DatatypeExpr pf;

	FuncDecl filtering_function;
	boolean autoConfigured;
	BoolExpr behaviour;
	FuncDecl rule_func;
	// blacklisting and defaultAction must match
	
	Event event;

	

	/**
	 * Public constructor for the Packet Filter
	 * @param source It is the Allocation Node on which the packet filter is put
	 * @param ctx It is the Z3 Context in which the model is generated
	 * @param nctx It is the NetContext object to which constraints are sent
	 * @param wildcardManager 
	 */
	public PacketFilter(AllocationNode source, Context ctx, NetContext nctx, WildcardManager wildcardManager) {
		this.source = source;
		this.ctx = ctx;
		this.nctx = nctx;
		
		pf = source.getZ3Name();
		constraints = new ArrayList<BoolExpr>();
		isEndHost = false;
		
		fpList = new ArrayList<FilteringPolicy>();
		
   		// true for blacklisting, false for whitelisting
   		// this is the default, but it can be changed
		for(int i = 0; i < 2; i++) {
			FilteringPolicy fp = new FilteringPolicy();
			fp.setExisting(false);
			fp.setBlacklisting(false);
			fp.setDefaultActionSet(false);
			fp.setConfiguration(null);
			fpList.add(fp);
		}
		
		for(Configuration c : source.getNode().getConfiguration()) {
			int index = 1;
			if(c.getFirewall().getIndex() != null) index = c.getFirewall().getIndex();
			FilteringPolicy fp = fpList.get(index-1);
			fp.setExisting(true);
			fp.setBlacklisting(c.getFirewall().getDefaultAction() == ActionTypes.ALLOW);
			fp.setDefaultActionSet(true);
			fp.setWhitelist(ctx.mkBoolConst(pf + "_" + index + "_whitelist"));	
			fp.setConfiguration(c);
		}
   		
   		// function can be used or not, autoplace follows it
   		used = ctx.mkBoolConst(pf+"_used");
		autoplace = false; 
		
		//function can be autoConfigured is z3 must establish the firewall filtering policy
		autoConfigured = false;
		
		event = null;
	}

	/**
	 * This method allows to generate the filtering rules for a manually configured packet_filter
	 */
	public void manualConfiguration(){
		
		//if(!autoplace) constraints.add(ctx.mkEq(used, ctx.mkTrue()));
		
		/* Constraints about deny */
		
		Node n = source.getNode();
		if(n.getFunctionalType().equals(FunctionalTypes.FIREWALL)){
			
			for(int i = 0; i < 2; i++) {
				FilteringPolicy fp = fpList.get(i);
				if(i == 0 && fp.isExisting()) {
					//System.out.println("Allowed");
					for(Integer traffic : source.getForwardBehaviourList()) {
						//System.out.println(traffic);
						constraints.add(ctx.mkEq((BoolExpr)nctx.deny.apply(source.getZ3Name(), fp.getZ3Name(), ctx.mkInt(traffic)), ctx.mkFalse()));
					}
					//System.out.println("Dropped");
					for(Integer traffic : source.getDroppedList()) {
						//System.out.println(traffic);
						constraints.add(ctx.mkEq((BoolExpr)nctx.deny.apply(source.getZ3Name(), fp.getZ3Name(), ctx.mkInt(traffic)), ctx.mkTrue()));
					}
				}
				
				if(i == 1 && fp.isExisting()) {
					//System.out.println("Allowed");
					for(Integer traffic : source.getForwardBehaviourList2()) {
						//System.out.println(traffic);
						constraints.add(ctx.mkEq((BoolExpr)nctx.deny.apply(source.getZ3Name(), fp.getZ3Name(), ctx.mkInt(traffic)), ctx.mkFalse()));
					}
					//System.out.println("Dropped");
					for(Integer traffic : source.getDroppedList2()) {
						//System.out.println(traffic);
						constraints.add(ctx.mkEq((BoolExpr)nctx.deny.apply(source.getZ3Name(), fp.getZ3Name(), ctx.mkInt(traffic)), ctx.mkTrue()));
					}
				}
			}
		}
			
		/* Constraints about operability */
		
		// Case 1 : event n (none)
		if(event == null) {
			for(Map.Entry<String,DatatypeExpr> timeEntry : nctx.timeMap.entrySet()) {
				//System.out.println("Time " + timeEntry.getKey());
				DatatypeExpr timeValue = timeEntry.getValue();
				//BoolExpr antecedent = ctx.mkEq(nctx.omega, timeValue);
				List<BoolExpr> singleOperableConstraints = new ArrayList<>();
				for(FilteringPolicy fp : fpList) {
					if(fp.isExisting()) {
						singleOperableConstraints.add(ctx.mkEq(nctx.operable.apply(fp.getZ3Name(), timeValue), ctx.mkTrue()));
					}	
				}
				BoolExpr[] arrayConstraints = new BoolExpr[singleOperableConstraints.size()];
				BoolExpr operableConstraint = ctx.mkAnd(singleOperableConstraints.toArray(arrayConstraints));
				constraints.add(operableConstraint);
			}	
		}
		else if(event.getType() == EventType.U) {
			List<BoolExpr> operabilityPerTimeConstraints = new ArrayList<>();
			for(Map.Entry<String,DatatypeExpr> timeEntry : nctx.timeMap.entrySet()) {
				String timeKey = timeEntry.getKey();
				int timeInt = Integer.parseInt(timeKey);
				//System.out.println("Time " + timeEntry.getKey());
				DatatypeExpr timeValue = timeEntry.getValue();
				FilteringPolicy fp1 = fpList.get(0);
				FilteringPolicy fp2 = fpList.get(1);
				
				if(timeInt == 0) {
					BoolExpr b1 = ctx.mkEq(nctx.operable.apply(fp1.getZ3Name(), timeValue), ctx.mkTrue());
					BoolExpr b2 = ctx.mkEq(nctx.operable.apply(fp2.getZ3Name(), timeValue), ctx.mkFalse());
					operabilityPerTimeConstraints.add(ctx.mkAnd(b1,b2));
					continue;
				}


				BoolExpr antec = ctx.mkEq(nctx.omega.apply(event.getZ3Name()), timeValue);
				List<BoolExpr> conseqConstraints = new ArrayList<>();
				for(int i = 0; i < timeInt; i++) {
					DatatypeExpr previousTimeValue = nctx.timeMap.get(String.valueOf(i));
					//System.out.println(previousTimeValue);
					BoolExpr b1 = ctx.mkEq(nctx.operable.apply(fp1.getZ3Name(), previousTimeValue), ctx.mkTrue());
					BoolExpr b2 = ctx.mkEq(nctx.operable.apply(fp2.getZ3Name(), previousTimeValue), ctx.mkFalse());
					conseqConstraints.add(b1);
					conseqConstraints.add(b2);
				}
				for(int i = timeInt; i <= nctx.eventNumber; i++) {
					DatatypeExpr nextTimeValue = nctx.timeMap.get(String.valueOf(i));
					//System.out.println(nextTimeValue);
					BoolExpr b1 = ctx.mkEq(nctx.operable.apply(fp1.getZ3Name(), nextTimeValue), ctx.mkFalse());
					BoolExpr b2 = ctx.mkEq(nctx.operable.apply(fp2.getZ3Name(), nextTimeValue), ctx.mkTrue());
					conseqConstraints.add(b1);
					conseqConstraints.add(b2);
				}
				BoolExpr[] arrayConstraints = new BoolExpr[conseqConstraints.size()];
				BoolExpr timeConstraint = ctx.mkAnd(conseqConstraints.toArray(arrayConstraints));
				constraints.add(ctx.mkImplies(antec, timeConstraint));
			}
			
			
		}
		
		else if(event.getType() == EventType.A) {
			List<BoolExpr> operabilityPerTimeConstraints = new ArrayList<>();
			for(Map.Entry<String,DatatypeExpr> timeEntry : nctx.timeMap.entrySet()) {
				String timeKey = timeEntry.getKey();
				int timeInt = Integer.parseInt(timeKey);
				//System.out.println("Time " + timeEntry.getKey());
				DatatypeExpr timeValue = timeEntry.getValue();
				//FilteringPolicy fp1 = fpList.get(0);
				FilteringPolicy fp2 = fpList.get(1);
				
				if(timeInt == 0) {
					//BoolExpr b1 = ctx.mkEq(nctx.operable.apply(fp1.getZ3Name(), timeValue), ctx.mkTrue());
					BoolExpr b2 = ctx.mkEq(nctx.operable.apply(fp2.getZ3Name(), timeValue), ctx.mkFalse());
					operabilityPerTimeConstraints.add(b2);
					continue;
				}


				BoolExpr antec = ctx.mkEq(nctx.omega.apply(event.getZ3Name()), timeValue);
				List<BoolExpr> conseqConstraints = new ArrayList<>();
				for(int i = 0; i < timeInt; i++) {
					DatatypeExpr previousTimeValue = nctx.timeMap.get(String.valueOf(i));
					//System.out.println(previousTimeValue);
					//BoolExpr b1 = ctx.mkEq(nctx.operable.apply(fp1.getZ3Name(), previousTimeValue), ctx.mkTrue());
					BoolExpr b2 = ctx.mkEq(nctx.operable.apply(fp2.getZ3Name(), previousTimeValue), ctx.mkFalse());
					//conseqConstraints.add(b1);
					conseqConstraints.add(b2);
				}
				for(int i = timeInt; i <= nctx.eventNumber; i++) {
					DatatypeExpr nextTimeValue = nctx.timeMap.get(String.valueOf(i));
					//System.out.println(nextTimeValue);
					//BoolExpr b1 = ctx.mkEq(nctx.operable.apply(fp1.getZ3Name(), nextTimeValue), ctx.mkFalse());
					BoolExpr b2 = ctx.mkEq(nctx.operable.apply(fp2.getZ3Name(), nextTimeValue), ctx.mkTrue());
					//conseqConstraints.add(b1);
					conseqConstraints.add(b2);
				}
				BoolExpr[] arrayConstraints = new BoolExpr[conseqConstraints.size()];
				BoolExpr timeConstraint = ctx.mkAnd(conseqConstraints.toArray(arrayConstraints));
				constraints.add(ctx.mkImplies(antec, timeConstraint));
			}
			
			
		}
		
		else if(event.getType() == EventType.R) {
			List<BoolExpr> operabilityPerTimeConstraints = new ArrayList<>();
			for(Map.Entry<String,DatatypeExpr> timeEntry : nctx.timeMap.entrySet()) {
				String timeKey = timeEntry.getKey();
				int timeInt = Integer.parseInt(timeKey);
				DatatypeExpr timeValue = timeEntry.getValue();
				FilteringPolicy fp1 = fpList.get(0);
				//FilteringPolicy fp2 = fpList.get(1);
				
				if(timeInt == 0) {
					BoolExpr b1 = ctx.mkEq(nctx.operable.apply(fp1.getZ3Name(), timeValue), ctx.mkTrue());
					//BoolExpr b2 = ctx.mkEq(nctx.operable.apply(fp2.getZ3Name(), timeValue), ctx.mkFalse());
					operabilityPerTimeConstraints.add(b1);
					continue;
				}


				BoolExpr antec = ctx.mkEq(nctx.omega.apply(event.getZ3Name()), timeValue);
				List<BoolExpr> conseqConstraints = new ArrayList<>();
				for(int i = 0; i < timeInt; i++) {
					DatatypeExpr previousTimeValue = nctx.timeMap.get(String.valueOf(i));
					//System.out.println(previousTimeValue);
					BoolExpr b1 = ctx.mkEq(nctx.operable.apply(fp1.getZ3Name(), previousTimeValue), ctx.mkTrue());
					//BoolExpr b2 = ctx.mkEq(nctx.operable.apply(fp2.getZ3Name(), previousTimeValue), ctx.mkFalse());
					conseqConstraints.add(b1);
					//conseqConstraints.add(b2);
				}
				for(int i = timeInt; i <= nctx.eventNumber; i++) {
					DatatypeExpr nextTimeValue = nctx.timeMap.get(String.valueOf(i));
					//System.out.println(nextTimeValue);
					BoolExpr b1 = ctx.mkEq(nctx.operable.apply(fp1.getZ3Name(), nextTimeValue), ctx.mkFalse());
					//BoolExpr b2 = ctx.mkEq(nctx.operable.apply(fp2.getZ3Name(), nextTimeValue), ctx.mkTrue());
					conseqConstraints.add(b1);
					//conseqConstraints.add(b2);
				}
				BoolExpr[] arrayConstraints = new BoolExpr[conseqConstraints.size()];
				BoolExpr timeConstraint = ctx.mkAnd(conseqConstraints.toArray(arrayConstraints));
				constraints.add(ctx.mkImplies(antec, timeConstraint));
			}
			
			
		}
			
		
		
		
		

	}

	public boolean isBlacklisting() {
		for(FilteringPolicy fp : fpList) {
			if(fp.isExisting()) return fp.isBlacklisting();
		}
		return false;
	}
    
    
	
	/**
	 * This method allows to create SOFT and HARD constraints for an auto_configured packet filter
	 *@param nRules It is the number of MAXIMUM rules the packet_filter should try to configure
	 */
//    public void automaticConfiguration() {
//    	
//    	//allocation
//    	if(autoplace) {
//  			// packet filter should not be used if possible
//  			nctx.softConstrAutoPlace.add(new Tuple<BoolExpr, String>(ctx.mkNot(used), "fw_auto_conf"));
//  		}else {
//  			used = ctx.mkTrue();
//  			constraints.add(ctx.mkEq(used, ctx.mkTrue()));
//  		}
//    	
//    	//configuration
//    	if(defaultActionSet) {
//    		if(blacklisting) {
//    			constraints.add(ctx.mkEq(whitelist, ctx.mkFalse()));
//    		} else {
//    			constraints.add(ctx.mkEq(whitelist, ctx.mkTrue()));
//    		}
//    	}
//    	for(Map<Integer, Integer> flowMap : source.getMapFlowIdAtomicPredicatesInInput().values()) {
//    		for(Integer traffic : flowMap.values()) {
//    			BoolExpr rule = (BoolExpr) ctx.mkConst(pf + "_rule_" + traffic, ctx.mkBoolSort());
//    			constraints.add(
//    					ctx.mkEq(
//    							(BoolExpr) nctx.deny.apply(source.getZ3Name(), ctx.mkInt(traffic)),
//    							ctx.mkAnd(
//    									used,
//    									ctx.mkOr(
//    											ctx.mkAnd(whitelist, ctx.mkNot(rule)),
//    											ctx.mkAnd(ctx.mkNot(whitelist), rule)
//    											)
//    									)
//    							)
//    					);
//    			nctx.softConstrAutoConf.add(new Tuple<BoolExpr, String>(ctx.mkEq(rule, ctx.mkFalse()), "fw_auto_conf"));
//    		}
//    	}
//    
//    }

	
	

	/**
	 * This method allows to know if autoconfiguration feature is used
	 *@return the value of autoconfigured boolean variable
	 */
	public boolean isAutoconfigured() {
		return autoConfigured;
	}
    
   	/**
	 * This method allows to know if autoplacement feature is used
	 *@return the value of autoplace boolean variable
	 */
	public boolean isAutoplace() {
		return autoplace;
	}

 	/**
	 * This method allows to set autoconfigured variable
	 *@param autoconfigured Value to set
	 */
	public void setAutoconfigured(boolean autoconfigured) {
		this.autoConfigured = autoconfigured;
	}
	
	/**
	 * This method allows to set autoplace variable
	 *@param autoplace Value to set
	 */
	public void setAutoplace(boolean autoplace) {
		this.autoplace = autoplace;
	}
	
	public List<FilteringPolicy> getFpList() {
		return fpList;
	}

	public void setFpList(List<FilteringPolicy> fpList) {
		this.fpList = fpList;
	}
	
	public Event getEvent() {
		return event;
	}

	public void setEvent(Event event) {
		this.event = event;
	}

	/**
	 * This method allows to wrap the method which adds the constraints inside Z3 solver
	 * @param solver Istance of Z3 solver
	 */
	@Override
	public void addContraints(Optimize solver) {
		BoolExpr[] constr = new BoolExpr[constraints.size()];
	    solver.Add(constraints.toArray(constr));
	    //additionalConstraints(solver);
	}
	
}
