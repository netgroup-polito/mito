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
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.microsoft.z3.BoolExpr;
import com.microsoft.z3.Context;
import com.microsoft.z3.DatatypeExpr;
import com.microsoft.z3.Model;
import com.microsoft.z3.Optimize;
import com.microsoft.z3.Params;
import com.microsoft.z3.Status;

import it.polito.mito.allocation.AllocationNode;
import it.polito.mito.functions.PacketFilter;
import it.polito.mito.graph.AtomicFlow;
import it.polito.mito.graph.Event;
import it.polito.mito.graph.FilteringPolicy;
import it.polito.mito.graph.FlowPath;
import it.polito.mito.graph.SecurityRequirement;
import it.polito.mito.jaxb.FunctionalTypes;
import it.polito.mito.utils.VerificationResult;


/**
 * Various checks for specific properties in the network.
 *
 *
 */
	
public class Checker {
	public enum Prop {
	    ISOLATION,REACHABILITY,COMPLETE_REACHABILITY,ATTACK_MITIGATION_PROPERTY
	}
	
	Context ctx;
	NetContext nctx;
	Optimize solver;
	public BoolExpr[] assertions={};
	public Status result;
	public Model model;
	private HashMap<String, AllocationNode> allocationNodes;
	private HashMap<Integer, Event> events;
	private List<BoolExpr> constraintList;
	private long timeChecker;
	private HashMap<Integer, SecurityRequirement> securityRequirements;
	private String impactMode;
	
	private Map<Integer, BoolExpr> softConstraintMSMap;
	private Map<Integer, Integer> softConstraintWeightsMap;
	


	/**
	 * Public constructor of Checker class
	 * @param context it is the z3 context where assertions must be introduced into
	 * @param nctx it is the NetContext which stores basic z3 variables
	 * @param allocationNodes it is the map of allocation nodes of the Allocation Graph
	 * @param events 
	 * @param securityRequirements 
	 * @param impactMode 
	 */
	public Checker(Context context, NetContext nctx, HashMap<String,AllocationNode> allocationNodes, HashMap<Integer, Event> events, HashMap<Integer, SecurityRequirement> securityRequirements, String impactMode) {
		this.ctx = context;
		this.nctx = nctx;
		this.allocationNodes = allocationNodes;
		this.events = events;
		this.solver = ctx.mkOptimize();
		this.constraintList =new ArrayList<BoolExpr>();
		this.securityRequirements = securityRequirements;
		this.impactMode = impactMode;
		
		this.softConstraintMSMap = new HashMap<Integer,BoolExpr>();
		this.softConstraintWeightsMap = new HashMap<Integer,Integer>();
		
		// initial parameters
		Params p = ctx.mkParams();
		p.add("maxsat_engine", ctx.mkSymbol("wmax"));
		p.add("maxres.wmax", true  );
		p.add("timeout", 1800000);
		solver.setParameters(p);
	}
	
	
	/**
	 * Thus method adds hard and soft constraints in the solver
	 */
	public void addConstraints() {
		allocationNodes.values().forEach(node->node.addConstraints(solver));
		constraintList.forEach(boolExpr->this.solver.Add(boolExpr));
		nctx.addConstraints(solver);
	}
	
	public void addOmegaConstraints() {
		
		for(Event e : events.values()) {
			constraintList.add(ctx.mkNot(ctx.mkEq(nctx.omega.apply(e.getZ3Name()), nctx.timeMap.get(Integer.toString(0)))));
		}
		
		//omega surjectivity
		for(Event e1 : events.values()) {
			for(Event e2 : events.values()) {
				if(!e1.getEventName().equals(e2.getEventName())) {
					constraintList.add(ctx.mkNot(ctx.mkEq(nctx.omega.apply(e1.getZ3Name()), nctx.omega.apply(e2.getZ3Name()))));
				}
			}
		}
	}
	
	public void addSoftConstraints() {
		if(impactMode.equals("economic")) {
			
			int i = 0;
			for(SecurityRequirement sr : securityRequirements.values()) {
				float weight = sr.getOriginalProperty().getWeights().getW1()*sr.getOriginalProperty().getImpact().getI1() +
						sr.getOriginalProperty().getWeights().getW2()*sr.getOriginalProperty().getImpact().getI2() +
						sr.getOriginalProperty().getWeights().getW3()*sr.getOriginalProperty().getImpact().getI3();
				for(int j = 0; j < nctx.timeMap.size(); j++) {
					softConstraintMSMap.put(i, (BoolExpr) nctx.mitigated.apply(ctx.mkInt(sr.getIdRequirement()), nctx.timeMap.get(Integer.toString(j))));
					softConstraintWeightsMap.put(i, Math.round(weight));
					i++;
					}
				System.out.println("Requirement ID: " + sr.getIdRequirement() + " Impact = " + weight);
				}

			}
		else if(impactMode.equals("privacy")) {

	        List<SecurityRequirement> requirements = new ArrayList<>(securityRequirements.values());
	        Map<SecurityRequirement, Float> impacts = new HashMap<>();
	        for (SecurityRequirement sr : requirements) {
	            float impact = sr.getOriginalProperty().getWeights().getW1() * sr.getOriginalProperty().getImpact().getI1()
	                         + sr.getOriginalProperty().getWeights().getW2() * sr.getOriginalProperty().getImpact().getI2()
	                         + sr.getOriginalProperty().getWeights().getW3() * sr.getOriginalProperty().getImpact().getI3();
	            impacts.put(sr, impact);
				System.out.println("Requirement ID: " + sr.getIdRequirement() + " Impact = " + impact);
	        }
	        
	        requirements.sort(Comparator.comparing(impacts::get));
	        for(SecurityRequirement t: requirements) {
	        	//System.out.println(impacts.get(t));
	        }
	        
	        Map<SecurityRequirement, Integer> lambda = new HashMap<>();
	        lambda.put(requirements.get(0), 1);
	        int sum = 1;
	        for (int i = 1; i < requirements.size(); i++) {
	        	int currentLambda = 1;
	        	for(int j = 0; j < i; j++) {
	        		currentLambda += lambda.get(requirements.get(j));
	        	}
	            lambda.put(requirements.get(i), currentLambda);
	        }

	        int i = 0;
	        for (SecurityRequirement sr : requirements) {
	            int weight = lambda.get(sr);
	            
	            for (int j = 0; j < nctx.timeMap.size(); j++) {
	                softConstraintMSMap.put(i, (BoolExpr) nctx.mitigated.apply(
	                        ctx.mkInt(sr.getIdRequirement()), nctx.timeMap.get(Integer.toString(j))));
	                softConstraintWeightsMap.put(i, weight);
	                i++;
	            }
	        }
		}
		
		for(int i=0; i < softConstraintMSMap.size(); i++) {
			//System.out.println(softConstraintMSMap.get(i) + "+" + softConstraintWeightsMap.get(i));
			this.solver.AssertSoft(softConstraintMSMap.get(i), softConstraintWeightsMap.get(i), "attack");
			//System.out.println(softConstraintMSMap.get(i) + " Impact = " + softConstraintWeightsMap.get(i));
		}

			

	}
	

	/**
	 * This method starts the z3 solver to solve the MaxSMT problem
	 * @return
	 */
	public VerificationResult propertyCheck(){
		solver.Push();
		addOmegaConstraints();
		addConstraints();
		addSoftConstraints();
		long startTime = System.currentTimeMillis();

		result = this.solver.Check(); 
		long stopTime = System.currentTimeMillis();
	    long elapsedTime = stopTime - startTime;
	     timeChecker = elapsedTime;
	     System.out.println("single checker time " +timeChecker);
		model = (result == Status.SATISFIABLE) ? this.solver.getModel() : null;
		logAssertions();
		solver.Pop();
		return new VerificationResult(ctx, result, nctx, assertions, model);
	}
	
	public long getTimeChecker() {
		return timeChecker;
	}


	public void setTimeChecker(long timeChecker) {
		this.timeChecker = timeChecker;
	}


	/**
	 * This method prints the assertions of the z3 model in the log.
	 * old versions of z3 did not provide solver.getAssertions() method
	 * so if you want to use, it has to be commented
	 */
	private void logAssertions()  {	
		/*
		Logger logger = LogManager.getLogger("assertions");
		StringWriter stringWriter = new StringWriter();
		assertions = solver.getAssertions();
		Arrays.asList(assertions).forEach(t-> stringWriter.append(t+"\n\n"));
		if(model!=null){
			logger.debug("---------- Assertions: "+assertions.length);	
		}
		*/
	}


	
	/**
	 * This method is invoked by MitoProxy to generate the z3 constraints for each security requirement
	 * @param sr It is the requirement that must be modeled in z3 language
	 * @param propType It is the type of the security requirement
	 */
	public void createRequirementConstraints(SecurityRequirement sr, Prop propType) {
		
		switch (propType) {
			case ISOLATION:
				createIsolationConstraints(sr);
				break;
			case REACHABILITY:
				createReachabilityConstraint(sr);
				break;
			case COMPLETE_REACHABILITY:
				createCompleteReachabilityConstraint(sr);
				break;
			case ATTACK_MITIGATION_PROPERTY:
				createAttackMitigationConstraint(sr);
				break;
		}
	}


	private void createAttackMitigationConstraint(SecurityRequirement sr) {
		
		
		for(int i = 0; i < nctx.timeMap.size(); i++) {
			
			Map<Integer, FlowPath> allFlows = sr.getFlowsMap();
			List<BoolExpr> flowConstraints = new ArrayList<>();
			
			for(FlowPath flowPath : allFlows.values()) {
				List<BoolExpr> pathConstraints = new ArrayList<>();
				
				for(AtomicFlow flow : flowPath.getAtomicFlowsMap().values()) {
					
					List<BoolExpr> singleConstraints = new ArrayList<>();
					for(AllocationNode node : flowPath.getPath()) {
						
						if(node.getTypeNF() == FunctionalTypes.FIREWALL) {
							PacketFilter pf = (PacketFilter) node.getPlacedNF();
							int traffic;
							if(node.getAtomicPredicatesInInputForFlow(flowPath.getIdFlow()) == null)
								traffic = -1;
							else
								traffic = node.getAtomicPredicatesInInputForFlow(flowPath.getIdFlow()).get(flow.getFlowId());
							List<BoolExpr> fpExprs = new ArrayList<>();
							for(FilteringPolicy fp : pf.getFpList()) {
								if(fp.isExisting()) {
									BoolExpr fpExpr = ctx.mkAnd((BoolExpr) nctx.operable.apply(fp.getZ3Name(), nctx.timeMap.get(Integer.toString(i))), (BoolExpr) nctx.deny.apply(node.getZ3Name(), fp.getZ3Name(), ctx.mkInt(traffic)));
									fpExprs.add(fpExpr);									
								}

							}
							BoolExpr[] fpConstraints = new BoolExpr[fpExprs.size()];
							BoolExpr fpConstraint = ctx.mkOr(fpExprs.toArray(fpConstraints));
							singleConstraints.add(fpConstraint);
						}
						
					}
					
					if(singleConstraints.size() > 0) {
						BoolExpr[] arrayConstraints = new BoolExpr[singleConstraints.size()];
						BoolExpr finalConstraint = ctx.mkOr(singleConstraints.toArray(arrayConstraints));
						pathConstraints.add(finalConstraint);
					} else {
						pathConstraints.add(ctx.mkTrue());
					}
					
				}
				
				BoolExpr[] arrayConstraints = new BoolExpr[pathConstraints.size()];
				BoolExpr flowConstraint = ctx.mkAnd(pathConstraints.toArray(arrayConstraints));
				flowConstraints.add(flowConstraint);

			} //end for on flows
			
			BoolExpr[] arrayConstraints = new BoolExpr[flowConstraints.size()];
			BoolExpr finalConstraint = ctx.mkAnd(flowConstraints.toArray(arrayConstraints));
			constraintList.add(ctx.mkEq((BoolExpr)nctx.mitigated.apply(ctx.mkInt(sr.getIdRequirement()), nctx.timeMap.get(Integer.toString(i))),finalConstraint));
		} //end for on states
		
		constraintList.add(ctx.mkEq((BoolExpr)nctx.mitigated.apply(ctx.mkInt(sr.getIdRequirement()), nctx.timeMap.get(Integer.toString(nctx.timeMap.size()-1))),ctx.mkTrue()));
			
	}


	/**
	 * This method generates the constraints for a reachability requirement
	 * @param sr It is the requirement that must be modeled in z3 language
	 * @param propType It is the type of the security requirement
	 */
	private void createReachabilityConstraint(SecurityRequirement sr) {
		
		List<BoolExpr> pathConstraints = new ArrayList<>();
		Map<Integer, FlowPath> allFlows = sr.getFlowsMap();
		
		for(FlowPath flowPath : allFlows.values()) {
			for(AtomicFlow flow : flowPath.getAtomicFlowsMap().values()) {
				List<BoolExpr> singleConstraints = new ArrayList<>();
				
				for(AllocationNode node : flowPath.getPath()) {
					int traffic;
					if(node.getAtomicPredicatesInInputForFlow(flowPath.getIdFlow()) == null)
						traffic = -1;
					else
						traffic = node.getAtomicPredicatesInInputForFlow(flowPath.getIdFlow()).get(flow.getFlowId());
					singleConstraints.add(ctx.mkImplies(node.getPlacedNF().getUsed(), ctx.mkNot((BoolExpr) nctx.deny.apply(node.getZ3Name(), ctx.mkInt(traffic)))));
				}
				

				BoolExpr[] arrayConstraints = new BoolExpr[singleConstraints.size()];
				BoolExpr finalConstraint = ctx.mkAnd(singleConstraints.toArray(arrayConstraints));
				pathConstraints.add(finalConstraint);
			}
		}
		
	
		BoolExpr[] arrayConstraints = new BoolExpr[pathConstraints.size()];
		BoolExpr finalConstraint = ctx.mkOr(pathConstraints.toArray(arrayConstraints));
		constraintList.add(finalConstraint);
	}
	
	
	
	private void createCompleteReachabilityConstraint(SecurityRequirement sr) {
		
		Map<Integer, FlowPath> allFlows = sr.getFlowsMap();
		List<BoolExpr> pathConstraints = new ArrayList<>();
		
		for(FlowPath flowPath : allFlows.values()) {
			List<BoolExpr> atomicFlowConstraintsInsideFlowPath = new ArrayList<>();
			for(Map.Entry<Integer, AtomicFlow> atomicFlowEntry: flowPath.getAtomicFlowsMap().entrySet()) {
				
				List<BoolExpr> singleConstraints = new ArrayList<>();
				for(AllocationNode node : flowPath.getPath()) {
					int traffic;
					if(node.getAtomicPredicatesInInputForFlow(flowPath.getIdFlow()) == null)
						traffic = -1;
					else
						traffic = node.getAtomicPredicatesInInputForFlow(flowPath.getIdFlow()).get(atomicFlowEntry.getValue().getFlowId());
					singleConstraints.add(ctx.mkImplies(node.getPlacedNF().getUsed(), ctx.mkEq( (BoolExpr)nctx.deny.apply(node.getZ3Name(), ctx.mkInt(traffic)), ctx.mkFalse())));
				}
				
				BoolExpr[] arrayConstraints = new BoolExpr[singleConstraints.size()];
				BoolExpr maximalFlowConstraint = ctx.mkAnd(singleConstraints.toArray(arrayConstraints));
				atomicFlowConstraintsInsideFlowPath.add(maximalFlowConstraint);
			}
			
			BoolExpr[] tmp = new BoolExpr[atomicFlowConstraintsInsideFlowPath.size()];
			BoolExpr pathConstraint = ctx.mkAnd(atomicFlowConstraintsInsideFlowPath.toArray(tmp));
			pathConstraints.add(pathConstraint);
		}
	
		BoolExpr[] arrayConstraints = new BoolExpr[pathConstraints.size()];
		BoolExpr finalConstraint = ctx.mkOr(pathConstraints.toArray(arrayConstraints));
		constraintList.add(finalConstraint);
	}


	
	/**
	 * This method generates the constraints for an isolation requirement
	 * @param sr It is the requirement that must be modeled in z3 language
	 * @param propType It is the type of the security requirement
	 */
	private void createIsolationConstraints(SecurityRequirement sr) {
		
		List<BoolExpr> pathConstraints = new ArrayList<>();
		Map<Integer, FlowPath> allFlows = sr.getFlowsMap();
		
		for(FlowPath flowPath : allFlows.values()) {
			for(AtomicFlow flow : flowPath.getAtomicFlowsMap().values()) {
				List<BoolExpr> singleConstraints = new ArrayList<>();
				
				for(AllocationNode node : flowPath.getPath()) {
					int traffic;
					if(node.getAtomicPredicatesInInputForFlow(flowPath.getIdFlow()) == null)
						traffic = -1;
					else
						traffic = node.getAtomicPredicatesInInputForFlow(flowPath.getIdFlow()).get(flow.getFlowId());
					singleConstraints.add(ctx.mkAnd(node.getPlacedNF().getUsed(), (BoolExpr) nctx.deny.apply(node.getZ3Name(), ctx.mkInt(traffic))));
				}
				
				BoolExpr[] arrayConstraints = new BoolExpr[singleConstraints.size()];
				BoolExpr finalConstraint = ctx.mkOr(singleConstraints.toArray(arrayConstraints));
				pathConstraints.add(finalConstraint);
			}
			
		}
		
		
		BoolExpr[] arrayConstraints = new BoolExpr[pathConstraints.size()];
		BoolExpr finalConstraint = ctx.mkAnd(pathConstraints.toArray(arrayConstraints));
		constraintList.add(finalConstraint);
	}

}


