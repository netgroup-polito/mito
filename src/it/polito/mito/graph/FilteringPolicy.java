package it.polito.mito.graph;

import com.microsoft.z3.BoolExpr;
import com.microsoft.z3.DatatypeExpr;

import it.polito.mito.jaxb.Configuration;

public class FilteringPolicy {
	
	private boolean existing;
	private String fpName;
	private DatatypeExpr z3Name;
	
	private boolean blacklisting;
	private boolean defaultActionSet;
	private BoolExpr whitelist;
	private Configuration configuration;
	
	
	public boolean isBlacklisting() {
		return blacklisting;
	}
	public void setBlacklisting(boolean blacklisting) {
		this.blacklisting = blacklisting;
	}
	public boolean isDefaultActionSet() {
		return defaultActionSet;
	}
	public void setDefaultActionSet(boolean defaultActionSet) {
		this.defaultActionSet = defaultActionSet;
	}
	public BoolExpr getWhitelist() {
		return whitelist;
	}
	public void setWhitelist(BoolExpr whitelist) {
		this.whitelist = whitelist;
	}
	public boolean isExisting() {
		return existing;
	}
	public void setExisting(boolean existing) {
		this.existing = existing;
	}
	public Configuration getConfiguration() {
		return configuration;
	}
	public void setConfiguration(Configuration configuration) {
		this.configuration = configuration;
	}
	public String getFpName() {
		return fpName;
	}
	public void setFpName(String fpName) {
		this.fpName = fpName;
	}
	public DatatypeExpr getZ3Name() {
		return z3Name;
	}
	public void setZ3Name(DatatypeExpr z3Name) {
		this.z3Name = z3Name;
	}
	
	
	

}
