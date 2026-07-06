package it.polito.mito.graph;

import com.microsoft.z3.DatatypeExpr;

import it.polito.mito.allocation.AllocationNode;
import it.polito.mito.jaxb.EventType;

public class Event {
	
	private int id;
	private AllocationNode pf;
	private EventType type;
	private String eventName;
	private DatatypeExpr z3Name;
	
	public Event(int id, AllocationNode pf, EventType type) {
		super();
		this.id = id;
		this.pf = pf;
		this.type = type;
		this.eventName = new String("Event_FW_" + pf.getIpAddress());
	}

	public int getId() {
		return id;
	}

	public void setId(int id) {
		this.id = id;
	}

	public AllocationNode getPf() {
		return pf;
	}

	public void setPf(AllocationNode pf) {
		this.pf = pf;
	}

	public EventType getType() {
		return type;
	}

	public void setType(EventType type) {
		this.type = type;
	}

	public String getEventName() {
		return eventName;
	}

	public void setEventName(String eventName) {
		this.eventName = eventName;
	}

	public DatatypeExpr getZ3Name() {
		return z3Name;
	}

	public void setZ3Name(DatatypeExpr z3Name) {
		this.z3Name = z3Name;
	}
	
}
