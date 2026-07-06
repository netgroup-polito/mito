package it.polito.mito.extra;


import java.io.File;
import java.io.StringWriter;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.PropertyException;
import javax.xml.bind.Unmarshaller;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.xml.sax.SAXException;

import it.polito.mito.jaxb.*;
import it.polito.mito.utils.Tuple;


// Auxiliary class to generate  test cases for performance tests (used by TestPerformanceScalability)
public class TestCaseGeneratorMitoAll2 {

 
	NFV nfv;
	String name;
	
	/*Additional variables */
	/*int countC = 1;
	int countAP = 1;
	int countS = 1;
	int countP = 1;*/
	Random rand = null;
	
	/*String IPC;
	String IPAP;
	String IPS;*/
	NFV originalNFV;
	
	Set<String> allIPs;
	//Map<Integer, Node> EndPointsG1, EndPointsG2, EndPointsExtra, EndPointsExtra2;
	//Map<Integer, Node> singleFirewallsI;
	///Map<Integer, Node> singleFirewallsT;
	//Map<Integer, Node> groupFirewallsI;
	//Map<Integer, Node> groupFirewallsT;
	//Map<Integer, Node> groupForwarder;
	
	Node centralForwarder;
	
	public enum ImpactBias { LOW, MEDIUM, HIGH }

	private static final String GENERATOR_VERSION = "DEDICATED_TOP_V5";
	private static final float TOP_BASE_IMPACT = 9.99f;
	private static final float TOP_STEP_IMPACT = 0.01f;
	private static final float MEDIUM_IMPACT = 4.90f;
	private static final float LOW_IMPACT = 0.10f;


	//List<Tuple<String, Node>> lastAPs;
	
	
	public TestCaseGeneratorMitoAll2(String name, int numberStates, int seed) {
		this.name = name;
		this.rand = new Random(seed); 

		/*EndPointsG1 = new HashMap<Integer, Node>();
		EndPointsG2 = new HashMap<Integer, Node>();
		EndPointsExtra = new HashMap<Integer, Node>();
		EndPointsExtra2 = new HashMap<Integer, Node>();
		singleFirewallsI = new HashMap<Integer, Node>();
		singleFirewallsT = new HashMap<Integer, Node>();
		groupFirewallsI = new HashMap<Integer, Node>();
		groupFirewallsT = new HashMap<Integer, Node>();
		groupForwarder = new HashMap<Integer, Node>();
		centralForwarder = null;*/

		allIPs = new HashSet<String>();
		nfv = generateNFV(numberStates, rand);
	}
	
	
	
	public NFV changeIP(int numberStates, int seed) {
		this.rand = new Random(seed);
		
		//init

		return generateNFV(numberStates, rand);
	}
	
	
	
	private String createIP() {
		String ip;
		int first, second, third, forth;
		first = rand.nextInt(256);
		if(first == 0) first++;
		second = rand.nextInt(256);
		third = rand.nextInt(256);
		forth = rand.nextInt(256);
		ip = new String(first + "." + second + "." + third + "." + forth);
		if(rand.nextBoolean()) {
			if(rand.nextBoolean())
				ip = new String(first + "." + first + "." + first + "." + first);
			else {
				if(rand.nextBoolean())
					ip = new String(second + "." + second + "." + second + "." + second);
				else {
						ip = new String(third + "." + third + "." + third + "." + third);
				}
			}
		}
		return ip;
	}
	
	private String createRandomIP() {
		boolean notCreated = true;
		String ip = null;
		while(notCreated) {
			ip = createIP();
			if(!allIPs.contains(ip)) {
				notCreated = false;
				allIPs.add(ip);
			}
		}
		
		return ip;
		
	}
	
	private Node createWebClient(String webServerIp, String confName) {
	    String ipEndPoint = createRandomIP();
	    Node ep = new Node();
	    ep.setFunctionalType(FunctionalTypes.WEBCLIENT);
	    ep.setName(ipEndPoint);

	    Configuration confC = new Configuration();
	    confC.setName(confName);

	    Webclient wc = new Webclient();
	    wc.setNameWebServer(webServerIp);
	    confC.setWebclient(wc);

	    ep.getConfiguration().add(confC);
	    return ep;
	}

	private void populateClients(Map<Integer, Node> targetMap, int count, String webServerIp, String confName) {
	    for (int i = 0; i < count; i++) {
	        Node ep = createWebClient(webServerIp, confName);
	        targetMap.put(i, ep);
	    }
	}

	
	private Node createFirewall() {
	    String ip = createRandomIP();
	    Node firewall = new Node();
	    firewall.setName(ip);
	    firewall.setEvent(EventType.U);
	    firewall.setFunctionalType(FunctionalTypes.FIREWALL);

	    for (int i = 1; i <= 2; i++) {
	        Configuration conf = new Configuration();
	        conf.setName("conf" + i);

	        Firewall fw = new Firewall();
	        fw.setDefaultAction(ActionTypes.DENY); // allow rules will be added later
	        fw.setIndex(i);
	        conf.setFirewall(fw);
	    

	        firewall.getConfiguration().add(conf);
	    }

	    return firewall;
	}
	
	private void connectNodes(Node a, Node b) {
	    Neighbour neighA = new Neighbour();
	    neighA.setName(b.getName());
	    a.getNeighbour().add(neighA);

	    Neighbour neighB = new Neighbour();
	    neighB.setName(a.getName());
	    b.getNeighbour().add(neighB);
	}
	
	private double[] randomWeights3(Random rng) {
	    double x1 = -Math.log(1.0 - rng.nextDouble());
	    double x2 = -Math.log(1.0 - rng.nextDouble());
	    double x3 = -Math.log(1.0 - rng.nextDouble());
	    double s = x1 + x2 + x3;
	    return new double[]{ x1 / s, x2 / s, x3 / s };
	}

	private double clamp01to10(double v) {
	    return Math.max(0.0, Math.min(10.0, v));
	}

	private double targetFor(ImpactBias bias) {
	    switch (bias) {
	        case LOW:    return 2.5;   
	        case MEDIUM: return 5.5;   
	        case HIGH:   return 8.5;   
	        default:     return 5.5;
	    }
	}

	private double sigmaFor(ImpactBias bias) {
	    switch (bias) {
	        case LOW:    return 1.2;
	        case MEDIUM: return 1.5;
	        case HIGH:   return 1.0;
	        default:     return 1.2;
	    }
	}

	private double[] randomImpacts3(Random rng, ImpactBias bias) {
	    double t = targetFor(bias);
	    double sigma = sigmaFor(bias);
	    double i1 = clamp01to10(t + rng.nextGaussian() * sigma);
	    double i2 = clamp01to10(t + rng.nextGaussian() * sigma);
	    double i3 = clamp01to10(t + rng.nextGaussian() * sigma);
	    return new double[]{ i1, i2, i3 };
	}

	private void nudgeTowardsTarget(double[] impacts, double[] w, double target) {
	    double mean = w[0]*impacts[0] + w[1]*impacts[1] + w[2]*impacts[2];
	    double delta = (target - mean) * 0.5;  
	    for (int k = 0; k < 3; k++) impacts[k] = clamp01to10(impacts[k] + delta);
	}

	
	private void createPolicy(PName type, NFV nfv, Graph graph,
	                          String IPClient, String IPServer,
	                          ImpactBias bias, Long seed) {

	    Random rng = (seed == null) ? new Random() : new Random(seed);

	    Property property = new Property();
	    property.setName(type);
	    property.setGraph(0L);    
	    property.setSrc(IPClient);
	    property.setDst(IPServer);

	    double[] w = randomWeights3(rng);
	    double[] impacts = randomImpacts3(rng, bias);
	    nudgeTowardsTarget(impacts, w, targetFor(bias));

	    ImpactType impactObj = new ImpactType();
	    impactObj.setI1((float) impacts[0]);
	    impactObj.setI2((float)impacts[1]);
	    impactObj.setI3((float)impacts[2]);

	    WeightsType weightsObj = new WeightsType();
	    weightsObj.setW1((float)w[0]);
	    weightsObj.setW2((float)w[1]);
	    weightsObj.setW3((float)w[2]);

	    property.setImpact(impactObj);
	    property.setWeights(weightsObj);

	    nfv.getPropertyDefinition().getProperty().add(property);
	}

	private void createPolicy(PName type, NFV nfv, Graph graph,
	                          String IPClient, String IPServer,
	                          ImpactBias bias) {
	    createPolicy(type, nfv, graph, IPClient, IPServer, bias, null);
	}

	/*
	 * Deterministic impact assignment used for the optimization-difference
	 * scenario.  All three impact dimensions are set to the same value and
	 * the weights are uniform, so the resulting AMR impact is exactly equal
	 * to impactValue.  This makes the Economic/Privacy comparison easier to
	 * control and reproduce.
	 */
	private void createPolicyWithFixedImpact(PName type, NFV nfv, Graph graph,
	                                      String IPClient, String IPServer,
	                                      float impactValue) {
	    Property property = new Property();
	    property.setName(type);
	    property.setGraph(0L);
	    property.setSrc(IPClient);
	    property.setDst(IPServer);

	    ImpactType impactObj = new ImpactType();
	    impactObj.setI1(impactValue);
	    impactObj.setI2(impactValue);
	    impactObj.setI3(impactValue);

	    WeightsType weightsObj = new WeightsType();
	    weightsObj.setW1(1.0f / 3.0f);
	    weightsObj.setW2(1.0f / 3.0f);
	    weightsObj.setW3(1.0f / 3.0f);

	    property.setImpact(impactObj);
	    property.setWeights(weightsObj);

	    nfv.getPropertyDefinition().getProperty().add(property);
	}

	private void addFirewallRule(Node firewall, int configIndex,
            ActionTypes action, String src, String dst) {
			Elements element = new Elements();
			element.setAction(action);
			element.setSource(src);
			element.setDestination(dst);
			element.setSrcPort("*");
			element.setDstPort("*");
			element.setProtocol(L4ProtocolTypes.ANY);
			
			firewall.getConfiguration().get(configIndex).getFirewall().getElements().add(element);
	}



	public NFV generateNFV(int numberStates, Random rand) {
		
		
		//creation of the graph element
		NFV nfv = new NFV();
		Graphs graphs = new Graphs();
		PropertyDefinition pd = new PropertyDefinition();
		Constraints cnst = new Constraints();
		NodeConstraints nc = new NodeConstraints();
		LinkConstraints lc = new LinkConstraints();
		cnst.setNodeConstraints(nc);
		cnst.setLinkConstraints(lc);
		nfv.setGraphs(graphs);
		nfv.setPropertyDefinition(pd);
		nfv.setConstraints(cnst);
		Graph graph = new Graph();
		graph.setId((long) 0);
		
		centralForwarder = new Node();
		String ipCentral = createRandomIP();
		centralForwarder.setName(ipCentral);
		centralForwarder.setFunctionalType(FunctionalTypes.FORWARDER);
		
		int numberNetworks = numberStates/5;
		
		for(int k=0; k<numberNetworks; k++){
			Map<Integer, Node> EndPointsG11, EndPointsG12, EndPointsG21, EndPointsG22, EndPointsG3;
			EndPointsG11 = new HashMap<Integer, Node>();
			EndPointsG12 = new HashMap<Integer, Node>();
			EndPointsG21 = new HashMap<Integer, Node>();
			EndPointsG22 = new HashMap<Integer, Node>();
			EndPointsG3 = new HashMap<Integer, Node>();
			
			//Nodes
			populateClients(EndPointsG11, 3, "10.0.0.1", "confA");
			populateClients(EndPointsG12, 3, "10.0.0.1", "confA");
			populateClients(EndPointsG21, 3, "10.0.0.1", "confA");
			populateClients(EndPointsG22, 3, "10.0.0.1", "confA");
			populateClients(EndPointsG3,  5, "10.0.0.1", "confA");

			Node firewall1 = createFirewall();
			Node firewall2 = createFirewall();
			Node firewall3 = createFirewall();
			Node firewall4 = createFirewall();
			Node firewall5 = createFirewall();
			
			Node forwarder1 = new Node();
			String ipfw1 = createRandomIP();
			forwarder1.setName(ipfw1);
			forwarder1.setFunctionalType(FunctionalTypes.FORWARDER);
			
			Node forwarder2 = new Node();
			String ipfw2 = createRandomIP();
			forwarder2.setName(ipfw2);
			forwarder2.setFunctionalType(FunctionalTypes.FORWARDER);
			
			//Links
			for(int i=0; i<3; i++) {
				connectNodes(EndPointsG11.get(i), firewall1);
				connectNodes(EndPointsG12.get(i), firewall2);
				connectNodes(EndPointsG21.get(i), firewall4);
				connectNodes(EndPointsG22.get(i), firewall5);
			}
			for(int i=0; i<5; i++) {
				connectNodes(EndPointsG3.get(i), centralForwarder);
			}

			/*
			 * DEDICATED_TOP_V5: connect one endpoint to firewall3 so that
			 * the top-impact AMR of this network can be mitigated by a
			 * single dedicated firewall update. Medium-impact AMRs do not
			 * use firewall3, which prevents the privacy mode from mitigating
			 * a large medium-impact block together with the top AMR.
			 */
			connectNodes(EndPointsG11.get(0), firewall3);

			connectNodes(firewall1, forwarder1);
			connectNodes(firewall2, forwarder1);
			connectNodes(firewall3, forwarder1);
			connectNodes(firewall4, forwarder2);
			connectNodes(firewall5, forwarder2);
			connectNodes(firewall3, centralForwarder);
			connectNodes(forwarder2, centralForwarder);
			
			//save nodes
			graph.getNode().addAll(EndPointsG11.values());
			graph.getNode().addAll(EndPointsG12.values());
			graph.getNode().addAll(EndPointsG21.values());
			graph.getNode().addAll(EndPointsG22.values());
			graph.getNode().addAll(EndPointsG3.values());
			graph.getNode().add(firewall1);
			graph.getNode().add(firewall2);
			graph.getNode().add(firewall3);
			graph.getNode().add(firewall4);
			graph.getNode().add(firewall5);
			graph.getNode().add(forwarder1);
			graph.getNode().add(forwarder2);
			
			//create policies
			/*
			 * DEDICATED_TOP_V5 scenario.
			 *
			 * Goal: make the privacy mode mitigate only a few AMRs in the
			 * first transient states, namely the individually highest-impact
			 * AMRs, while the economic mode is still attracted by blocks of
			 * many medium-impact AMRs.
			 *
			 * Per generated network:
			 * - 1 top-impact AMR is placed on a dedicated path through firewall3.
			 *   The old allow rule for this AMR is installed only on firewall3, so
			 *   one firewall update can mitigate it without mitigating the medium
			 *   AMR block.
			 * - 14 medium-impact AMRs are placed on the medium side, protected by
			 *   firewall4/firewall5. Their aggregate impact is larger than the
			 *   single top-impact AMR, so they remain attractive for Economic.
			 * - 3 low-impact AMRs are also placed on the medium side.
			 */
			final float TOP_IMPACT = TOP_BASE_IMPACT - (TOP_STEP_IMPACT * k);
			System.out.println("### GENERATOR VERSION: " + GENERATOR_VERSION + " ###");
			System.out.println("DEBUG impact top = " + TOP_IMPACT);
			System.out.println("DEBUG impact medium = " + MEDIUM_IMPACT);
			System.out.println("DEBUG impact low = " + LOW_IMPACT);

			// One dedicated top-impact AMR. It uses firewall3 only.
			String highSrc = EndPointsG11.get(0).getName();
			String highDst = EndPointsG3.get(0).getName();
			createPolicyWithFixedImpact(PName.ATTACK_MITIGATION_PROPERTY, nfv, graph,
			                            highSrc, highDst, TOP_IMPACT);
			addFirewallRule(firewall3, 0, ActionTypes.ALLOW, highSrc, highDst);

			// Nine medium-impact AMRs requiring medium-side updates.
			for(int i=0; i<3; i++) {
				for(int j=0; j<3; j++) {
					String ip1 = EndPointsG21.get(i).getName();
					String ip2 = EndPointsG22.get(j).getName();
					createPolicyWithFixedImpact(PName.ATTACK_MITIGATION_PROPERTY, nfv, graph,
					                            ip1, ip2, MEDIUM_IMPACT);
					addFirewallRule(firewall4, 0, ActionTypes.ALLOW, ip1, ip2);
					addFirewallRule(firewall5, 0, ActionTypes.ALLOW, ip1, ip2);
				}
			}

			// Five additional medium-impact AMRs on firewall5.
			for(int i=0; i<5; i++) {
				String ip1 = EndPointsG21.get(2).getName();
				String ip2 = EndPointsG3.get(i).getName();
				createPolicyWithFixedImpact(PName.ATTACK_MITIGATION_PROPERTY, nfv, graph,
				                            ip1, ip2, MEDIUM_IMPACT);
				addFirewallRule(firewall5, 0, ActionTypes.ALLOW, ip1, ip2);
			}

			// Low-impact AMRs are kept away from the top-impact path.
			for(int i=0; i<3; i++) {
				String ip1 = EndPointsG22.get(2).getName();
				String ip2 = EndPointsG3.get(i).getName();
				createPolicyWithFixedImpact(PName.ATTACK_MITIGATION_PROPERTY, nfv, graph,
				                            ip1, ip2, LOW_IMPACT);
				addFirewallRule(firewall5, 0, ActionTypes.ALLOW, ip1, ip2);
			}
			
		}
		
	
		//add the nodes in the graph
		graph.getNode().add(centralForwarder);
		nfv.getGraphs().getGraph().add(graph);
		nfv.setImpactMode("privacy");
			
		
		return nfv;
	}


	
	
	public NFV getNfv() {
		return nfv;
	}

	public void setNfv(NFV nfv) {
		this.nfv = nfv;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

}
