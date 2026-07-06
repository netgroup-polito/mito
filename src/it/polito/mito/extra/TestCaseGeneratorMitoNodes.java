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
public class TestCaseGeneratorMitoNodes {

 
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


	//List<Tuple<String, Node>> lastAPs;
	
	
	public TestCaseGeneratorMitoNodes(String name, int numberNodes, int seed) {
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
		nfv = generateNFV(numberNodes, rand);
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
	        case LOW:    return 2.5;   // tipicamente "basso"
	        case MEDIUM: return 5.5;   // medio
	        case HIGH:   return 8.5;   // alto
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

	
	// Overload con seed opzionale (per test riproducibili)
	private void createPolicy(PName type, NFV nfv, Graph graph,
	                          String IPClient, String IPServer,
	                          ImpactBias bias, Long seed) {

	    Random rng = (seed == null) ? new Random() : new Random(seed);

	    Property property = new Property();
	    property.setName(type);
	    property.setGraph(0L);     // oppure prendi da 'graph' se hai un id
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



	public NFV generateNFV(int numberNodes, Random rand) {
		
		
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
		
		int numberNetworks = 5/5;
		
		int extraNodes = numberNodes - 23;
		int extraNodesA = extraNodes / 2;
		int extraNodesB = extraNodes / 2;
		if (extraNodes % 2 != 0) {
			extraNodesA += 1; 
		}
		
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
			
			List<Node> forwardersA = new ArrayList<>();
			for(int i=0; i<extraNodesA; i++){
				Node forwarderTMP = new Node();
				String ipfwTMP = createRandomIP();
				forwarderTMP.setName(ipfwTMP);
				forwarderTMP.setFunctionalType(FunctionalTypes.FORWARDER);
				forwardersA.add(forwarderTMP);
			}
			List<Node> forwardersB = new ArrayList<>();
			for(int i=0; i<extraNodesB; i++){
				Node forwarderTMP = new Node();
				String ipfwTMP = createRandomIP();
				forwarderTMP.setName(ipfwTMP);
				forwarderTMP.setFunctionalType(FunctionalTypes.FORWARDER);
				forwardersB.add(forwarderTMP);
			}
			
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
			
			Node prev = firewall1;
			for (Node n : forwardersA) {
			    connectNodes(prev, n);
			    prev = n;
			}
			connectNodes(prev, forwarder1);
			//connectNodes(firewall1, forwarder1);
			connectNodes(firewall2, forwarder1);
			connectNodes(firewall3, forwarder1);
			
			prev = firewall4;
			for (Node n : forwardersB) {
			    connectNodes(prev, n);
			    prev = n;
			}
			connectNodes(prev, forwarder2);
			//connectNodes(firewall4, forwarder2);
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
			graph.getNode().addAll(forwardersA);
			graph.getNode().addAll(forwardersB);
			
			//create policies
			for(int i=0; i<2; i++) {
				for(int j=0; j<3; j++) {
					String ip1 = EndPointsG11.get(i).getName();
					String ip2 =EndPointsG12.get(j).getName();
					createPolicy(PName.ATTACK_MITIGATION_PROPERTY, nfv, graph, ip1, ip2, ImpactBias.HIGH);
					addFirewallRule(firewall1, 0, ActionTypes.ALLOW, ip1, ip2);
					addFirewallRule(firewall2, 0, ActionTypes.ALLOW, ip1, ip2);
				}				
			}
			for(int i=0; i<2; i++) {
				for(int j=0; j<3; j++) {
					String ip1 = EndPointsG21.get(i).getName();
					String ip2 =EndPointsG22.get(j).getName();
					createPolicy(PName.ATTACK_MITIGATION_PROPERTY, nfv, graph, ip1, ip2, ImpactBias.MEDIUM);
					addFirewallRule(firewall4, 0, ActionTypes.ALLOW, ip1, ip2);
					addFirewallRule(firewall5, 0, ActionTypes.ALLOW, ip1, ip2);
				}				
			}
			for(int i=0; i<4; i++) {
					String ip1 = EndPointsG11.get(2).getName();
					String ip2 =EndPointsG3.get(i).getName();
					createPolicy(PName.ATTACK_MITIGATION_PROPERTY, nfv, graph, ip1, ip2, ImpactBias.LOW);
					addFirewallRule(firewall1, 0, ActionTypes.ALLOW, ip1, ip2);
					addFirewallRule(firewall3, 0, ActionTypes.ALLOW, ip1, ip2);		
			}
			for(int i=0; i<4; i++) {
				String ip1 = EndPointsG21.get(2).getName();
				String ip2 =EndPointsG3.get(i).getName();
				createPolicy(PName.ATTACK_MITIGATION_PROPERTY, nfv, graph, ip1, ip2, ImpactBias.LOW);
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
