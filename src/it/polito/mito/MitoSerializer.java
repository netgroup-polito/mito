package it.polito.mito;

import java.io.File;
import java.util.List;
import java.util.stream.Collectors;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;

import org.w3c.dom.Document;

import com.microsoft.z3.Status;

import it.polito.mito.allocation.AllocationGraphGenerator;
import it.polito.mito.extra.BadGraphError;
import it.polito.mito.jaxb.EType;
import it.polito.mito.jaxb.Graph;
import it.polito.mito.jaxb.NFV;
import it.polito.mito.jaxb.Path;
import it.polito.mito.jaxb.Property;
import it.polito.mito.translator.FirewallsOmegaXmlBuilder;
import it.polito.mito.translator.Translator;
import it.polito.mito.translator.XmlUtils;
import it.polito.mito.translator.Z3OmegaParser;
import it.polito.mito.utils.TestResults;
import it.polito.mito.utils.VerificationResult;

/**
 * This class separates the Mito classes implementation from the actual input
 */
public class MitoSerializer {
	private NFV nfv, result;
	private boolean sat = false;
	private String z3Model;
	private TestResults testResults;
	
	int time = 0;
	
	public int getTime() {
		return time;
	}


	public void setTime(int time) {
		this.time = time;
	}


	/**
	 * Wraps all the Mito tasks, executing the z3 procedure for each graph in the
	 * NFV element
	 * 
	 * @param root the NFV element received as input
	 */
	public MitoSerializer(NFV root) {
		this.nfv = root;
		AllocationGraphGenerator agg = new AllocationGraphGenerator(root);
		root = agg.getAllocationGraph();
		MitoNormalizer norm = new MitoNormalizer(root);
		root = norm.getRoot();

		try {
			List<Path> paths = null;
			if (root.getNetworkForwardingPaths() != null)
				paths = root.getNetworkForwardingPaths().getPath();
			for (Graph g : root.getGraphs().getGraph()) {
				List<Property> prop = root.getPropertyDefinition().getProperty().stream()
						.filter(p -> p.getGraph() == g.getId()).collect(Collectors.toList());
				if (prop.size() == 0)
					throw new BadGraphError("No property defined for the Graph " + g.getId(),
							EType.INVALID_PROPERTY_DEFINITION);
				MitoProxy test = new MitoProxy(g, root.getHosts(), root.getConnections(), root.getConstraints(),
						prop, root.getImpactMode(), paths);
				testResults = test.getTestTimeResults();
				
				long beginAll = System.currentTimeMillis();
				VerificationResult res = test.checkNFFGProperty();
				long endAll = System.currentTimeMillis();
				//loggerResult.debug("Only checker: " + (endAll - beginAll) + "ms");
				//System.out.println("Only checker: " + (endAll - beginAll) + "ms");
				time =  (int) res.getTime(); 
				
				if (res.result != Status.UNSATISFIABLE && res.result != Status.UNKNOWN) {
					
					z3Model = res.model.toString();
					
					System.out.println(z3Model);
					
					Z3OmegaParser parser = new Z3OmegaParser();
			        Z3OmegaParser.OmegaResult omegaResult = parser.parseOmega(z3Model);

			        // 4) costruisci l'XML con firewall + tempi
			        Document firewallsDoc = null;
					try {
						firewallsDoc = FirewallsOmegaXmlBuilder.build(nfv, omegaResult);
					} catch (ParserConfigurationException e) {
						e.printStackTrace();
					}

			        // 5) scrivi su file o su stringa
			        //File outFile = new File("firewallsOmega.xml");
			        //XmlUtils.writeDocumentToFile(firewallsDoc, outFile);

			        // oppure:
			        String xmlString = null;
					try {
						xmlString = XmlUtils.documentToString(firewallsDoc);
					} catch (TransformerException e) {
						e.printStackTrace();
					}
			        System.out.println(xmlString);
					
					
					
					//Translator t = new Translator(res.model.toString(), root, g, test.getAllocationNodes(), test.getTrafficFlowsMap(), test.getNetworkAtomicPredicates());
					z3Model = res.model.toString();
					//t.setNormalizer(norm);
					//result = t.convert();
					//root = result;
					result = root;
					sat = true; 
					System.out.println("SAT\n");
					testResults.setZ3Result("SAT");
				} else {
					System.out.println("UNSAT\n");
					testResults.setZ3Result("UNSAT");
					sat = false;
					result = root;
				}
				root.getPropertyDefinition().getProperty().stream().filter(p -> p.getGraph() == g.getId())
						.forEach(p -> p.setIsSat(res.result != Status.UNSATISFIABLE));

			} 
		} catch (BadGraphError e) {
			throw e;
		}
	}


	public String getZ3Model() {
		return z3Model;
	}


	public void setZ3Model(String z3Model) {
		this.z3Model = z3Model;
	}


	/**
	 * @return the original NFV object given in the constructor
	 */
	public NFV getNfv() {
		return nfv;
	}

	/**
	 * @return the NFV object after the computation
	 */
	public NFV getResult() {
		return result;
	}

	/**
	 * @return if the z3 model is sat
	 */
	public boolean isSat() {
		return sat;
	}
	
	public TestResults getTestTimeResults() {
		return testResults;
	}

}
