package it.polito.mito.translator;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import it.polito.mito.jaxb.FunctionalTypes;
import it.polito.mito.jaxb.Graph;
import it.polito.mito.jaxb.NFV;
import it.polito.mito.jaxb.Node;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.util.Map;

public class FirewallsOmegaXmlBuilder {

    /**
     * Crea un XML del tipo:
     *
     * <Scheduling>
     *   <firewall ip="30.0.0.2" event="u" state="1"/>
     *   <firewall ip="30.0.0.3" event="a" state="2"/>
     *   <firewall ip="30.0.0.1" event="r" state="3"/>
     * </Scheduling>
     *
     * usando:
     *  - nfv: oggetto JAXB già parsato dal tuo file NFV
     *  - omegaResult: risultato del parsing della funzione omega
     */
    public static Document build(NFV nfv, Z3OmegaParser.OmegaResult omegaResult)
            throws ParserConfigurationException {

        // 1) prepara il Document vuoto
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.newDocument();

        // Root <Scheduling>
        Element root = doc.createElement("Scheduling");
        doc.appendChild(root);

        Map<String, Integer> ipToTime = omegaResult.getIpToTime();
        Integer defaultTime = omegaResult.getDefaultTime();

        // 2) scorri tutti i nodi del grafo e prendi solo i FIREWALL
        if (nfv.getGraphs() != null) {
            for (Graph graph : nfv.getGraphs().getGraph()) {
                for (Node node : graph.getNode()) {
                    if (node.getFunctionalType() == FunctionalTypes.FIREWALL) {

                        String ip = node.getName(); // es. "30.0.0.2"
                        Integer time = ipToTime.get(ip);
                        if (time == null && defaultTime != null) {
                            // firewall implicito -> usa il defaultTime della omega
                            time = defaultTime;
                        }

                        // crea elemento <firewall>
                        Element fwEl = doc.createElement("firewall");
                        fwEl.setAttribute("ip", ip);

                        // ora l’attributo si chiama "state" (non più "time")
                        if (time != null) {
                            fwEl.setAttribute("state", String.valueOf(time));
                        }

                        // attributo event preso dall'NFV
                        if (node.getEvent() != null) {
                            fwEl.setAttribute("event", node.getEvent().value());
                        }

                        root.appendChild(fwEl);
                    }
                }
            }
        }

        return doc;
    }
}
