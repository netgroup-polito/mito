package it.polito.mito.translator;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Z3OmegaParser {

    public static class OmegaResult {
        private final Map<String, Integer> ipToTime;
        private final Integer defaultTime;

        public OmegaResult(Map<String, Integer> ipToTime, Integer defaultTime) {
            this.ipToTime = ipToTime;
            this.defaultTime = defaultTime;
        }

        public Map<String, Integer> getIpToTime() {
            return ipToTime;
        }

        public Integer getDefaultTime() {
            return defaultTime;
        }
    }

    /**
     * Estrae la funzione (define-fun omega ...) dal testo Z3 e la converte
     * in una mappa IP -> stato (tempo) + un defaultTime per il firewall implicito.
     */
    public OmegaResult parseOmega(String z3Output) {
        // 1) Isola il blocco di definizione di omega.
        //    Prendiamo tutto da "Time" fino al prossimo "(define-fun" o fine file.
        Pattern omegaBlockPattern = Pattern.compile(
                "\\(define-fun\\s+omega\\s*\\(.*?\\)\\s*Time(.*?)(?=\\(define-fun|\\Z)",
                Pattern.DOTALL
        );
        Matcher blockMatcher = omegaBlockPattern.matcher(z3Output);
        if (!blockMatcher.find()) {
            throw new IllegalArgumentException("Blocco (define-fun omega ...) non trovato nel testo Z3.");
        }

        String body = blockMatcher.group(1);

        // 2) Troviamo tutte le righe "ite" del tipo:
        //    (ite (= x!0 QUALCOSA) |N| ...)
        //
        // Non ci fissiamo sul prefisso "Event_FW_" ma prendiamo QUALCOSA e poi,
        // da QUALCOSA, estraiamo un IP del tipo 30.0.0.2.
        Pattern itePattern = Pattern.compile(
                "\\(ite\\s*\\(=\\s*x!0\\s+([^\\s\\)]+)\\)\\s*\\|([0-9]+)\\|",
                Pattern.DOTALL
        );

        Map<String, Integer> ipToTime = new LinkedHashMap<>();
        Matcher iteMatcher = itePattern.matcher(body);
        Pattern ipPattern = Pattern.compile("([0-9]+(?:\\.[0-9]+){3})"); // match tipo 30.0.0.2

        while (iteMatcher.find()) {
            String eventSymbol = iteMatcher.group(1);     // es. Event_FW_30.0.0.2
            String timeStr     = iteMatcher.group(2);     // es. "1"

            // Estrai un IP da eventSymbol
            Matcher ipMatcher = ipPattern.matcher(eventSymbol);
            if (!ipMatcher.find()) {
                // nessun IP trovato, saltiamo questa entry
                continue;
            }

            String ip = ipMatcher.group(1);               // es. 30.0.0.2
            Integer time = Integer.valueOf(timeStr);

            ipToTime.put(ip, time);
        }

        /*if (ipToTime.isEmpty()) {
            throw new IllegalArgumentException(
                    "Nessun mapping Event_* con IP trovato nella funzione omega. " +
                    "Controlla il formato degli eventi nel modello Z3."
            );
        }*/

        // 3) defaultTime = ultimo numero tra |...| nel corpo di omega
        Integer defaultTime = extractLastBarNumber(body);

        return new OmegaResult(ipToTime, defaultTime);
    }

    /**
     * Estrae l'ultimo numero tra | e | dal testo.
     * Esempio: "... |1| ... |2| ... |3|)))" -> 3
     */
    private Integer extractLastBarNumber(String text) {
        int lastBar = text.lastIndexOf('|');
        if (lastBar < 0) {
            return null;
        }
        int prevBar = text.lastIndexOf('|', lastBar - 1);
        if (prevBar < 0) {
            return null;
        }
        String numberStr = text.substring(prevBar + 1, lastBar).trim();
        try {
            return Integer.valueOf(numberStr);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(
                    "Impossibile parsare il defaultTime tra '|' nel corpo di omega: '" +
                    numberStr + "'", e
            );
        }
    }
}
