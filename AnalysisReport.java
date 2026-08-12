import java.util.Map;

public class AnalysisReport {

    private SecurityAnalyzer analyzer;

    /**
     * Creates an AnalysisReport.
     *
     * @param analyzer security analyzer containing analysis results
     */
    public AnalysisReport(SecurityAnalyzer analyzer) {
        this.analyzer = analyzer;
    }

    /**
     * Prints the complete security analysis report.
     */
    public void printReport() {

        System.out.println();
        System.out.println("========================================");
        System.out.println("        SECURITY LOG ANALYZER");
        System.out.println("========================================");

        System.out.println();

        System.out.println("Total Log Entries:     "
                + analyzer.getTotalEntries());

        System.out.println("Successful Logins:     "
                + analyzer.getSuccessfulLogins());

        System.out.println("Failed Logins:         "
                + analyzer.getFailedLogins());

        System.out.println("Errors:                "
                + analyzer.getErrors());

        System.out.println();

        System.out.println("----------------------------------------");
        System.out.println("       FAILED LOGINS BY IP");
        System.out.println("----------------------------------------");

        for (Map.Entry<String, Integer> entry :
                analyzer.getFailedLoginsByIP().entrySet()) {

            System.out.println(
                    entry.getKey()
                    + " -> "
                    + entry.getValue()
                    + " failed attempts"
            );
        }

        System.out.println();

        System.out.println("----------------------------------------");
        System.out.println("       FAILED LOGINS BY USER");
        System.out.println("----------------------------------------");

        for (Map.Entry<String, Integer> entry :
                analyzer.getFailedLoginsByUser().entrySet()) {

            System.out.println(
                    entry.getKey()
                    + " -> "
                    + entry.getValue()
                    + " failed attempts"
            );
        }

        System.out.println();

        System.out.println("----------------------------------------");
        System.out.println("       SECURITY ALERTS");
        System.out.println("----------------------------------------");

        int alerts = 0;

        for (Map.Entry<String, Integer> entry :
                analyzer.getFailedLoginsByIP().entrySet()) {

            int attempts = entry.getValue();

            if (attempts >= 5) {

                System.out.println(
                        "[HIGH] Possible brute-force attack"
                );

                System.out.println(
                        "IP: " + entry.getKey()
                        + " | Failed Attempts: " + attempts
                );

                alerts++;
            }

            else if (attempts >= 3) {

                System.out.println(
                        "[MEDIUM] Multiple failed login attempts"
                );

                System.out.println(
                        "IP: " + entry.getKey()
                        + " | Failed Attempts: " + attempts
                );

                alerts++;
            }
        }

        if (alerts == 0) {
            System.out.println("No suspicious activity detected.");
        }

        System.out.println();

        System.out.println("----------------------------------------");
        System.out.println("       ANALYSIS SUMMARY");
        System.out.println("----------------------------------------");

        System.out.println(
                "Most Suspicious IP: "
                + analyzer.getMostSuspiciousIP()
        );

        System.out.println(
                "Most Targeted User: "
                + analyzer.getMostTargetedUser()
        );

        System.out.println(
                "Security Alerts: "
                + alerts
        );

        System.out.println();
        System.out.println("========================================");
    }
}
