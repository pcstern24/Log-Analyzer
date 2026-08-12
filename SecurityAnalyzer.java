import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class SecurityAnalyzer {

    private ArrayList<LogEntry> entries;

    private HashMap<String, Integer> failedLoginsByIP;
    private HashMap<String, Integer> failedLoginsByUser;

    private int successfulLogins;
    private int failedLogins;
    private int errors;

    /**
     * Creates a SecurityAnalyzer.
     *
     * @param entries list of log entries
     */
    public SecurityAnalyzer(ArrayList<LogEntry> entries) {

        this.entries = entries;

        failedLoginsByIP = new HashMap<>();
        failedLoginsByUser = new HashMap<>();

        successfulLogins = 0;
        failedLogins = 0;
        errors = 0;
    }

    /**
     * Analyzes all log entries.
     */
    public void analyze() {

        for (LogEntry entry : entries) {

            if (entry == null) {
                continue;
            }

            String event = entry.getEvent();

            if (event.equals("Login successful")) {
                successfulLogins++;
            }

            if (event.equals("Failed login")) {

                failedLogins++;

                String ip = entry.getIpAddress();
                String username = entry.getUsername();

                failedLoginsByIP.put(
                        ip,
                        failedLoginsByIP.getOrDefault(ip, 0) + 1
                );

                failedLoginsByUser.put(
                        username,
                        failedLoginsByUser.getOrDefault(username, 0) + 1
                );
            }

            if (entry.getLevel().equals("ERROR")) {
                errors++;
            }
        }
    }

    public int getTotalEntries() {
        return entries.size();
    }

    public int getSuccessfulLogins() {
        return successfulLogins;
    }

    public int getFailedLogins() {
        return failedLogins;
    }

    public int getErrors() {
        return errors;
    }

    public HashMap<String, Integer> getFailedLoginsByIP() {
        return failedLoginsByIP;
    }

    public HashMap<String, Integer> getFailedLoginsByUser() {
        return failedLoginsByUser;
    }

    /**
     * Returns the IP address with the most failed login attempts.
     *
     * @return most active suspicious IP
     */
    public String getMostSuspiciousIP() {

        String suspiciousIP = "None";
        int highestCount = 0;

        for (Map.Entry<String, Integer> entry : failedLoginsByIP.entrySet()) {

            if (entry.getValue() > highestCount) {

                highestCount = entry.getValue();
                suspiciousIP = entry.getKey();
            }
        }

        return suspiciousIP;
    }

    /**
     * Returns the username with the most failed login attempts.
     *
     * @return most targeted username
     */
    public String getMostTargetedUser() {

        String targetedUser = "None";
        int highestCount = 0;

        for (Map.Entry<String, Integer> entry : failedLoginsByUser.entrySet()) {

            if (entry.getValue() > highestCount) {

                highestCount = entry.getValue();
                targetedUser = entry.getKey();
            }
        }

        return targetedUser;
    }

    /**
     * Determines whether an IP should be considered suspicious.
     *
     * @param ipAddress IP address to check
     * @param threshold number of failed attempts required
     * @return true if the IP exceeds the threshold
     */
    public boolean isSuspiciousIP(String ipAddress, int threshold) {

        return failedLoginsByIP.getOrDefault(ipAddress, 0) >= threshold;
    }
}
