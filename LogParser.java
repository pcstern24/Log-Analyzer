import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;

public class LogParser {

    /**
     * Reads a log file and converts each valid line into a LogEntry.
     *
     * @param fileName name of the log file
     * @return list of parsed log entries
     * @throws IOException if the file cannot be read
     */
    public ArrayList<LogEntry> parseFile(String fileName) throws IOException {

        ArrayList<LogEntry> entries = new ArrayList<>();

        try (BufferedReader reader = new BufferedReader(new FileReader(fileName))) {

            String line;

            while ((line = reader.readLine()) != null) {

                LogEntry entry = parseLine(line);

                if (entry != null) {
                    entries.add(entry);
                }
            }
        }

        return entries;
    }

    /**
     * Parses one line from the log file.
     *
     * @param line log line
     * @return LogEntry or null if the line cannot be parsed
     */
    private LogEntry parseLine(String line) {

        try {

            String[] parts = line.split(" ");

            // Minimum:
            // date time level event
            if (parts.length < 4) {
                return null;
            }

            String timestamp = parts[0] + " " + parts[1];
            String level = parts[2];

            StringBuilder eventBuilder = new StringBuilder();

            String username = "N/A";
            String ipAddress = "N/A";

            for (int i = 3; i < parts.length; i++) {

                String part = parts[i];

                if (part.startsWith("user=")) {

                    username = part.substring(5);

                } else if (part.startsWith("ip=")) {

                    ipAddress = part.substring(3);

                } else {

                    if (eventBuilder.length() > 0) {
                        eventBuilder.append(" ");
                    }

                    eventBuilder.append(part);
                }
            }

            String event = eventBuilder.toString();

            return new LogEntry(
                    timestamp,
                    level,
                    event,
                    username,
                    ipAddress
            );

        } catch (Exception e) {

            System.out.println("Could not parse log line:");
            System.out.println(line);

            return null;
        }
    }
}
