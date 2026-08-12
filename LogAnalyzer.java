import java.io.IOException;
import java.util.ArrayList;

public class LogAnalyzer {

    public static void main(String[] args) {

        String fileName = "server.log";

        LogParser parser = new LogParser();

        try {

            ArrayList<LogEntry> entries =
                    parser.parseFile(fileName);

            SecurityAnalyzer analyzer =
                    new SecurityAnalyzer(entries);

            analyzer.analyze();

            AnalysisReport report =
                    new AnalysisReport(analyzer);

            report.printReport();

        } catch (IOException e) {

            System.out.println(
                    "Unable to read log file: "
                    + e.getMessage()
            );
        }
    }
}
