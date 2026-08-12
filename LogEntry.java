public class LogEntry {

    private String timestamp;
    private String level;
    private String event;
    private String username;
    private String ipAddress;


    /**
      * Creates a log entry object 
      *
      * @param timestamp timestamp of the event 
      * @param level security level
      * @param event type of event 
      * @param username username of the involved event 
      * @param ipAddress IP address of the involved event 
      */
    public LogEntry(String timestamp, String level, String event, String username, String ipAddress) {

        this.timestamp = timestamp;
        this.level = level;
        this.event = event;
        this.username = username;
        this.ipAddress = ipAddress;
    } 

    public String getTimestamp() {
        return timestamp;
    }

    public String getLevel() {
        return level;
    }

    public String getEvent() {
        return event;
    }

    public String getUsername() {
        return username;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public String toString() {
        return timestamp + " " + level + " " + event 
            + "user= " + username 
            + " ip= " + ipAddress;
    }
}
