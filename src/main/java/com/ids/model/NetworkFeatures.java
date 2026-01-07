package com.ids.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class NetworkFeatures {
    @JsonProperty("duration")
    private int duration;

    @JsonProperty("protocol_type")
    private String protocolType; // "tcp", "udp", "icmp"

    @JsonProperty("service")
    private String service; // "http", "ftp", "ssh", etc.

    @JsonProperty("flag")
    private String flag; // "S0", "S1", "S2", "S3", "SF", "REJ", etc.

    @JsonProperty("src_bytes")
    private long srcBytes;

    @JsonProperty("dst_bytes")
    private long dstBytes;

    @JsonProperty("land")
    private int land; // 0 or 1 - same src/dst IP

    @JsonProperty("wrong_fragment")
    private int wrongFragment; // number of wrong fragments

    @JsonProperty("urgent")
    private int urgent; // number of urgent packets

    @JsonProperty("hot")
    private int hot; // number of "hot" indicators

    @JsonProperty("num_failed_logins")
    private int numFailedLogins;

    @JsonProperty("logged_in")
    private int loggedIn; // 0 or 1

    @JsonProperty("num_compromised")
    private int numCompromised; // number of compromised conditions

    @JsonProperty("root_shell")
    private int rootShell; // 0 or 1

    @JsonProperty("su_attempted")
    private int suAttempted; // 0 or 1

    @JsonProperty("num_root")
    private int numRoot; // number of root accesses

    // Constructor
    public NetworkFeatures() {}

    public NetworkFeatures(int duration, String protocolType, String service, String flag,
                           long srcBytes, long dstBytes, int land, int wrongFragment,
                           int urgent, int hot, int numFailedLogins, int loggedIn,
                           int numCompromised, int rootShell, int suAttempted, int numRoot) {
        this.duration = duration;
        this.protocolType = protocolType;
        this.service = service;
        this.flag = flag;
        this.srcBytes = srcBytes;
        this.dstBytes = dstBytes;
        this.land = land;
        this.wrongFragment = wrongFragment;
        this.urgent = urgent;
        this.hot = hot;
        this.numFailedLogins = numFailedLogins;
        this.loggedIn = loggedIn;
        this.numCompromised = numCompromised;
        this.rootShell = rootShell;
        this.suAttempted = suAttempted;
        this.numRoot = numRoot;
    }

    // Getters & Setters
    public int getDuration() { return duration; }
    public void setDuration(int duration) { this.duration = duration; }

    public String getProtocolType() { return protocolType; }
    public void setProtocolType(String protocolType) { this.protocolType = protocolType; }

    public String getService() { return service; }
    public void setService(String service) { this.service = service; }

    public String getFlag() { return flag; }
    public void setFlag(String flag) { this.flag = flag; }

    public long getSrcBytes() { return srcBytes; }
    public void setSrcBytes(long srcBytes) { this.srcBytes = srcBytes; }

    public long getDstBytes() { return dstBytes; }
    public void setDstBytes(long dstBytes) { this.dstBytes = dstBytes; }

    public int getLand() { return land; }
    public void setLand(int land) { this.land = land; }

    public int getWrongFragment() { return wrongFragment; }
    public void setWrongFragment(int wrongFragment) { this.wrongFragment = wrongFragment; }

    public int getUrgent() { return urgent; }
    public void setUrgent(int urgent) { this.urgent = urgent; }

    public int getHot() { return hot; }
    public void setHot(int hot) { this.hot = hot; }

    public int getNumFailedLogins() { return numFailedLogins; }
    public void setNumFailedLogins(int numFailedLogins) { this.numFailedLogins = numFailedLogins; }

    public int getLoggedIn() { return loggedIn; }
    public void setLoggedIn(int loggedIn) { this.loggedIn = loggedIn; }

    public int getNumCompromised() { return numCompromised; }
    public void setNumCompromised(int numCompromised) { this.numCompromised = numCompromised; }

    public int getRootShell() { return rootShell; }
    public void setRootShell(int rootShell) { this.rootShell = rootShell; }

    public int getSuAttempted() { return suAttempted; }
    public void setSuAttempted(int suAttempted) { this.suAttempted = suAttempted; }

    public int getNumRoot() { return numRoot; }
    public void setNumRoot(int numRoot) { this.numRoot = numRoot; }

    @Override
    public String toString() {
        return "NetworkFeatures{" +
                "duration=" + duration +
                ", protocolType='" + protocolType + '\'' +
                ", service='" + service + '\'' +
                ", flag='" + flag + '\'' +
                ", srcBytes=" + srcBytes +
                ", dstBytes=" + dstBytes +
                ", land=" + land +
                '}';
    }
}