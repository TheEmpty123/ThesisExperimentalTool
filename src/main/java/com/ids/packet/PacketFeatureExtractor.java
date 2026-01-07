package com.ids.packet;

import com.ids.model.NetworkFeatures;
import org.pcap4j.packet.*;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.util.HashMap;
import java.util.Map;

public class PacketFeatureExtractor {
    private static final Logger logger = LoggerFactory.getLogger(PacketFeatureExtractor.class);

    // Service mapping theo port numbers
    private static final Map<Integer, String> PORT_TO_SERVICE = new HashMap<>();
    static {
        PORT_TO_SERVICE.put(20, "ftp-data");
        PORT_TO_SERVICE.put(21, "ftp");
        PORT_TO_SERVICE.put(22, "ssh");
        PORT_TO_SERVICE.put(23, "telnet");
        PORT_TO_SERVICE.put(25, "smtp");
        PORT_TO_SERVICE.put(53, "domain");
        PORT_TO_SERVICE.put(80, "http");
        PORT_TO_SERVICE.put(110, "pop3");
        PORT_TO_SERVICE.put(143, "imap4");
        PORT_TO_SERVICE.put(443, "https");
        PORT_TO_SERVICE.put(3306, "mysql");
        PORT_TO_SERVICE.put(5432, "postgres");
    }

    // TCP Flags mapping
    private static final Map<String, String> TCP_FLAGS = new HashMap<>();
    static {
        // S0: Connection established but not terminated
        // S1: Connection started
        // SF: Normal establishment and termination
        // REJ: Rejected connection
        // RSTO: Connection reset by originator
        // RSTR: Connection reset by responder
        // RSTOS0: Established, reset by originator
        // SH: Shutdown
    }

    /**
     * Extract features từ IP packet
     */
    public static NetworkFeatures extractFeatures(IpV4Packet ipPacket) {
        try {
            NetworkFeatures features = new NetworkFeatures();

            // IP Layer Info
            IpV4Packet.IpV4Header ipHeader = ipPacket.getHeader();
            features.setProtocolType(getProtocolType(ipHeader.getProtocol().name()));

            // Check Land Attack (same src/dst IP)
            if (ipHeader.getSrcAddr().equals(ipHeader.getDstAddr())) {
                features.setLand(1);
            } else {
                features.setLand(0);
            }

            // Extract bytes
            features.setSrcBytes(ipPacket.length());

            // TCP/UDP Layer
            Packet payload = ipPacket.getPayload();
            if (payload instanceof TcpPacket) {
                extractTcpFeatures(features, (TcpPacket) payload);
            } else if (payload instanceof UdpPacket) {
                extractUdpFeatures(features, (UdpPacket) payload);
            } else if (ipHeader.getProtocol().name().contains("ICMP")) {
                features.setService("icmp");
                features.setFlag("ICMP");
                features.setDuration(1);
            }

            // Default values for undetected features
            if (features.getDuration() == 0) {
                features.setDuration(1);
            }

            return features;

        } catch (Exception e) {
            logger.error("Error extracting features: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Extract TCP-specific features
     */
    private static void extractTcpFeatures(NetworkFeatures features, TcpPacket tcpPacket) {
        TcpPacket.TcpHeader tcpHeader = tcpPacket.getHeader();

        // Service mapping từ destination port
        int dstPort = tcpHeader.getDstPort().valueAsInt();
        String service = PORT_TO_SERVICE.getOrDefault(dstPort, String.valueOf(dstPort));
        features.setService(service);

        // Destination bytes
        Packet payload = tcpPacket.getPayload();
        if (payload != null) {
            features.setDstBytes(payload.length());
        } else {
            features.setDstBytes(0);
        }

        // TCP Flags
        String flags = extractTcpFlags(tcpHeader);
        features.setFlag(flags);

        // Duration (placeholder - thực tế cần tracking connection)
        features.setDuration(1);
    }

    /**
     * Extract UDP-specific features
     */
    private static void extractUdpFeatures(NetworkFeatures features, UdpPacket udpPacket) {
        UdpPacket.UdpHeader udpHeader = udpPacket.getHeader();

        int dstPort = udpHeader.getDstPort().valueAsInt();
        String service = PORT_TO_SERVICE.getOrDefault(dstPort, String.valueOf(dstPort));
        features.setService(service);

        // Payload size
        Packet payload = udpPacket.getPayload();
        if (payload != null) {
            features.setDstBytes(payload.length());
        } else {
            features.setDstBytes(0);
        }

        features.setFlag("UDP");
        features.setDuration(1);
    }

    /**
     * Extract TCP flag string từ TCP header
     */
    private static String extractTcpFlags(TcpPacket.TcpHeader tcpHeader) {
        StringBuilder flags = new StringBuilder();

        if (tcpHeader.getSyn()) flags.append("S");
        if (tcpHeader.getAck()) flags.append("A");
        if (tcpHeader.getFin()) flags.append("F");
        if (tcpHeader.getRst()) flags.append("R");
        if (tcpHeader.getPsh()) flags.append("P");
        if (tcpHeader.getUrg()) flags.append("U");

        if (flags.length() == 0) {
            return "0"; // No flags set
        }

        return flags.toString();
    }

    /**
     * Map protocol number to string
     */
    private static String getProtocolType(String protocolName) {
        if (protocolName.contains("TCP")) {
            return "tcp";
        } else if (protocolName.contains("UDP")) {
            return "udp";
        } else if (protocolName.contains("ICMP")) {
            return "icmp";
        }
        return protocolName.toLowerCase();
    }

    /**
     * Extract source IP
     */
    public static String extractSrcIp(IpV4Packet packet) {
        InetAddress srcAddr = packet.getHeader().getSrcAddr();
        return srcAddr != null ? srcAddr.getHostAddress() : "unknown";
    }

    /**
     * Extract destination IP
     */
    public static String extractDstIp(IpV4Packet packet) {
        InetAddress dstAddr = packet.getHeader().getDstAddr();
        return dstAddr != null ? dstAddr.getHostAddress() : "unknown";
    }
}
