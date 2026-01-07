package com.ids;

import com.ids.backend.PredictionClient;
import com.ids.model.NetworkFeatures;
import com.ids.packet.PacketFeatureExtractor;
import org.pcap4j.core.*;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import java.io.Closeable;
import java.io.IOException;
import java.net.InetAddress;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeoutException;

public class NetworkTrafficAnalyzer implements Closeable {
    private static final Logger logger = LoggerFactory.getLogger(NetworkTrafficAnalyzer.class);

    private PcapHandle handle;
    private final String networkInterface;
    private final PredictionClient predictionClient;
    private final ExecutorService executorService;
    private volatile boolean isRunning = false;
    private Thread captureThread;
    JTextArea outputLog;
    JLabel capturedCountLabel;
    JLabel normalCountLabel;
    JLabel attackCountLabel;
    Action logAction;

    private static final String BACKEND_URL = "http://localhost:8888/predict";
    private static final int PACKET_COUNT = -1; // Capture unlimited packets
    private static final int READ_TIMEOUT = 1000; // milliseconds - increased for responsiveness
    private static final int THREAD_POOL_SIZE = 4;

    public NetworkTrafficAnalyzer(String interfaceName) throws PcapNativeException {
        this.networkInterface = interfaceName;
        this.predictionClient = new PredictionClient(BACKEND_URL);
        this.executorService = Executors.newFixedThreadPool(THREAD_POOL_SIZE);

        // Setup packet capture
        logger.info("INIT: locating interface...");
        PcapNetworkInterface nif = Pcaps.getDevByName(interfaceName);
        if (nif == null) {
            throw new PcapNativeException("Interface not found: " + interfaceName);
        }
        logger.info("INIT: interface found");

        logger.info("INIT: opening handle...");
        this.handle = nif.openLive(
                65536,                          // Snapshot length
                PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
                READ_TIMEOUT
        );
        logger.info("INIT: handle opened OK");

        logger.info("Opened interface: {} ({})", interfaceName, nif.getDescription());

        // Warn if using virtual adapter
        if (interfaceName.contains("Virtual")) {
            logger.warn("WARNING: Using virtual adapter. May not capture packets. Consider using a physical network adapter.");
        }
    }

    /**
     * Start capturing packets (in separate thread)
     */
    public void start() {

        if (isRunning) {
            logger.warn("Capture already running");
            return;
        }

        isRunning = true;

        captureThread = new Thread(() -> {
            try {
                logger.info("CAPTURE LOOP START");

                handle.loop(-1, (PacketListener) packet ->
                        executorService.execute(() -> processPacket(packet))
                );


            } catch (InterruptedException e) {
                logger.info("Capture thread interrupted");
            } catch (PcapNativeException | NotOpenException e) {
                logger.error("Capture error", e);
            } finally {
                isRunning = false;
                logger.info("CAPTURE LOOP END");
            }

        }, "PacketCaptureThread");

        captureThread.start();
    }

    /**
     * Process individual packet
     */
    private void processPacket(Packet packet) {
        try {
            // Check if it's an IPv4 packet
            IpV4Packet ipPacket = packet.get(IpV4Packet.class);
            if (ipPacket == null) return;

//            IpV4Packet ipPacket = (IpV4Packet) packet;

            // Extract source/destination IPs
            String srcIp = PacketFeatureExtractor.extractSrcIp(ipPacket);
            String dstIp = PacketFeatureExtractor.extractDstIp(ipPacket);

            logger.debug("Packet captured: {} -> {}", srcIp, dstIp);

            // Extract features từ packet
            NetworkFeatures features = PacketFeatureExtractor.extractFeatures(ipPacket);

            if (features == null) {
                logger.warn("Failed to extract features from packet");
                return;
            }

            // Log extracted features
            logger.info("Extracted features - Protocol: {}, Service: {}, Src Bytes: {}, Dst Bytes: {}",
                    features.getProtocolType(),
                    features.getService(),
                    features.getSrcBytes(),
                    features.getDstBytes());

            // Send to backend for prediction
            sendPredictionRequest(features, srcIp, dstIp);

        } catch (Exception e) {
            logger.error("Error processing packet: {}", e.getMessage(), e);
        }
    }

    /**
     * Send prediction request to backend
     */
    private void sendPredictionRequest(NetworkFeatures features, String srcIp, String dstIp) {
        try {
            PredictionClient.PredictionResult result = predictionClient.predict(features);

            if (result != null) {
                logPredictionResult(srcIp, dstIp, result);
            } else {
                logger.warn("No prediction result from backend");
            }
        } catch (Exception e) {
            logger.error("Error sending prediction request: {}", e.getMessage(), e);
        }
    }

    int capturedCount = 0;
    int normalCount = 0;
    int attackCount = 0;
    /**
     * Log prediction result
     */
    private void logPredictionResult(String srcIp, String dstIp,
                                     PredictionClient.PredictionResult result) {
        String logLevel = "attack".equalsIgnoreCase(result.getPredictionLabel()) ? "ALERT" : "INFO";
        capturedCount++;
        String message = String.format(
                "[%s] Packet #%s Traffic from %s to %s | Prediction: %s | Confidence: %.2f%%",
                logLevel,
                capturedCount,
                srcIp,
                dstIp,
                result.getPredictionLabel().toUpperCase(),
                result.getConfidence() * 100
        );


        if (logAction != null) {
            logAction.run(message);
//            if ("attack".equalsIgnoreCase(result.getPredictionLabel())) {
//                attackCount++;
//                attackCountLabel.setText("Attack: " + attackCount);
//            } else {
//                normalCount++;
//                normalCountLabel.setText("Normal: " + normalCount);
//            }
//            capturedCountLabel.setText("Captured: " + capturedCount);
        }

        if ("attack".equalsIgnoreCase(result.getPredictionLabel())) {
            logger.error("{} | Attack Type: {}", message);
        } else {
            logger.info(message);
        }
    }

    /**
     * Stop capturing packets
     */
    public void stop() {

        if (!isRunning) return;

        logger.info("Stopping capture...");
        isRunning = false;

        try {
            if (handle != null && handle.isOpen()) {
                handle.breakLoop();
                handle.close();
            }

            if (captureThread != null) {
                captureThread.join(2000);
            }

            executorService.shutdownNow();

        } catch (Exception e) {
            logger.error("Stop error", e);
        }

        logger.info("Stopped.");
    }

    /**
     * List available network interfaces
     */
    public static String listInterfaces() throws PcapNativeException {
        List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
        StringBuilder o = new StringBuilder();
        if (allDevs.isEmpty()) {
            o.append("No network interfaces found!");
            System.out.println(o);
            return o.toString();
        }

        o.append("\n=== Available Network Interfaces ===");
        System.out.println("\n=== Available Network Interfaces ===");
        for (int i = 0; i < allDevs.size(); i++) {
            PcapNetworkInterface device = allDevs.get(i);
            o.append("\n" + (i + 1) + ". " + device.getName());
            System.out.println((i + 1) + ". " + device.getName());

            if (device.getDescription() != null) {
                o.append("\n   " + device.getDescription());
                System.out.println("   " + device.getDescription());
            }
            if (!device.getAddresses().isEmpty()) {
                o.append("\n   Addresses: ");
                System.out.print("   Addresses: ");
                device.getAddresses().forEach(addr -> {
                    o.append(addr.getAddress().getHostAddress() + " ");
                    System.out.print(addr.getAddress().getHostAddress() + " ");
                });
                o.append("\n");
                System.out.println();
            }
        }
        o.append("====================================\n");
        System.out.println("====================================\n");
        return o.toString();
    }

    private void reinitializeHandle() throws PcapNativeException {
        if (handle != null && handle.isOpen()) {
            return;
        }

        PcapNetworkInterface nif = Pcaps.getDevByName(networkInterface);
        if (nif == null) {
            throw new PcapNativeException("Interface not found: " + networkInterface);
        }

        handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
        logger.info("Handle reinitialized for interface: {}", networkInterface);
    }

    @Override
    public void close() throws IOException {
        stop();
    }

    /**
     * Main entry point
     */
    public static void main(String[] args) {
        try {
            // If no arguments, list interfaces
            if (args.length == 0) {
                System.out.println("Usage: java NetworkTrafficAnalyzer <interface_name>");
                System.out.println("Example: java NetworkTrafficAnalyzer eth0\n");
                listInterfaces();
                return;
            }

            String interfaceName = args[0];


            try {
                // Create analyzer
                NetworkTrafficAnalyzer analyzer = new NetworkTrafficAnalyzer(interfaceName);

                // Add shutdown hook
                Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                    System.out.println("\n\nShutting down...");
                    analyzer.stop();
                }));

                logger.info("========== Network Traffic Analyzer Started ==========");
                logger.info("Interface: {}", interfaceName);
                logger.info("Backend URL: {}", BACKEND_URL);
                logger.info("Thread Pool Size: {}", THREAD_POOL_SIZE);
                logger.info("========================================================");

                // Start capturing (non-blocking)
                analyzer.start();

                // Keep main thread alive
                System.out.println("Packet capture running. Press Ctrl+C to stop.\n");

                synchronized (NetworkTrafficAnalyzer.class) {
                    NetworkTrafficAnalyzer.class.wait();
                }
            } catch (Exception e) {
                logger.error("Main thread interrupted: {}", e.getMessage(), e);
            }

        } catch (PcapNativeException e) {
            logger.error("Pcap error: {}", e.getMessage());
            System.err.println("Make sure you have the required permissions (run with sudo on Linux/Mac)");
            System.exit(1);
        } catch (Exception e) {
            logger.error("Fatal error: {}", e.getMessage(), e);
            System.exit(1);
        }
    }

    public static void startCapture(String iName, int packageCount) {
        try {
            String interfaceName = iName;

            try {
                // Create analyzer
                NetworkTrafficAnalyzer analyzer = new NetworkTrafficAnalyzer(interfaceName);

                // Add shutdown hook
                Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                    System.out.println("\n\nShutting down...");
                    analyzer.stop();
                }));

                logger.info("========== Network Traffic Analyzer Started ==========");
                logger.info("Interface: {}", interfaceName);
                logger.info("Backend URL: {}", BACKEND_URL);
                logger.info("Thread Pool Size: {}", THREAD_POOL_SIZE);
                logger.info("========================================================");

                // Start capturing (non-blocking)
                analyzer.start();

                // Keep main thread alive
                System.out.println("Packet capture running. Press Ctrl+C to stop.\n");

                synchronized (NetworkTrafficAnalyzer.class) {
                    NetworkTrafficAnalyzer.class.wait();
                }
            } catch (Exception e) {
                logger.error("Main thread interrupted: {}", e.getMessage(), e);
            }

        } catch (Exception e) {
            logger.error("Fatal error: {}", e.getMessage(), e);
            System.exit(1);
        }
    }

    public void start(JTextArea outputLog, int maxPackets, JLabel capturedCountLabel, JLabel normalCountLabel, JLabel attackCountLabel,Action logAction) {
        this.outputLog = outputLog;
        this.logAction = logAction;
        this.capturedCountLabel = capturedCountLabel;
        this.normalCountLabel = normalCountLabel;
        this.attackCountLabel = attackCountLabel;

        appendToLog("Starting...");
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            appendToLog("\n\nShutting down...");
            stop();
        }));
        appendToLog("========== Network Traffic Analyzer Started ==========");
//        logger.info("Interface: {}", interfaceName);
        appendToLog("Backend URL: " + BACKEND_URL);
        appendToLog("Thread Pool Size: " + THREAD_POOL_SIZE);
        appendToLog("========================================================");



        if (isRunning) {
            appendToLog("Capture already running");
            return;
        }

        isRunning = true;

        captureThread = new Thread(() -> {
            try {
                appendToLog("CAPTURE LOOP START");

                handle.loop(-1, (PacketListener) packet ->
                        executorService.execute(() -> processPacket(packet))
                );

            } catch (InterruptedException e) {
                appendToLog("Capture thread interrupted");
            } catch (PcapNativeException | NotOpenException e) {
                appendToLog("Capture error" + e.getMessage());
            } finally {
                isRunning = false;
                appendToLog("CAPTURE LOOP END");
            }

        }, "PacketCaptureThread2");

        captureThread.start();

//        synchronized (NetworkTrafficAnalyzer.class) {
//            try {
//                NetworkTrafficAnalyzer.class.wait();
//            } catch (InterruptedException e) {
//                logger.error("Capture simulation interrupted", e);
////                throw new RuntimeException(e);
//            }
//        }
    }

    /**
     * Appends a message to the output log
     *
     * @param message The message to append
     */
    private void appendToLog(String message) {
        if (outputLog == null) return;
        outputLog.append(message + "\n");
        outputLog.setCaretPosition(outputLog.getDocument().getLength());
    }
}
