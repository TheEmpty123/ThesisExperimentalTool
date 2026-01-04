
import utils.LogObj;
import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.List;

/**
 * Main GUI for the Network Attack Detection Experimental Tool.
 * Provides interface for inputting test data, sending it to the Python Model Server,
 * and displaying prediction results with a modern dark theme interface.
 */
public class ExperimentalToolGUI extends JFrame {
    // Input form fields
    private JTextField durationField;
    private JTextField protocolTypeField;
    private JTextField serviceField;
    private JTextField flagField;
    private JTextField srcBytesField;
    private JTextField dstBytesField;
    private JTextField landField;
    private JTextField wrongFragmentField;
    private JTextField urgentField;
    private JTextField hotField;
    private JTextField numFailedLoginsField;
    private JTextField loggedInField;
    private JTextField numCompromisedField;
    private JTextField rootShellField;
    private JTextField suAttemptedField;
    private JTextField numRootField;
    private JTextField numFileCreationsField;
    private JTextField numShellsField;
    private JTextField numAccessFilesField;
    private JTextField numOutboundCmdsField;
    private JTextField isHostLoginField;
    private JTextField isGuestLoginField;
    private JTextField countField;
    private JTextField srvCountField;
    private JTextField serrorRateField;
    private JTextField srvSerrorRateField;
    private JTextField rerrorRateField;
    private JTextField srvRerrorRateField;
    private JTextField sameSrvRateField;
    private JTextField diffSrvRateField;
    private JTextField srvDiffHostRateField;
    private JTextField dstHostCountField;
    private JTextField dstHostSrvCountField;
    private JTextField dstHostSameSrvRateField;
    private JTextField dstHostDiffSrvRateField;
    private JTextField dstHostSameSrcPortRateField;
    private JTextField dstHostSrvDiffHostRateField;
    private JTextField dstHostSerrorRateField;
    private JTextField dstHostSrvSerrorRateField;
    private JTextField dstHostRerrorRateField;
    private JTextField dstHostSrvRerrorRateField;
    private JTextField labelField;

    // Results display components
    private JLabel resultLabel;
    private JLabel confidenceLabel;
    private JPanel probabilityBarPanel;
    private JLabel statusLabel;

    // Original components still needed
    private JTable resultsTable;
    private DefaultTableModel resultsTableModel;
    private JTextField serverUrlField;
    private ModelServerClient client;
    private List<PredictionResult> currentResults;

    // For batch processing dialog
    private JTextArea batchInputTextArea;
    private JRadioButton keyValueRadioButton;
    private JRadioButton csvRadioButton;

    // Menu items
    private JMenuItem importMenuItem;
    private JMenuItem exportMenuItem;
    private JMenuItem batchProcessMenuItem;

    // Logger
    private static final LogObj log = new LogObj("ExperimentalToolGUI");

    /**
     * Constructor - initializes the GUI components
     */
    public ExperimentalToolGUI() {

        log.info("Initializing Experimental Tool GUI");

        // Initialize the HTTP client
        client = new ModelServerClient();
        currentResults = new ArrayList<>();

        // Set up the frame
        setTitle("Network Attack Detection - Experimental Tool");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(1000, 700);
        setLocationRelativeTo(null);

        // Create menu bar
        setupMenuBar();

        // Create the main panel with a border layout
        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Create the server URL panel
        JPanel serverPanel = new JPanel(new BorderLayout(5, 0));

        // URL label and field
        JPanel urlPanel = new JPanel(new BorderLayout(5, 0));
        urlPanel.add(new JLabel("Python Model Server URL:"), BorderLayout.WEST);
        serverUrlField = new JTextField("http://localhost:8888/predict");
        urlPanel.add(serverUrlField, BorderLayout.CENTER);

        // Add health check button
        JButton healthCheckButton = new JButton("Check Server Health");
        healthCheckButton.addActionListener(e -> checkServerHealth());

        // Add components to server panel
        serverPanel.add(urlPanel, BorderLayout.CENTER);
        serverPanel.add(healthCheckButton, BorderLayout.EAST);

        // Create the input panel (left side)
        JPanel inputPanel = createInputPanel();

        // Create the result panel (right side)
        JPanel resultPanel = createResultPanel();

        // Create a horizontal split pane for input and result areas
        JSplitPane splitPane = new JSplitPane(
                JSplitPane.HORIZONTAL_SPLIT,
                inputPanel,
                resultPanel
        );
        splitPane.setResizeWeight(0.4); // 40% left, 60% right

        // Add all panels to the main panel
        mainPanel.add(serverPanel, BorderLayout.NORTH);
        mainPanel.add(splitPane, BorderLayout.CENTER);

        // Add the main panel to the frame
        add(mainPanel);
    }

    /**
     * Sets up the menu bar with File and Tools menus
     */
    private void setupMenuBar() {

        log.info("Setting up menu bar");

        JMenuBar menuBar = new JMenuBar();

        // File menu
        JMenu fileMenu = new JMenu("File");
        importMenuItem = new JMenuItem("Import CSV to Batch Table...");
        importMenuItem.addActionListener(e -> loadFromFile());
        exportMenuItem = new JMenuItem("Export Results...");
        exportMenuItem.addActionListener(e -> exportResults());
        exportMenuItem.setEnabled(false);

        fileMenu.add(importMenuItem);
        fileMenu.add(exportMenuItem);

        // Tools menu
        JMenu toolsMenu = new JMenu("Tools");
        batchProcessMenuItem = new JMenuItem("Batch Process Viewer");
        batchProcessMenuItem.addActionListener(e -> showBatchProcessDialog());

        toolsMenu.add(batchProcessMenuItem);

        // Add menus to menu bar
        menuBar.add(fileMenu);
        menuBar.add(toolsMenu);

        // Set the menu bar
        setJMenuBar(menuBar);
    }

    /**
     * Creates the input panel with a form for manual input
     * 
     * @return The input panel
     */
    private JPanel createInputPanel() {
        log.info("Creating input panel");

        JPanel inputPanel = new JPanel(new BorderLayout(5, 5));
        inputPanel.setBorder(BorderFactory.createTitledBorder("Manual Input Features"));

        // Create a form panel with GridBagLayout
        JPanel formPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);

        // Add form fields - important fields at the top
        int row = 0;

        // Duration
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Duration:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        durationField = new JTextField("0");
        formPanel.add(durationField, gbc);
        row++;

        // Protocol Type
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Protocol Type:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        protocolTypeField = new JTextField("tcp");
        formPanel.add(protocolTypeField, gbc);
        row++;

        // Service
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Service:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        serviceField = new JTextField("http");
        formPanel.add(serviceField, gbc);
        row++;

        // Flag
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Flag:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        flagField = new JTextField("SF");
        formPanel.add(flagField, gbc);
        row++;

        // Source Bytes
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Source Bytes:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        srcBytesField = new JTextField("1000");
        formPanel.add(srcBytesField, gbc);
        row++;

        // Destination Bytes
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Destination Bytes:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        dstBytesField = new JTextField("2000");
        formPanel.add(dstBytesField, gbc);
        row++;

        // Land
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Land:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        landField = new JTextField("0");
        formPanel.add(landField, gbc);
        row++;

        // Wrong Fragment
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Wrong Fragment:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        wrongFragmentField = new JTextField("0");
        formPanel.add(wrongFragmentField, gbc);
        row++;

        // Urgent
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Urgent:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        urgentField = new JTextField("0");
        formPanel.add(urgentField, gbc);
        row++;

        // Hot
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Hot:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        hotField = new JTextField("0");
        formPanel.add(hotField, gbc);
        row++;

        // Num Failed Logins
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Num Failed Logins:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        numFailedLoginsField = new JTextField("0");
        formPanel.add(numFailedLoginsField, gbc);
        row++;

        // Logged In
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Logged In:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        loggedInField = new JTextField("0");
        formPanel.add(loggedInField, gbc);
        row++;

        // Num Compromised
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Num Compromised:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        numCompromisedField = new JTextField("0");
        formPanel.add(numCompromisedField, gbc);
        row++;

        // Root Shell
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Root Shell:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        rootShellField = new JTextField("0");
        formPanel.add(rootShellField, gbc);
        row++;

        // Su Attempted
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Su Attempted:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        suAttemptedField = new JTextField("0");
        formPanel.add(suAttemptedField, gbc);
        row++;

        // Num Root
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Num Root:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        numRootField = new JTextField("0");
        formPanel.add(numRootField, gbc);
        row++;

        // Num File Creations
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Num File Creations:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        numFileCreationsField = new JTextField("0");
        formPanel.add(numFileCreationsField, gbc);
        row++;

        // Num Shells
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Num Shells:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        numShellsField = new JTextField("0");
        formPanel.add(numShellsField, gbc);
        row++;

        // Num Access Files
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Num Access Files:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        numAccessFilesField = new JTextField("0");
        formPanel.add(numAccessFilesField, gbc);
        row++;

        // Num Outbound Cmds
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Num Outbound Cmds:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        numOutboundCmdsField = new JTextField("0");
        formPanel.add(numOutboundCmdsField, gbc);
        row++;

        // Is Host Login
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Is Host Login:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        isHostLoginField = new JTextField("0");
        formPanel.add(isHostLoginField, gbc);
        row++;

        // Is Guest Login
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Is Guest Login:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        isGuestLoginField = new JTextField("0");
        formPanel.add(isGuestLoginField, gbc);
        row++;

        // Count
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Count:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        countField = new JTextField("0");
        formPanel.add(countField, gbc);
        row++;

        // Srv Count
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Srv Count:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        srvCountField = new JTextField("0");
        formPanel.add(srvCountField, gbc);
        row++;

        // Serror Rate
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Serror Rate:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        serrorRateField = new JTextField("0.0");
        formPanel.add(serrorRateField, gbc);
        row++;

        // Srv Serror Rate
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Srv Serror Rate:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        srvSerrorRateField = new JTextField("0.0");
        formPanel.add(srvSerrorRateField, gbc);
        row++;

        // Rerror Rate
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Rerror Rate:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        rerrorRateField = new JTextField("0.0");
        formPanel.add(rerrorRateField, gbc);
        row++;

        // Srv Rerror Rate
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Srv Rerror Rate:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        srvRerrorRateField = new JTextField("0.0");
        formPanel.add(srvRerrorRateField, gbc);
        row++;

        // Same Srv Rate
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Same Srv Rate:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        sameSrvRateField = new JTextField("0.0");
        formPanel.add(sameSrvRateField, gbc);
        row++;

        // Diff Srv Rate
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Diff Srv Rate:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        diffSrvRateField = new JTextField("0.0");
        formPanel.add(diffSrvRateField, gbc);
        row++;

        // Srv Diff Host Rate
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Srv Diff Host Rate:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        srvDiffHostRateField = new JTextField("0.0");
        formPanel.add(srvDiffHostRateField, gbc);
        row++;

        // Dst Host Count
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Dst Host Count:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        dstHostCountField = new JTextField("0");
        formPanel.add(dstHostCountField, gbc);
        row++;

        // Dst Host Srv Count
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Dst Host Srv Count:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        dstHostSrvCountField = new JTextField("0");
        formPanel.add(dstHostSrvCountField, gbc);
        row++;

        // Dst Host Same Srv Rate
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Dst Host Same Srv Rate:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        dstHostSameSrvRateField = new JTextField("0.0");
        formPanel.add(dstHostSameSrvRateField, gbc);
        row++;

        // Dst Host Diff Srv Rate
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Dst Host Diff Srv Rate:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        dstHostDiffSrvRateField = new JTextField("0.0");
        formPanel.add(dstHostDiffSrvRateField, gbc);
        row++;

        // Dst Host Same Src Port Rate
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Dst Host Same Src Port Rate:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        dstHostSameSrcPortRateField = new JTextField("0.0");
        formPanel.add(dstHostSameSrcPortRateField, gbc);
        row++;

        // Dst Host Srv Diff Host Rate
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Dst Host Srv Diff Host Rate:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        dstHostSrvDiffHostRateField = new JTextField("0.0");
        formPanel.add(dstHostSrvDiffHostRateField, gbc);
        row++;

        // Dst Host Serror Rate
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Dst Host Serror Rate:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        dstHostSerrorRateField = new JTextField("0.0");
        formPanel.add(dstHostSerrorRateField, gbc);
        row++;

        // Dst Host Srv Serror Rate
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Dst Host Srv Serror Rate:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        dstHostSrvSerrorRateField = new JTextField("0.0");
        formPanel.add(dstHostSrvSerrorRateField, gbc);
        row++;

        // Dst Host Rerror Rate
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Dst Host Rerror Rate:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        dstHostRerrorRateField = new JTextField("0.0");
        formPanel.add(dstHostRerrorRateField, gbc);
        row++;

        // Dst Host Srv Rerror Rate
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Dst Host Srv Rerror Rate:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        dstHostSrvRerrorRateField = new JTextField("0.0");
        formPanel.add(dstHostSrvRerrorRateField, gbc);
        row++;

        // Label
//        gbc.gridx = 0;
//        gbc.gridy = row;
//        gbc.weightx = 0.0;
//        formPanel.add(new JLabel("Label:"), gbc);
//
//        gbc.gridx = 1;
//        gbc.weightx = 1.0;
//        labelField = new JTextField("normal");
//        formPanel.add(labelField, gbc);
//        row++;

        // Add predict button
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(20, 5, 5, 5);

        JButton predictButton = new JButton("Predict Single");
        predictButton.setBackground(new Color(76, 175, 80)); // Green color
        predictButton.setForeground(Color.WHITE);
        predictButton.setFont(predictButton.getFont().deriveFont(Font.BOLD, 14f));
        predictButton.addActionListener(e -> predictSingle());

        formPanel.add(predictButton, gbc);

        // Create a scroll pane for the form panel
        JScrollPane scrollPane = new JScrollPane(formPanel);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);

        // Add scroll pane to input panel
        inputPanel.add(scrollPane, BorderLayout.CENTER);

        // Add a button to generate random input
        JButton generateRandomButton = new JButton("Generate Random Input");
        generateRandomButton.addActionListener(e -> generateRandomInput());

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonPanel.add(generateRandomButton);

        inputPanel.add(buttonPanel, BorderLayout.SOUTH);

        return inputPanel;
    }

    /**
     * Creates the result panel with visual dashboard
     * 
     * @return The result panel
     */
    private JPanel createResultPanel() {

        log.info("Creating result panel");

        JPanel resultPanel = new JPanel(new BorderLayout(5, 5));
        resultPanel.setBorder(BorderFactory.createTitledBorder("Visual Results Dashboard"));

        // Create a panel for the main result display
        JPanel dashboardPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();

        // Result label (large, centered)
        resultLabel = new JLabel("WAITING FOR PREDICTION", JLabel.CENTER);
        resultLabel.setFont(new Font("Arial", Font.BOLD, 36));
        resultLabel.setForeground(Color.GRAY);

        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(20, 10, 10, 10);
        dashboardPanel.add(resultLabel, gbc);

        // Confidence label
        confidenceLabel = new JLabel("Confidence: --", JLabel.CENTER);
        confidenceLabel.setFont(new Font("Arial", Font.PLAIN, 18));

        gbc.gridy = 1;
        gbc.insets = new Insets(0, 10, 20, 10);
        dashboardPanel.add(confidenceLabel, gbc);

        // Probability bar
        probabilityBarPanel = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                Graphics2D g2d = (Graphics2D) g.create();

                int width = getWidth();
                int height = getHeight();

                // Default 50/50 split
                double normalRatio = 0.5;

                // Draw background
                g2d.setColor(Color.DARK_GRAY);
                g2d.fillRect(0, 0, width, height);

                // Draw normal portion (green)
                g2d.setColor(new Color(76, 175, 80));
                g2d.fillRect(0, 0, (int)(width * normalRatio), height);

                // Draw attack portion (red)
                g2d.setColor(new Color(244, 67, 54));
                g2d.fillRect((int)(width * normalRatio), 0, (int)(width * (1 - normalRatio)), height);

                // Draw labels
                g2d.setColor(Color.WHITE);
                g2d.setFont(new Font("Arial", Font.BOLD, 12));

                String normalText = "NORMAL: 50%";
                String attackText = "ATTACK: 50%";

                FontMetrics fm = g2d.getFontMetrics();
                int normalTextWidth = fm.stringWidth(normalText);
                int attackTextWidth = fm.stringWidth(attackText);

                // Only draw text if there's enough space
                if (width * normalRatio > normalTextWidth + 10) {
                    g2d.drawString(normalText, 10, height / 2 + fm.getAscent() / 2);
                }

                if (width * (1 - normalRatio) > attackTextWidth + 10) {
                    g2d.drawString(attackText, (int)(width * normalRatio) + 10, height / 2 + fm.getAscent() / 2);
                }

                g2d.dispose();
            }
        };
        probabilityBarPanel.setPreferredSize(new Dimension(400, 40));

        gbc.gridy = 2;
        gbc.insets = new Insets(10, 30, 30, 30);
//        dashboardPanel.add(probabilityBarPanel, gbc);

        // Status bar at the bottom
        statusLabel = new JLabel("Ready", JLabel.LEFT);
        statusLabel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));

        // Add components to result panel
        resultPanel.add(dashboardPanel, BorderLayout.CENTER);
        resultPanel.add(statusLabel, BorderLayout.SOUTH);

        return resultPanel;
    }

    /**
     * Shows the batch process dialog
     */
    private void showBatchProcessDialog() {

        log.info("Showing batch process dialog");

        JDialog batchDialog = new JDialog(this, "Batch Process Viewer", true);
        batchDialog.setSize(800, 600);
        batchDialog.setLocationRelativeTo(this);

        JPanel dialogPanel = new JPanel(new BorderLayout(10, 10));
        dialogPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Input format selection
        JPanel formatPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        keyValueRadioButton = new JRadioButton("Key-Value Format", true);
        csvRadioButton = new JRadioButton("CSV Format");
        ButtonGroup formatGroup = new ButtonGroup();
        formatGroup.add(keyValueRadioButton);
        formatGroup.add(csvRadioButton);
        formatPanel.add(new JLabel("Input Format:"));
        formatPanel.add(keyValueRadioButton);
        formatPanel.add(csvRadioButton);

        // Text area for batch input
        batchInputTextArea = new JTextArea();
        batchInputTextArea.setLineWrap(true);
        batchInputTextArea.setWrapStyleWord(true);
        JScrollPane inputScrollPane = new JScrollPane(batchInputTextArea);
        inputScrollPane.setBorder(BorderFactory.createTitledBorder("Batch Input Data"));

        // Table for results
        String[] columnNames = {"Prediction", "Label", "Confidence", "Normal Prob", "Attack Prob", "Status"};
        resultsTableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        resultsTable = new JTable(resultsTableModel);
        resultsTable.setFillsViewportHeight(true);
        JScrollPane tableScrollPane = new JScrollPane(resultsTable);
        tableScrollPane.setBorder(BorderFactory.createTitledBorder("Batch Results"));

        // Button panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton loadButton = new JButton("Load from File");
        loadButton.addActionListener(e -> loadBatchFile());
        JButton processButton = new JButton("Process Batch");
        processButton.addActionListener(e -> processBatch());
        JButton exportButton = new JButton("Export Results");
        exportButton.addActionListener(e -> exportResults());

        buttonPanel.add(loadButton);
        buttonPanel.add(processButton);
        buttonPanel.add(exportButton);

        // Add components to dialog panel
        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.add(formatPanel, BorderLayout.NORTH);
        topPanel.add(inputScrollPane, BorderLayout.CENTER);

        JSplitPane splitPane = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT,
                topPanel,
                tableScrollPane
        );
        splitPane.setResizeWeight(0.5);

        dialogPanel.add(splitPane, BorderLayout.CENTER);
        dialogPanel.add(buttonPanel, BorderLayout.SOUTH);

        batchDialog.add(dialogPanel);
        batchDialog.setVisible(true);
    }

    /**
     * Loads a batch file for processing
     */
    private void loadBatchFile() {
        log.info("Loading batch file");

        JFileChooser fileChooser = new JFileChooser();

        // Set up file filters based on selected format
        if (csvRadioButton.isSelected()) {
            FileNameExtensionFilter csvFilter = new FileNameExtensionFilter("CSV Files (*.csv)", "csv");
            fileChooser.setFileFilter(csvFilter);
        } else {
            FileNameExtensionFilter txtFilter = new FileNameExtensionFilter("Text Files (*.txt)", "txt");
            fileChooser.setFileFilter(txtFilter);
        }

        int result = fileChooser.showOpenDialog(this);

        if (result == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            try {
                String content = Files.readString(selectedFile.toPath());
                batchInputTextArea.setText(content);

                // Auto-select the appropriate format based on file extension
                if (selectedFile.getName().toLowerCase().endsWith(".csv")) {
                    csvRadioButton.setSelected(true);
                }

                updateStatus("File loaded successfully: " + selectedFile.getName());
            } catch (IOException e) {
                showError("Error loading file", "Error loading file: " + e.getMessage());
                updateStatus("Error loading file: " + e.getMessage());
            }
        }
    }

    /**
     * Processes a batch of inputs
     */
    private void processBatch() {
        log.info("Processing batch process");

        String inputData = batchInputTextArea.getText().trim();
        String serverUrl = serverUrlField.getText().trim();

        if (inputData.isEmpty()) {
            showWarning("Empty Input", "Please enter test data or load it from a file.");
            return;
        }

        if (serverUrl.isEmpty()) {
            showWarning("Empty Server URL", "Please enter the Python Model Server URL.");
            return;
        }

        // Clear previous results
        clearResults();
        updateStatus("Starting batch processing...");

        // Use a SwingWorker to perform batch processing in the background
        SwingWorker<List<PredictionResult>, PredictionResult> worker = new SwingWorker<>() {
            @Override
            protected List<PredictionResult> doInBackground() throws Exception {
                List<PredictionResult> results = new ArrayList<>();

                if (csvRadioButton.isSelected()) {
                    // For CSV, create a temporary file and process it
                    File tempFile = File.createTempFile("batch_", ".csv");
                    try {
                        Files.writeString(tempFile.toPath(), inputData);
                        results = client.batchPredictFromCsv(serverUrl, tempFile);

                        // Publish results as they come in
                        for (PredictionResult result : results) {
                            publish(result);
                        }
                    } finally {
                        tempFile.delete();
                    }
                } else {
                    // For key-value format, split by lines and process each line
                    String[] lines = inputData.split("\n");
                    for (String line : lines) {
                        if (!line.trim().isEmpty()) {
                            PredictionResult result = client.predict(serverUrl, line);
                            results.add(result);
                            publish(result);
                        }
                    }
                }

                return results;
            }

            @Override
            protected void process(List<PredictionResult> chunks) {
                // Display results as they come in
                for (PredictionResult result : chunks) {
                    displayResult(result);
                }
            }

            @Override
            protected void done() {
                try {
                    currentResults = get();
                    updateStatus("Batch processing completed. Processed " + currentResults.size() + " items.");
                    exportMenuItem.setEnabled(!currentResults.isEmpty());
                } catch (Exception e) {
                    showError("Error", "Error during batch processing: " + e.getMessage());
                    updateStatus("Error: " + e.getMessage());
                }
            }
        };

        worker.execute();
    }

    /**
     * Predicts a single input from the form
     */
    private void predictSingle() {

        log.info("Predicting single input");

        String serverUrl = serverUrlField.getText().trim();

        if (serverUrl.isEmpty()) {
            showWarning("Empty Server URL", "Please enter the Python Model Server URL.");
            return;
        }

        // Create a map of features from the form fields
        Map<String, Object> features = new HashMap<>();

        // Add all fields to the features map
        features.put("duration", parseValue(durationField.getText()));
        features.put("protocol_type", protocolTypeField.getText());
        features.put("service", serviceField.getText());
        features.put("flag", flagField.getText());
        features.put("src_bytes", parseValue(srcBytesField.getText()));
        features.put("dst_bytes", parseValue(dstBytesField.getText()));
        features.put("land", parseValue(landField.getText()));
        features.put("wrong_fragment", parseValue(wrongFragmentField.getText()));
        features.put("urgent", parseValue(urgentField.getText()));
        features.put("hot", parseValue(hotField.getText()));
        features.put("num_failed_logins", parseValue(numFailedLoginsField.getText()));
        features.put("logged_in", parseValue(loggedInField.getText()));
        features.put("num_compromised", parseValue(numCompromisedField.getText()));
        features.put("root_shell", parseValue(rootShellField.getText()));
        features.put("su_attempted", parseValue(suAttemptedField.getText()));
        features.put("num_root", parseValue(numRootField.getText()));
        features.put("num_file_creations", parseValue(numFileCreationsField.getText()));
        features.put("num_shells", parseValue(numShellsField.getText()));
        features.put("num_access_files", parseValue(numAccessFilesField.getText()));
        features.put("num_outbound_cmds", parseValue(numOutboundCmdsField.getText()));
        features.put("is_host_login", parseValue(isHostLoginField.getText()));
        features.put("is_guest_login", parseValue(isGuestLoginField.getText()));
        features.put("count", parseValue(countField.getText()));
        features.put("srv_count", parseValue(srvCountField.getText()));
        features.put("serror_rate", parseValue(serrorRateField.getText()));
        features.put("srv_serror_rate", parseValue(srvSerrorRateField.getText()));
        features.put("rerror_rate", parseValue(rerrorRateField.getText()));
        features.put("srv_rerror_rate", parseValue(srvRerrorRateField.getText()));
        features.put("same_srv_rate", parseValue(sameSrvRateField.getText()));
        features.put("diff_srv_rate", parseValue(diffSrvRateField.getText()));
        features.put("srv_diff_host_rate", parseValue(srvDiffHostRateField.getText()));
        features.put("dst_host_count", parseValue(dstHostCountField.getText()));
        features.put("dst_host_srv_count", parseValue(dstHostSrvCountField.getText()));
        features.put("dst_host_same_srv_rate", parseValue(dstHostSameSrvRateField.getText()));
        features.put("dst_host_diff_srv_rate", parseValue(dstHostDiffSrvRateField.getText()));
        features.put("dst_host_same_src_port_rate", parseValue(dstHostSameSrcPortRateField.getText()));
        features.put("dst_host_srv_diff_host_rate", parseValue(dstHostSrvDiffHostRateField.getText()));
        features.put("dst_host_serror_rate", parseValue(dstHostSerrorRateField.getText()));
        features.put("dst_host_srv_serror_rate", parseValue(dstHostSrvSerrorRateField.getText()));
        features.put("dst_host_rerror_rate", parseValue(dstHostRerrorRateField.getText()));
        features.put("dst_host_srv_rerror_rate", parseValue(dstHostSrvRerrorRateField.getText()));
//        features.put("label", labelField.getText());

        updateStatus("Sending request to " + serverUrl + "...");

        // Use a SwingWorker to perform the HTTP request in the background
        SwingWorker<PredictionResult, Void> worker = new SwingWorker<>() {
            @Override
            protected PredictionResult doInBackground() throws Exception {
                return client.sendPredictionRequest(serverUrl, features);
            }

            @Override
            protected void done() {
                try {
                    PredictionResult result = get();
                    updateDashboard(result);
                    updateStatus("Request completed. Status: " + result.getStatus());
                } catch (Exception e) {
                    showError("Error", "Error processing request: " + e.getMessage());
                    updateStatus("Error: " + e.getMessage());
                }
            }
        };

        worker.execute();
    }

    /**
     * Updates the dashboard with the prediction result
     * 
     * @param result The prediction result to display
     */
    private void updateDashboard(PredictionResult result) {

        log.info("Updating dashboard with prediction result");

        if ("error".equals(result.getStatus())) {
            resultLabel.setText("ERROR");
            resultLabel.setForeground(Color.ORANGE);
            confidenceLabel.setText("Error: " + result.getErrorMessage());
            return;
        }

        // Update result label
        if ("Attack".equals(result.getPredictionLabel())) {
            resultLabel.setText("ATTACK");
            resultLabel.setForeground(new Color(244, 67, 54)); // Red
        } else {
            resultLabel.setText("NORMAL");
            resultLabel.setForeground(new Color(76, 175, 80)); // Green
        }

        // Update confidence label
        confidenceLabel.setText(String.format("Confidence: %.1f%%", result.getConfidence() * 100));

        // Update probability bar
        updateProbabilityBar(result.getNormalProbability(), result.getAttackProbability());

        // Add to current results list for potential export
        currentResults.clear();
        currentResults.add(result);
        exportMenuItem.setEnabled(true);
    }

    /**
     * Updates the probability bar visualization
     * 
     * @param normalProb Probability of normal traffic
     * @param attackProb Probability of attack
     */
    private void updateProbabilityBar(double normalProb, double attackProb) {

        log.info("Updating probability bar");

        final double normalRatio = normalProb;

        probabilityBarPanel = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                Graphics2D g2d = (Graphics2D) g.create();

                int width = getWidth();
                int height = getHeight();

                // Draw background
                g2d.setColor(Color.DARK_GRAY);
                g2d.fillRect(0, 0, width, height);

                // Draw normal portion (green)
                g2d.setColor(new Color(76, 175, 80));
                g2d.fillRect(0, 0, (int)(width * normalRatio), height);

                // Draw attack portion (red)
                g2d.setColor(new Color(244, 67, 54));
                g2d.fillRect((int)(width * normalRatio), 0, (int)(width * (1 - normalRatio)), height);

                // Draw labels
                g2d.setColor(Color.WHITE);
                g2d.setFont(new Font("Arial", Font.BOLD, 12));

                String normalText = String.format("NORMAL: %.1f%%", normalProb * 100);
                String attackText = String.format("ATTACK: %.1f%%", attackProb * 100);

                FontMetrics fm = g2d.getFontMetrics();
                int normalTextWidth = fm.stringWidth(normalText);
                int attackTextWidth = fm.stringWidth(attackText);

                // Only draw text if there's enough space
                if (width * normalRatio > normalTextWidth + 10) {
                    g2d.drawString(normalText, 10, height / 2 + fm.getAscent() / 2);
                }

                if (width * (1 - normalRatio) > attackTextWidth + 10) {
                    g2d.drawString(attackText, (int)(width * normalRatio) + 10, height / 2 + fm.getAscent() / 2);
                }

                g2d.dispose();
            }
        };

        probabilityBarPanel.repaint();
    }

    /**
     * Loads test data from a file
     */
    private void loadFromFile() {
        log.info("Loading test data from file");

        JFileChooser fileChooser = new JFileChooser();
        FileNameExtensionFilter csvFilter = new FileNameExtensionFilter("CSV Files (*.csv)", "csv");
        fileChooser.setFileFilter(csvFilter);

        int result = fileChooser.showOpenDialog(this);

        if (result == JFileChooser.APPROVE_OPTION) {
            showBatchProcessDialog();
            File selectedFile = fileChooser.getSelectedFile();
            try {
                String content = Files.readString(selectedFile.toPath());
                batchInputTextArea.setText(content);
                csvRadioButton.setSelected(true);
                updateStatus("File loaded successfully: " + selectedFile.getName());
            } catch (IOException e) {
                showError("Error loading file", "Error loading file: " + e.getMessage());
                updateStatus("Error loading file: " + e.getMessage());
            }
        }
    }

    /**
     * Exports the current results to a CSV file
     */
    private void exportResults() {

        log.info("Exporting results");

        if (currentResults.isEmpty()) {
            showWarning("No Results", "There are no results to export.");
            return;
        }

        JFileChooser fileChooser = new JFileChooser();
        FileNameExtensionFilter csvFilter = new FileNameExtensionFilter("CSV Files (*.csv)", "csv");
        fileChooser.setFileFilter(csvFilter);
        fileChooser.setSelectedFile(new File("prediction_results.csv"));

        int result = fileChooser.showSaveDialog(this);

        if (result == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();

            // Add .csv extension if not present
            if (!selectedFile.getName().toLowerCase().endsWith(".csv")) {
                selectedFile = new File(selectedFile.getAbsolutePath() + ".csv");
            }

            try (PrintWriter writer = new PrintWriter(selectedFile)) {
                // Write header
                writer.println(PredictionResult.getCsvHeader());

                // Write data
                for (PredictionResult predResult : currentResults) {
                    writer.println(predResult.toCsvString());
                }

                updateStatus("Results exported to: " + selectedFile.getAbsolutePath());
                JOptionPane.showMessageDialog(this, 
                        "Results exported successfully to:\n" + selectedFile.getAbsolutePath(), 
                        "Export Successful", 
                        JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException e) {
                showError("Export Error", "Error exporting results: " + e.getMessage());
                updateStatus("Export error: " + e.getMessage());
            }
        }
    }

    /**
     * Displays a prediction result in the results table
     * 
     * @param result The prediction result to display
     */
    private void displayResult(PredictionResult result) {

        log.info("Displaying prediction result in table");

        // Add to table
        if ("error".equals(result.getStatus())) {
            Object[] rowData = {"Error", "Error", 0.0, 0.0, 0.0, result.getErrorMessage()};
            resultsTableModel.addRow(rowData);
        } else {
            Object[] rowData = {
                result.getPrediction(),
                result.getPredictionLabel(),
                String.format("%.2f", result.getConfidence()),
                String.format("%.2f", result.getNormalProbability()),
                String.format("%.2f", result.getAttackProbability()),
                result.getStatus()
            };
            resultsTableModel.addRow(rowData);
        }
    }

    /**
     * Clears all results from the table
     */
    private void clearResults() {

        log.info("Clearing results");

        resultsTableModel.setRowCount(0);
        currentResults.clear();
        exportMenuItem.setEnabled(false);
    }

    /**
     * Updates the status label
     * 
     * @param status The status message to display
     */
    private void updateStatus(String status) {
        statusLabel.setText(status);
    }

    /**
     * Shows an error message dialog
     * 
     * @param title The dialog title
     * @param message The error message
     */
    private void showError(String title, String message) {
        JOptionPane.showMessageDialog(this, message, title, JOptionPane.ERROR_MESSAGE);
    }

    /**
     * Shows a warning message dialog
     * 
     * @param title The dialog title
     * @param message The warning message
     */
    private void showWarning(String title, String message) {
        JOptionPane.showMessageDialog(this, message, title, JOptionPane.WARNING_MESSAGE);
    }

    /**
     * Generates random network traffic data and fills the form fields
     */
    private void generateRandomInput() {

        log.info("Generating new random input from file");

        // Define possible values for categorical features
        String[] protocolTypes = {"tcp", "udp", "icmp"};
        String[] services = {"http", "ftp", "smtp", "ssh", "dns", "telnet", "pop3", "imap"};
        String[] flags = {"SF", "S0", "REJ", "RSTO", "RSTR", "SH", "RSTRH", "OTH"};
//        String[] labels = {"normal", "attack"};

        // Generate random values
        Random random = new Random();

        // Main fields
        int duration = random.nextInt(1000);
        String protocolType = protocolTypes[random.nextInt(protocolTypes.length)];
        String service = services[random.nextInt(services.length)];
        String flag = flags[random.nextInt(flags.length)];
        int srcBytes = random.nextInt(10000);
        int dstBytes = random.nextInt(10000);

        // Binary fields (0 or 1)
        int land = random.nextInt(2);
        int wrongFragment = random.nextInt(2);
        int urgent = random.nextInt(2);
        int hot = random.nextInt(10);
        int numFailedLogins = random.nextInt(5);
        int loggedIn = random.nextInt(2);
        int numCompromised = random.nextInt(5);
        int rootShell = random.nextInt(2);
        int suAttempted = random.nextInt(2);
        int numRoot = random.nextInt(5);
        int numFileCreations = random.nextInt(10);
        int numShells = random.nextInt(5);
        int numAccessFiles = random.nextInt(10);
        int numOutboundCmds = random.nextInt(5);
        int isHostLogin = random.nextInt(2);
        int isGuestLogin = random.nextInt(2);

        // Count fields
        int count = random.nextInt(100);
        int srvCount = random.nextInt(100);

        // Rate fields (0.0 to 1.0)
        double serrorRate = random.nextDouble();
        double srvSerrorRate = random.nextDouble();
        double rerrorRate = random.nextDouble();
        double srvRerrorRate = random.nextDouble();
        double sameSrvRate = random.nextDouble();
        double diffSrvRate = random.nextDouble();
        double srvDiffHostRate = random.nextDouble();

        // Destination host fields
        int dstHostCount = random.nextInt(255);
        int dstHostSrvCount = random.nextInt(255);
        double dstHostSameSrvRate = random.nextDouble();
        double dstHostDiffSrvRate = random.nextDouble();
        double dstHostSameSrcPortRate = random.nextDouble();
        double dstHostSrvDiffHostRate = random.nextDouble();
        double dstHostSerrorRate = random.nextDouble();
        double dstHostSrvSerrorRate = random.nextDouble();
        double dstHostRerrorRate = random.nextDouble();
        double dstHostSrvRerrorRate = random.nextDouble();

        // Label
//        String label = labels[random.nextInt(labels.length)];

        // Set values to form fields - main fields
        durationField.setText(String.valueOf(duration));
        protocolTypeField.setText(protocolType);
        serviceField.setText(service);
        flagField.setText(flag);
        srcBytesField.setText(String.valueOf(srcBytes));
        dstBytesField.setText(String.valueOf(dstBytes));

        // Set values to form fields - binary fields
        landField.setText(String.valueOf(land));
        wrongFragmentField.setText(String.valueOf(wrongFragment));
        urgentField.setText(String.valueOf(urgent));
        hotField.setText(String.valueOf(hot));
        numFailedLoginsField.setText(String.valueOf(numFailedLogins));
        loggedInField.setText(String.valueOf(loggedIn));
        numCompromisedField.setText(String.valueOf(numCompromised));
        rootShellField.setText(String.valueOf(rootShell));
        suAttemptedField.setText(String.valueOf(suAttempted));
        numRootField.setText(String.valueOf(numRoot));
        numFileCreationsField.setText(String.valueOf(numFileCreations));
        numShellsField.setText(String.valueOf(numShells));
        numAccessFilesField.setText(String.valueOf(numAccessFiles));
        numOutboundCmdsField.setText(String.valueOf(numOutboundCmds));
        isHostLoginField.setText(String.valueOf(isHostLogin));
        isGuestLoginField.setText(String.valueOf(isGuestLogin));

        // Set values to form fields - count fields
        countField.setText(String.valueOf(count));
        srvCountField.setText(String.valueOf(srvCount));

        // Set values to form fields - rate fields
        serrorRateField.setText(String.format("%.6f", serrorRate));
        srvSerrorRateField.setText(String.format("%.6f", srvSerrorRate));
        rerrorRateField.setText(String.format("%.6f", rerrorRate));
        srvRerrorRateField.setText(String.format("%.6f", srvRerrorRate));
        sameSrvRateField.setText(String.format("%.6f", sameSrvRate));
        diffSrvRateField.setText(String.format("%.6f", diffSrvRate));
        srvDiffHostRateField.setText(String.format("%.6f", srvDiffHostRate));

        // Set values to form fields - destination host fields
        dstHostCountField.setText(String.valueOf(dstHostCount));
        dstHostSrvCountField.setText(String.valueOf(dstHostSrvCount));
        dstHostSameSrvRateField.setText(String.format("%.6f", dstHostSameSrvRate));
        dstHostDiffSrvRateField.setText(String.format("%.6f", dstHostDiffSrvRate));
        dstHostSameSrcPortRateField.setText(String.format("%.6f", dstHostSameSrcPortRate));
        dstHostSrvDiffHostRateField.setText(String.format("%.6f", dstHostSrvDiffHostRate));
        dstHostSerrorRateField.setText(String.format("%.6f", dstHostSerrorRate));
        dstHostSrvSerrorRateField.setText(String.format("%.6f", dstHostSrvSerrorRate));
        dstHostRerrorRateField.setText(String.format("%.6f", dstHostRerrorRate));
        dstHostSrvRerrorRateField.setText(String.format("%.6f", dstHostSrvRerrorRate));

        // Set label
//        labelField.setText(label);

        updateStatus("Random network traffic data generated.");
    }

    /**
     * Attempts to parse a string value into a numeric type if possible.
     * 
     * @param value The string value to parse
     * @return The parsed value (Integer, Double, or String)
     */
    private Object parseValue(String value) {
        // Try to parse as integer
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            // Not an integer, try as double
            try {
                return Double.parseDouble(value);
            } catch (NumberFormatException e2) {
                // Not a number, return as string
                return value;
            }
        }
    }

    /**
     * Checks the health status of the Python Model Server
     * and displays the results in a dialog
     */
    private void checkServerHealth() {

        log.info("Checking server health");

        String serverUrl = serverUrlField.getText().trim();

        if (serverUrl.isEmpty()) {
            showWarning("Empty Server URL", "Please enter the Python Model Server URL.");
            return;
        }

        updateStatus("Checking server health at " + serverUrl + "...");

        // Use a SwingWorker to perform the health check in the background
        SwingWorker<ServerHealthStatus, Void> worker = new SwingWorker<>() {
            @Override
            protected ServerHealthStatus doInBackground() throws Exception {
                return client.checkServerHealth(serverUrl);
            }

            @Override
            protected void done() {
                try {
                    ServerHealthStatus healthStatus = get();
                    displayHealthStatus(healthStatus);
                } catch (Exception e) {
                    showError("Error", "Failed to check server health: " + e.getMessage());
                    updateStatus("Server health check failed.");
                }
            }
        };

        worker.execute();
    }

    /**
     * Displays the server health status in a dialog
     * 
     * @param healthStatus The server health status
     */
    private void displayHealthStatus(ServerHealthStatus healthStatus) {

        log.info("Displaying server health status");

        // Create a panel to display the health status
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Create a panel for the status information
        JPanel infoPanel = new JPanel(new GridLayout(0, 2, 5, 5));

        // Add status information
        infoPanel.add(new JLabel("Server Status:"));
        JLabel statusLabel = new JLabel(healthStatus.getStatus());
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.BOLD));
        if (healthStatus.isHealthy()) {
            statusLabel.setForeground(new Color(76, 175, 80)); // Green
        } else {
            statusLabel.setForeground(new Color(244, 67, 54)); // Red
        }
        infoPanel.add(statusLabel);

        // Add total features information
        infoPanel.add(new JLabel("Total Features:"));
        infoPanel.add(new JLabel(String.valueOf(healthStatus.getTotalFeatures())));

        // Add models loaded information
        infoPanel.add(new JLabel("All Models Loaded:"));
        JLabel modelsLabel = new JLabel(healthStatus.areAllModelsLoaded() ? "Yes" : "No");
        modelsLabel.setFont(modelsLabel.getFont().deriveFont(Font.BOLD));
        if (healthStatus.areAllModelsLoaded()) {
            modelsLabel.setForeground(new Color(76, 175, 80)); // Green
        } else {
            modelsLabel.setForeground(new Color(244, 67, 54)); // Red
        }
        infoPanel.add(modelsLabel);

        // Add individual model status
        infoPanel.add(new JLabel("Encoder Model:"));
        infoPanel.add(new JLabel(healthStatus.isEncoderLoaded() ? "Loaded" : "Not Loaded"));

        infoPanel.add(new JLabel("Features:"));
        infoPanel.add(new JLabel(healthStatus.isFeaturesLoaded() ? "Loaded" : "Not Loaded"));

        infoPanel.add(new JLabel("Main Model:"));
        infoPanel.add(new JLabel(healthStatus.isModelLoaded() ? "Loaded" : "Not Loaded"));

        infoPanel.add(new JLabel("Scaler:"));
        infoPanel.add(new JLabel(healthStatus.isScalerLoaded() ? "Loaded" : "Not Loaded"));

        // Add error message if any
        if (healthStatus.getErrorMessage() != null) {
            JLabel errorLabel = new JLabel("Error: " + healthStatus.getErrorMessage());
            errorLabel.setForeground(new Color(244, 67, 54)); // Red
            panel.add(errorLabel, BorderLayout.SOUTH);
        }

        // Add info panel to main panel
        panel.add(infoPanel, BorderLayout.CENTER);

        // Show the dialog
        String title = healthStatus.isHealthy() ? "Server Health: Healthy" : "Server Health: Issues Detected";
        JOptionPane.showMessageDialog(
                this,
                panel,
                title,
                healthStatus.isHealthy() ? JOptionPane.INFORMATION_MESSAGE : JOptionPane.WARNING_MESSAGE
        );

        // Update status bar
        updateStatus(healthStatus.isHealthy() 
                ? "Server health check completed: Server is healthy." 
                : "Server health check completed: Issues detected.");
    }
}
