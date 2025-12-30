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
    
    /**
     * Constructor - initializes the GUI components
     */
    public ExperimentalToolGUI() {
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
        serverPanel.add(new JLabel("Python Model Server URL:"), BorderLayout.WEST);
        serverUrlField = new JTextField("http://localhost:8888/predict");
        serverPanel.add(serverUrlField, BorderLayout.CENTER);
        
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
        JPanel inputPanel = new JPanel(new BorderLayout(5, 5));
        inputPanel.setBorder(BorderFactory.createTitledBorder("Manual Input Features"));
        
        // Create a form panel with GridBagLayout
        JPanel formPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);
        
        // Add form fields
        gbc.gridx = 0;
        gbc.gridy = 0;
        formPanel.add(new JLabel("Duration:"), gbc);
        
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        durationField = new JTextField("0");
        formPanel.add(durationField, gbc);
        
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Protocol Type:"), gbc);
        
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        protocolTypeField = new JTextField("tcp");
        formPanel.add(protocolTypeField, gbc);
        
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Service:"), gbc);
        
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        serviceField = new JTextField("http");
        formPanel.add(serviceField, gbc);
        
        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Flag:"), gbc);
        
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        flagField = new JTextField("SF");
        formPanel.add(flagField, gbc);
        
        gbc.gridx = 0;
        gbc.gridy = 4;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Source Bytes:"), gbc);
        
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        srcBytesField = new JTextField("1000");
        formPanel.add(srcBytesField, gbc);
        
        gbc.gridx = 0;
        gbc.gridy = 5;
        gbc.weightx = 0.0;
        formPanel.add(new JLabel("Destination Bytes:"), gbc);
        
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        dstBytesField = new JTextField("2000");
        formPanel.add(dstBytesField, gbc);
        
        // Add predict button
        gbc.gridx = 0;
        gbc.gridy = 6;
        gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(20, 5, 5, 5);
        
        JButton predictButton = new JButton("Predict Single");
        predictButton.setBackground(new Color(76, 175, 80)); // Green color
        predictButton.setForeground(Color.WHITE);
        predictButton.setFont(predictButton.getFont().deriveFont(Font.BOLD, 14f));
        predictButton.addActionListener(e -> predictSingle());
        
        formPanel.add(predictButton, gbc);
        
        // Add form panel to input panel
        inputPanel.add(formPanel, BorderLayout.CENTER);
        
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
        dashboardPanel.add(probabilityBarPanel, gbc);
        
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
        String serverUrl = serverUrlField.getText().trim();
        
        if (serverUrl.isEmpty()) {
            showWarning("Empty Server URL", "Please enter the Python Model Server URL.");
            return;
        }
        
        // Create a map of features from the form fields
        Map<String, Object> features = new HashMap<>();
        features.put("duration", parseValue(durationField.getText()));
        features.put("protocol_type", protocolTypeField.getText());
        features.put("service", serviceField.getText());
        features.put("flag", flagField.getText());
        features.put("src_bytes", parseValue(srcBytesField.getText()));
        features.put("dst_bytes", parseValue(dstBytesField.getText()));
        
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
        // Define possible values for categorical features
        String[] protocolTypes = {"tcp", "udp", "icmp"};
        String[] services = {"http", "ftp", "smtp", "ssh", "dns", "telnet", "pop3", "imap"};
        String[] flags = {"SF", "S0", "REJ", "RSTO", "RSTR", "SH", "RSTRH", "OTH"};
        
        // Generate random values
        Random random = new Random();
        int duration = random.nextInt(1000);
        String protocolType = protocolTypes[random.nextInt(protocolTypes.length)];
        String service = services[random.nextInt(services.length)];
        String flag = flags[random.nextInt(flags.length)];
        int srcBytes = random.nextInt(10000);
        int dstBytes = random.nextInt(10000);
        
        // Set values to form fields
        durationField.setText(String.valueOf(duration));
        protocolTypeField.setText(protocolType);
        serviceField.setText(service);
        flagField.setText(flag);
        srcBytesField.setText(String.valueOf(srcBytes));
        dstBytesField.setText(String.valueOf(dstBytes));
        
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
}