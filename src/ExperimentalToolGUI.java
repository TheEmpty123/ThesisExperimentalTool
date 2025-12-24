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
 * and displaying prediction results.
 */
public class ExperimentalToolGUI extends JFrame {
    private JTextArea inputTextArea;
    private JTable resultsTable;
    private DefaultTableModel resultsTableModel;
    private JTextField serverUrlField;
    private JButton sendButton;
    private JButton loadFileButton;
    private JButton exportResultsButton;
    private JButton batchProcessButton;
    private JRadioButton keyValueRadio;
    private JRadioButton csvRadio;
    private JTextArea statusTextArea;
    private ModelServerClient client;
    private List<PredictionResult> currentResults;

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
        setSize(900, 700);
        setLocationRelativeTo(null);

        // Create the main panel with a border layout
        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Create the server URL panel
        JPanel serverPanel = new JPanel(new BorderLayout(5, 0));
        serverPanel.add(new JLabel("Python Model Server URL:"), BorderLayout.WEST);
        serverUrlField = new JTextField("http://localhost:8888/predict");
        serverPanel.add(serverUrlField, BorderLayout.CENTER);

        // Create the input panel
        JPanel inputPanel = new JPanel(new BorderLayout(5, 5));
        inputPanel.setBorder(BorderFactory.createTitledBorder("Test Data Input"));

        // Input format selection
        JPanel formatPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        keyValueRadio = new JRadioButton("Key-Value Format", true);
        csvRadio = new JRadioButton("CSV Format");
        ButtonGroup formatGroup = new ButtonGroup();
        formatGroup.add(keyValueRadio);
        formatGroup.add(csvRadio);
        formatPanel.add(new JLabel("Input Format:"));
        formatPanel.add(keyValueRadio);
        formatPanel.add(csvRadio);

        // Add example placeholder text
        String exampleText = "Example (key-value format):\nduration: 0 protocol_type: tcp service: http flag: SF src_bytes: 1000 dst_bytes: 2000";

        // Text area for input
        inputTextArea = new JTextArea(exampleText);
        inputTextArea.setLineWrap(true);
        inputTextArea.setWrapStyleWord(true);
        JScrollPane inputScrollPane = new JScrollPane(inputTextArea);

        // Button panel for input options
        JPanel inputButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        loadFileButton = new JButton("Load from File");
        loadFileButton.addActionListener(e -> loadFromFile());
        JButton clearButton = new JButton("Clear");
        clearButton.addActionListener(e -> inputTextArea.setText(""));
        JButton validateButton = new JButton("Validate Input");
        validateButton.addActionListener(e -> validateInput());

        inputButtonPanel.add(loadFileButton);
        inputButtonPanel.add(clearButton);
        inputButtonPanel.add(validateButton);

        // Add components to input panel
        inputPanel.add(formatPanel, BorderLayout.NORTH);
        inputPanel.add(inputScrollPane, BorderLayout.CENTER);
        inputPanel.add(inputButtonPanel, BorderLayout.SOUTH);

        // Create the result panel
        JPanel resultPanel = new JPanel(new BorderLayout(5, 5));
        resultPanel.setBorder(BorderFactory.createTitledBorder("Prediction Results"));

        // Create table for results
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

        // Status text area
        statusTextArea = new JTextArea(3, 20);
        statusTextArea.setEditable(false);
        statusTextArea.setLineWrap(true);
        statusTextArea.setWrapStyleWord(true);
        JScrollPane statusScrollPane = new JScrollPane(statusTextArea);
        statusScrollPane.setBorder(BorderFactory.createTitledBorder("Status"));

        // Results button panel
        JPanel resultButtonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        exportResultsButton = new JButton("Export Results");
        exportResultsButton.addActionListener(e -> exportResults());
        exportResultsButton.setEnabled(false);
        resultButtonPanel.add(exportResultsButton);

        // Add components to result panel
        resultPanel.add(tableScrollPane, BorderLayout.CENTER);
        resultPanel.add(statusScrollPane, BorderLayout.SOUTH);
        resultPanel.add(resultButtonPanel, BorderLayout.NORTH);

        // Create the control panel
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        batchProcessButton = new JButton("Batch Process");
        batchProcessButton.addActionListener(e -> batchProcess());
        sendButton = new JButton("Send to Model Server");
        sendButton.addActionListener(e -> sendData());
        controlPanel.add(batchProcessButton);
        controlPanel.add(sendButton);

        // Add all panels to the main panel
        mainPanel.add(serverPanel, BorderLayout.NORTH);

        // Create a split pane for input and result areas
        JSplitPane splitPane = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT,
                inputPanel,
                resultPanel
        );
        splitPane.setResizeWeight(0.4);
        mainPanel.add(splitPane, BorderLayout.CENTER);
        mainPanel.add(controlPanel, BorderLayout.SOUTH);

        // Add the main panel to the frame
        add(mainPanel);

        // Add format radio button listeners to update example text
        keyValueRadio.addActionListener(e -> {
            if (keyValueRadio.isSelected() && inputTextArea.getText().equals(exampleText) || 
                inputTextArea.getText().startsWith("Example (CSV format):")) {
                inputTextArea.setText("Example (key-value format):\nduration: 0 protocol_type: tcp service: http flag: SF src_bytes: 1000 dst_bytes: 2000");
            }
        });

        csvRadio.addActionListener(e -> {
            if (csvRadio.isSelected() && inputTextArea.getText().equals(exampleText) || 
                inputTextArea.getText().startsWith("Example (key-value format):")) {
                inputTextArea.setText("Example (CSV format):\nduration,protocol_type,service,flag,src_bytes,dst_bytes\n0,tcp,http,SF,1000,2000");
            }
        });
    }

    /**
     * Loads test data from a file
     */
    private void loadFromFile() {
        JFileChooser fileChooser = new JFileChooser();

        // Set up file filters based on selected format
        if (csvRadio.isSelected()) {
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
                inputTextArea.setText(content);

                // Auto-select the appropriate format based on file extension
                if (selectedFile.getName().toLowerCase().endsWith(".csv")) {
                    csvRadio.setSelected(true);
                }

                updateStatus("File loaded successfully: " + selectedFile.getName());
            } catch (IOException e) {
                showError("Error loading file", "Error loading file: " + e.getMessage());
                updateStatus("Error loading file: " + e.getMessage());
            }
        }
    }

    /**
     * Validates the input data format
     */
    private void validateInput() {
        String inputData = inputTextArea.getText().trim();

        if (inputData.isEmpty()) {
            showWarning("Empty Input", "Please enter test data or load it from a file.");
            return;
        }

        try {
            if (keyValueRadio.isSelected()) {
                // Validate key-value format
                Map<String, Object> features = FeatureMapper.parseKeyValueString(inputData);
                updateStatus("Input validation successful. Found " + features.size() + " features.");
            } else {
                // Validate CSV format
                String[] lines = inputData.split("\n");
                if (lines.length < 2) {
                    throw new IllegalArgumentException("CSV must have at least a header row and one data row");
                }

                Map<String, Object> features = FeatureMapper.parseCsvLine(lines[0], lines[1]);
                updateStatus("Input validation successful. Found " + features.size() + " features.");
            }

            JOptionPane.showMessageDialog(this, 
                    "Input data format is valid.", 
                    "Validation Successful", 
                    JOptionPane.INFORMATION_MESSAGE);
        } catch (IllegalArgumentException e) {
            showError("Validation Error", "Input data format is invalid: " + e.getMessage());
            updateStatus("Validation error: " + e.getMessage());
        }
    }

    /**
     * Sends the input data to the Python Model Server
     */
    private void sendData() {
        String inputData = inputTextArea.getText().trim();
        String serverUrl = serverUrlField.getText().trim();

        if (inputData.isEmpty()) {
            showWarning("Empty Input", "Please enter test data or load it from a file.");
            return;
        }

        if (serverUrl.isEmpty()) {
            showWarning("Empty Server URL", "Please enter the Python Model Server URL.");
            return;
        }

        // Disable the send button while processing
        sendButton.setEnabled(false);
        batchProcessButton.setEnabled(false);
        sendButton.setText("Sending...");
        updateStatus("Sending request to " + serverUrl + "...");

        // Use a SwingWorker to perform the HTTP request in the background
        SwingWorker<PredictionResult, Void> worker = new SwingWorker<>() {
            @Override
            protected PredictionResult doInBackground() throws Exception {
                if (keyValueRadio.isSelected()) {
                    return client.predict(serverUrl, inputData);
                } else {
                    // For CSV, just process the first data row
                    String[] lines = inputData.split("\n", 3);
                    if (lines.length < 2) {
                        throw new IllegalArgumentException("CSV must have at least a header row and one data row");
                    }

                    Map<String, Object> features = FeatureMapper.parseCsvLine(lines[0], lines[1]);
                    return client.sendPredictionRequest(serverUrl, features);
                }
            }

            @Override
            protected void done() {
                try {
                    PredictionResult result = get();
                    displayResult(result);
                    updateStatus("Request completed. Status: " + result.getStatus());
                } catch (Exception e) {
                    showError("Error", "Error processing request: " + e.getMessage());
                    updateStatus("Error: " + e.getMessage());
                } finally {
                    // Re-enable the buttons
                    sendButton.setEnabled(true);
                    batchProcessButton.setEnabled(true);
                    sendButton.setText("Send to Model Server");
                }
            }
        };

        worker.execute();
    }

    /**
     * Processes multiple inputs in batch mode
     */
    private void batchProcess() {
        String inputData = inputTextArea.getText().trim();
        String serverUrl = serverUrlField.getText().trim();

        if (inputData.isEmpty()) {
            showWarning("Empty Input", "Please enter test data or load it from a file.");
            return;
        }

        if (serverUrl.isEmpty()) {
            showWarning("Empty Server URL", "Please enter the Python Model Server URL.");
            return;
        }

        // Disable buttons while processing
        sendButton.setEnabled(false);
        batchProcessButton.setEnabled(false);
        batchProcessButton.setText("Processing...");
        updateStatus("Starting batch processing...");

        // Clear previous results
        clearResults();

        // Use a SwingWorker to perform batch processing in the background
        SwingWorker<List<PredictionResult>, PredictionResult> worker = new SwingWorker<>() {
            @Override
            protected List<PredictionResult> doInBackground() throws Exception {
                List<PredictionResult> results = new ArrayList<>();

                if (csvRadio.isSelected()) {
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
                    exportResultsButton.setEnabled(!currentResults.isEmpty());
                } catch (Exception e) {
                    showError("Error", "Error during batch processing: " + e.getMessage());
                    updateStatus("Error: " + e.getMessage());
                } finally {
                    // Re-enable the buttons
                    sendButton.setEnabled(true);
                    batchProcessButton.setEnabled(true);
                    batchProcessButton.setText("Batch Process");
                }
            }
        };

        worker.execute();
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
        // Add to current results list
        currentResults.add(result);

        // Enable export button if we have results
        exportResultsButton.setEnabled(true);

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
        exportResultsButton.setEnabled(false);
    }

    /**
     * Updates the status text area
     * 
     * @param status The status message to display
     */
    private void updateStatus(String status) {
        statusTextArea.setText(status);
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
}
