import utils.LogObj;

import java.io.*;
import java.util.*;

/**
 * Class to handle mapping of input data to feature dictionaries.
 * Supports parsing key-value format and CSV files.
 */
public class FeatureMapper {

    // Logger
    private static LogObj log = new LogObj("FeatureMapper");
    
    /**
     * Parses a string in key-value format and returns a map of features.
     * Format example: "duration: 0 protocol_type: tcp service: http flag: SF src_bytes: 1000"
     * 
     * @param input The input string in key-value format
     * @return A map of feature names to values
     * @throws IllegalArgumentException If the input format is invalid
     */
    public static Map<String, Object> parseKeyValueString(String input) throws IllegalArgumentException {

        log.info("Parsing key-value string: " + input);

        Map<String, Object> features = new HashMap<>();
        
        if (input == null || input.trim().isEmpty()) {
            throw new IllegalArgumentException("Input cannot be empty");
        }
        
        // Split by whitespace, but keep key-value pairs together
        String[] parts = input.trim().split("\\s+");
        
        for (int i = 0; i < parts.length; i++) {
            String part = parts[i];
            
            // Check if this part contains a key-value separator
            if (part.endsWith(":")) {
                // The key ends with a colon, the value should be the next part
                if (i + 1 >= parts.length) {
                    throw new IllegalArgumentException("Missing value for key: " + part);
                }
                
                String key = part.substring(0, part.length() - 1);
                String value = parts[++i];
                
                // Try to parse numeric values
                features.put(key, parseValue(value));
            } else if (part.contains(":")) {
                // The key and value are in the same part, separated by a colon
                String[] keyValue = part.split(":", 2);
                if (keyValue.length != 2) {
                    throw new IllegalArgumentException("Invalid key-value format: " + part);
                }
                
                String key = keyValue[0].trim();
                String value = keyValue[1].trim();
                
                // Try to parse numeric values
                features.put(key, parseValue(value));
            } else {
                throw new IllegalArgumentException("Invalid format, missing colon separator: " + part);
            }
        }
        
        return features;
    }
    
    /**
     * Parses a CSV line and returns a map of features.
     * The first line of the CSV should contain the feature names.
     * 
     * @param headerLine The CSV header line with feature names
     * @param dataLine The CSV data line with feature values
     * @return A map of feature names to values
     * @throws IllegalArgumentException If the CSV format is invalid
     */
    public static Map<String, Object> parseCsvLine(String headerLine, String dataLine) throws IllegalArgumentException {
        log.info("Parsing CSV line: " + dataLine);

        Map<String, Object> features = new HashMap<>();
        
        if (headerLine == null || headerLine.trim().isEmpty()) {
            throw new IllegalArgumentException("Header line cannot be empty");
        }
        
        if (dataLine == null || dataLine.trim().isEmpty()) {
            throw new IllegalArgumentException("Data line cannot be empty");
        }
        
        String[] headers = headerLine.split(",");
        String[] values = dataLine.split(",");
        
        if (headers.length != values.length) {
            throw new IllegalArgumentException(
                    "Number of headers (" + headers.length + ") does not match number of values (" + values.length + ")");
        }
        
        for (int i = 0; i < headers.length; i++) {
            String header = headers[i].trim();
            String value = values[i].trim();
            
            // Try to parse numeric values
            features.put(header, parseValue(value));
        }
        
        return features;
    }
    
    /**
     * Parses a CSV file and returns a list of feature maps.
     * 
     * @param csvFile The CSV file to parse
     * @return A list of feature maps, one for each data line in the CSV
     * @throws IOException If an I/O error occurs
     * @throws IllegalArgumentException If the CSV format is invalid
     */
    public static List<Map<String, Object>> parseCsvFile(File csvFile) throws IOException, IllegalArgumentException {
        log.info("Parsing CSV file: " + csvFile.getAbsolutePath());

        List<Map<String, Object>> featuresList = new ArrayList<>();
        
        try (BufferedReader reader = new BufferedReader(new FileReader(csvFile))) {
            String headerLine = reader.readLine();
            if (headerLine == null) {
                throw new IllegalArgumentException("CSV file is empty");
            }
            
            String dataLine;
            while ((dataLine = reader.readLine()) != null) {
                if (!dataLine.trim().isEmpty()) {
                    featuresList.add(parseCsvLine(headerLine, dataLine));
                }
            }
        }
        
        return featuresList;
    }
    
    /**
     * Validates that all required features are present in the feature map.
     * 
     * @param features The feature map to validate
     * @param requiredFeatures The list of required feature names
     * @throws IllegalArgumentException If any required feature is missing
     */
    public static void validateFeatures(Map<String, Object> features, List<String> requiredFeatures) throws IllegalArgumentException {
        log.info("Validating features: " + features);

        for (String feature : requiredFeatures) {
            if (!features.containsKey(feature)) {
                throw new IllegalArgumentException("Missing required feature: " + feature);
            }
        }
    }
    
    /**
     * Attempts to parse a string value into a numeric type if possible.
     * 
     * @param value The string value to parse
     * @return The parsed value (Integer, Double, or String)
     */
    private static Object parseValue(String value) {
        log.info("Parsing value: " + value);

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