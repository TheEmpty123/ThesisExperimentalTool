import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.io.IOException;
import java.net.ConnectException;
import java.util.concurrent.TimeoutException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Client for communicating with the Python Model Server.
 * Handles sending HTTP requests and processing responses.
 */
public class ModelServerClient {
    private final HttpClient httpClient;
    private final int timeout;
    private final int maxRetries;

    /**
     * Constructor - initializes the HTTP client with default settings
     */
    public ModelServerClient() {
        this(10, 3);
    }

    /**
     * Constructor - initializes the HTTP client with custom settings
     * 
     * @param timeoutSeconds Timeout in seconds for HTTP requests
     * @param maxRetries Maximum number of retries for failed requests
     */
    public ModelServerClient(int timeoutSeconds, int maxRetries) {
        this.timeout = timeoutSeconds;
        this.maxRetries = maxRetries;

        // Create an HTTP client with a timeout
        httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_2)
                .connectTimeout(Duration.ofSeconds(timeoutSeconds))
                .build();
    }

    /**
     * Sends a request to the Python Model Server with a single set of features
     * 
     * @param serverUrl The URL of the Python Model Server
     * @param inputData The test data to send in key-value format
     * @return The prediction result
     */
    public PredictionResult predict(String serverUrl, String inputData) {
        try {
            // Parse the input data into a feature map
            Map<String, Object> features = FeatureMapper.parseKeyValueString(inputData);

            // Send the request and return the result
            return sendPredictionRequest(serverUrl, features);
        } catch (IllegalArgumentException e) {
            return new PredictionResult("Input data format error: " + e.getMessage());
        } catch (Exception e) {
            return new PredictionResult("Error: " + e.getMessage());
        }
    }

    /**
     * Sends a batch prediction request to the Python Model Server
     * 
     * @param serverUrl The URL of the Python Model Server
     * @param inputDataList List of input data strings in key-value format
     * @return List of prediction results
     */
    public List<PredictionResult> batchPredict(String serverUrl, List<String> inputDataList) {
        List<PredictionResult> results = new ArrayList<>();

        for (String inputData : inputDataList) {
            results.add(predict(serverUrl, inputData));
        }

        return results;
    }

    /**
     * Sends a batch prediction request from a CSV file
     * 
     * @param serverUrl The URL of the Python Model Server
     * @param csvFile The CSV file containing test data
     * @return List of prediction results
     */
    public List<PredictionResult> batchPredictFromCsv(String serverUrl, java.io.File csvFile) {
        List<PredictionResult> results = new ArrayList<>();

        try {
            // Parse the CSV file into a list of feature maps
            List<Map<String, Object>> featuresList = FeatureMapper.parseCsvFile(csvFile);

            // Send a prediction request for each set of features
            for (Map<String, Object> features : featuresList) {
                results.add(sendPredictionRequest(serverUrl, features));
            }
        } catch (IOException e) {
            results.add(new PredictionResult("CSV file error: " + e.getMessage()));
        } catch (IllegalArgumentException e) {
            results.add(new PredictionResult("CSV format error: " + e.getMessage()));
        } catch (Exception e) {
            results.add(new PredictionResult("Error: " + e.getMessage()));
        }

        return results;
    }

    /**
     * Sends a prediction request to the server with the given features
     * 
     * @param serverUrl The URL of the Python Model Server
     * @param features Map of feature names to values
     * @return The prediction result
     */
    public PredictionResult sendPredictionRequest(String serverUrl, Map<String, Object> features) {
        try {
            // Create the JSON request body
            String jsonBody = createJsonRequest(features);

            // Build the HTTP request
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(serverUrl))
                    .header("Content-Type", "application/json")
                    .timeout(Duration.ofSeconds(timeout))
                    .POST(HttpRequest.BodyPublishers.ofString(jsonBody, StandardCharsets.UTF_8))
                    .build();

            // Send the request with retries
            HttpResponse<String> response = sendWithRetries(request);

            // Process the response
            return processResponse(response);
        } catch (ConnectException e) {
            return new PredictionResult("Connection error: Could not connect to server at " + serverUrl);
        } catch (TimeoutException e) {
            return new PredictionResult("Timeout error: Server did not respond within " + timeout + " seconds");
        } catch (IOException e) {
            return new PredictionResult("I/O error: " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new PredictionResult("Request interrupted: " + e.getMessage());
        } catch (Exception e) {
            return new PredictionResult("Error: " + e.getMessage());
        }
    }

    /**
     * Creates a JSON request body from a map of features
     * 
     * @param features Map of feature names to values
     * @return JSON string in the format {"features": {...}}
     */
    private String createJsonRequest(Map<String, Object> features) {
        StringBuilder json = new StringBuilder();
        json.append("{\"features\":{");

        boolean first = true;
        for (Map.Entry<String, Object> entry : features.entrySet()) {
            if (!first) {
                json.append(",");
            }
            first = false;

            json.append("\"").append(entry.getKey()).append("\":");

            Object value = entry.getValue();
            if (value instanceof String) {
                json.append("\"").append(escapeJson((String) value)).append("\"");
            } else {
                json.append(value);
            }
        }

        json.append("}}");
        return json.toString();
    }

    /**
     * Sends an HTTP request with retries
     * 
     * @param request The HTTP request to send
     * @return The HTTP response
     * @throws IOException If an I/O error occurs
     * @throws InterruptedException If the operation is interrupted
     * @throws TimeoutException If the request times out after all retries
     */
    private HttpResponse<String> sendWithRetries(HttpRequest request) 
            throws IOException, InterruptedException, TimeoutException {
        Exception lastException = null;

        for (int attempt = 0; attempt < maxRetries; attempt++) {
            try {
                return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            } catch (IOException | InterruptedException e) {
                lastException = e;

                // If interrupted, propagate the interruption
                if (e instanceof InterruptedException) {
                    Thread.currentThread().interrupt();
                    throw (InterruptedException) e;
                }

                // Wait before retrying (exponential backoff)
                try {
                    Thread.sleep((long) Math.pow(2, attempt) * 1000);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw ie;
                }
            }
        }

        // If we get here, all retries failed
        if (lastException instanceof IOException) {
            throw (IOException) lastException;
        } else if (lastException instanceof InterruptedException) {
            throw (InterruptedException) lastException;
        } else {
            throw new TimeoutException("Request failed after " + maxRetries + " attempts");
        }
    }

    /**
     * Processes the HTTP response and creates a PredictionResult
     * 
     * @param response The HTTP response from the server
     * @return The prediction result
     */
    private PredictionResult processResponse(HttpResponse<String> response) {
        // Check if the request was successful
        if (response.statusCode() >= 200 && response.statusCode() < 300) {
            try {
                // Parse the JSON response
                Map<String, Object> jsonValues = parseJsonResponse(response.body());

                // Extract prediction values
                int prediction = getIntValue(jsonValues, "prediction", -1);
                String predictionLabel = getStringValue(jsonValues, "prediction_label", "Unknown");
                double confidence = getDoubleValue(jsonValues, "confidence", 0.0);
                double normalProb = getDoubleValue(jsonValues, "probabilities.0", 0.0);
                double attackProb = getDoubleValue(jsonValues, "probabilities.1", 0.0);

                // Create and return the prediction result
                return new PredictionResult(prediction, predictionLabel, confidence, normalProb, attackProb);
            } catch (Exception e) {
                return new PredictionResult("Error parsing response: " + e.getMessage());
            }
        } else {
            // Handle error response
            return new PredictionResult("Server error: " + response.statusCode() + " - " + response.body());
        }
    }

    /**
     * Escapes special characters in a string for JSON
     * 
     * @param input The input string
     * @return The escaped string
     */
    private String escapeJson(String input) {
        if (input == null) return "";
        return input.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    /**
     * Parses a JSON response string into a map of key-value pairs
     * 
     * @param jsonString The JSON string to parse
     * @return A map of key-value pairs from the JSON
     */
    private Map<String, Object> parseJsonResponse(String jsonString) {
        Map<String, Object> result = new HashMap<>();

        // Use regex to extract key-value pairs
        Pattern pattern = Pattern.compile("\"([\\w\\.]+)\"\\s*:\\s*\"([^\"]*)\"");
        Matcher matcher = pattern.matcher(jsonString);

        while (matcher.find()) {
            String key = matcher.group(1);
            String value = matcher.group(2);
            result.put(key, value);
        }

        // Also try to match non-string values (numbers, booleans, etc.)
        Pattern nonStringPattern = Pattern.compile("\"([\\w\\.]+)\"\\s*:\\s*([^,}\\s][^,}]*)");
        Matcher nonStringMatcher = nonStringPattern.matcher(jsonString);

        while (nonStringMatcher.find()) {
            String key = nonStringMatcher.group(1);
            String value = nonStringMatcher.group(2);
            // Only add if not already added as a string value
            if (!result.containsKey(key)) {
                // Try to parse as number
                try {
                    if (value.contains(".")) {
                        result.put(key, Double.parseDouble(value));
                    } else {
                        result.put(key, Integer.parseInt(value));
                    }
                } catch (NumberFormatException e) {
                    // Not a number, store as string
                    result.put(key, value);
                }
            }
        }

        // Try to parse arrays
        parseArrays(jsonString, result);

        return result;
    }

    /**
     * Parses arrays in a JSON string and adds them to the result map
     * 
     * @param jsonString The JSON string to parse
     * @param result The map to add the parsed arrays to
     */
    private void parseArrays(String jsonString, Map<String, Object> result) {
        // Find arrays in the JSON string
        Pattern arrayPattern = Pattern.compile("\"([\\w\\.]+)\"\\s*:\\s*\\[(.*?)\\]");
        Matcher arrayMatcher = arrayPattern.matcher(jsonString);

        while (arrayMatcher.find()) {
            String key = arrayMatcher.group(1);
            String arrayContent = arrayMatcher.group(2);

            // Split the array content by commas (ignoring commas in nested structures)
            String[] elements = arrayContent.split(",");

            // Store array elements with indexed keys
            for (int i = 0; i < elements.length; i++) {
                String element = elements[i].trim();
                if (!element.isEmpty()) {
                    result.put(key + "." + i, parseValue(element));
                }
            }
        }
    }

    /**
     * Parses a value string into an appropriate type
     * 
     * @param value The value string to parse
     * @return The parsed value (String, Double, Integer, Boolean)
     */
    private Object parseValue(String value) {
        // Remove quotes if present
        if (value.startsWith("\"") && value.endsWith("\"")) {
            return value.substring(1, value.length() - 1);
        }

        // Try to parse as boolean
        if ("true".equalsIgnoreCase(value)) {
            return Boolean.TRUE;
        } else if ("false".equalsIgnoreCase(value)) {
            return Boolean.FALSE;
        }

        // Try to parse as number
        try {
            if (value.contains(".")) {
                return Double.parseDouble(value);
            } else {
                return Integer.parseInt(value);
            }
        } catch (NumberFormatException e) {
            // Not a number, return as string
            return value;
        }
    }

    /**
     * Gets a string value from a map, with a default value if not found
     * 
     * @param map The map to get the value from
     * @param key The key to look up
     * @param defaultValue The default value to return if the key is not found
     * @return The string value
     */
    private String getStringValue(Map<String, Object> map, String key, String defaultValue) {
        Object value = map.get(key);
        if (value != null) {
            return value.toString();
        }
        return defaultValue;
    }

    /**
     * Gets an integer value from a map, with a default value if not found
     * 
     * @param map The map to get the value from
     * @param key The key to look up
     * @param defaultValue The default value to return if the key is not found
     * @return The integer value
     */
    private int getIntValue(Map<String, Object> map, String key, int defaultValue) {
        Object value = map.get(key);
        if (value instanceof Number) {
            return ((Number) value).intValue();
        } else if (value instanceof String) {
            try {
                return Integer.parseInt((String) value);
            } catch (NumberFormatException e) {
                return defaultValue;
            }
        }
        return defaultValue;
    }

    /**
     * Gets a double value from a map, with a default value if not found
     * 
     * @param map The map to get the value from
     * @param key The key to look up
     * @param defaultValue The default value to return if the key is not found
     * @return The double value
     */
    private double getDoubleValue(Map<String, Object> map, String key, double defaultValue) {
        Object value = map.get(key);
        if (value instanceof Number) {
            return ((Number) value).doubleValue();
        } else if (value instanceof String) {
            try {
                return Double.parseDouble((String) value);
            } catch (NumberFormatException e) {
                return defaultValue;
            }
        }
        return defaultValue;
    }

    /**
     * Checks the health status of the Python Model Server
     * 
     * @param serverUrl The base URL of the Python Model Server (without the endpoint)
     * @return The server health status
     */
    public ServerHealthStatus checkServerHealth(String serverUrl) {
        // Extract the base URL (remove "/predict" if present)
        String baseUrl = serverUrl;
        if (baseUrl.endsWith("/predict")) {
            baseUrl = baseUrl.substring(0, baseUrl.length() - 8); // Remove "/predict"
        }

        // Ensure the URL doesn't end with a slash
        if (baseUrl.endsWith("/")) {
            baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
        }

        // Append the health endpoint
        String healthUrl = baseUrl + "/health";

        try {
            // Build the HTTP request
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(healthUrl))
                    .timeout(Duration.ofSeconds(timeout))
                    .GET()
                    .build();

            // Send the request with retries
            HttpResponse<String> response = sendWithRetries(request);

            // Check if the request was successful
            if (response.statusCode() >= 200 && response.statusCode() < 300) {
                try {
//                    // Parse the JSON response
//                    Map<String, Object> jsonValues = parseJsonResponse(response.body());
//
//                    // Extract health status values
//                    String status = getStringValue(jsonValues, "status", "unknown");
//                    int totalFeatures = getIntValue(jsonValues, "total_features", 0);
//
//                    // Extract models_loaded values (nested map)
//                    @SuppressWarnings("unchecked")
//                    Map<String, Object> modelsLoaded =
//                            (Map<String, Object>) jsonValues.get("models_loaded");
//
//                    boolean encoderLoaded = Boolean.TRUE.equals(modelsLoaded.get("encoder"));
//                    boolean featuresLoaded = Boolean.TRUE.equals(modelsLoaded.get("features"));
//                    boolean modelLoaded = Boolean.TRUE.equals(modelsLoaded.get("model"));
//                    boolean scalerLoaded = Boolean.TRUE.equals(modelsLoaded.get("scaler"));

                    String body = response.body();
                    // Use regex to extract values
                    String status = "unknown";
                    int totalFeatures = 0;
                    boolean encoderLoaded = false;
                    boolean featuresLoaded = false;
                    boolean modelLoaded = false;
                    boolean scalerLoaded = false;
                    Pattern statusPattern = Pattern.compile("\"status\"\\s*:\\s*\"([^\"]+)\"");
                    Matcher statusMatcher = statusPattern.matcher(body);
                    if (statusMatcher.find()) {
                        status = statusMatcher.group(1);
                    }
                    Pattern totalFeaturesPattern = Pattern.compile("\"total_features\"\\s*:\\s*(\\d+)");
                    Matcher totalFeaturesMatcher = totalFeaturesPattern.matcher(body);
                    if (totalFeaturesMatcher.find()) {
                        totalFeatures = Integer.parseInt(totalFeaturesMatcher.group(1));
                    }
                    Pattern modelsLoadedPattern = Pattern.compile("\"models_loaded\"\\s*:\\s*\\{(.*?)\\}");
                    Matcher modelsLoadedMatcher = modelsLoadedPattern.matcher(body);
                    if (modelsLoadedMatcher.find()) {
                        String modelsLoadedContent = modelsLoadedMatcher.group(1);
                        Pattern modelPattern = Pattern.compile("\"(encoder|features|model|scaler)\"\\s*:\\s*(true|false)");
                        Matcher modelMatcher = modelPattern.matcher(modelsLoadedContent);
                        while (modelMatcher.find()) {
                            String modelName = modelMatcher.group(1);
                            boolean isLoaded = "true".equals(modelMatcher.group(2));
                            switch (modelName) {
                                case "encoder":
                                    encoderLoaded = isLoaded;
                                    break;
                                case "features":
                                    featuresLoaded = isLoaded;
                                    break;
                                case "model":
                                    modelLoaded = isLoaded;
                                    break;
                                case "scaler":
                                    scalerLoaded = isLoaded;
                                    break;
                            }
                        }
                    }

                    // Create and return the health status
                    return new ServerHealthStatus(
                            encoderLoaded, featuresLoaded, modelLoaded, scalerLoaded,
                            status, totalFeatures);
                } catch (Exception e) {
                    System.out.println(e.getMessage());
                    return new ServerHealthStatus("Error parsing response: " + e.getMessage());
                }
            } else {
                // Handle error response
                return new ServerHealthStatus("Server error: " + response.statusCode() + " - " + response.body());
            }
        } catch (ConnectException e) {
            return new ServerHealthStatus("Connection error: Could not connect to server at " + healthUrl);
        } catch (TimeoutException e) {
            return new ServerHealthStatus("Timeout error: Server did not respond within " + timeout + " seconds");
        } catch (IOException e) {
            return new ServerHealthStatus("I/O error: " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new ServerHealthStatus("Request interrupted: " + e.getMessage());
        } catch (Exception e) {
            return new ServerHealthStatus("Error: " + e.getMessage());
        }
    }
}
