package com.ids.backend;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.ids.model.NetworkFeatures;

import java.util.HashMap;
import java.util.Map;

public class PredictionClient {
    private static final Logger logger = LoggerFactory.getLogger(PredictionClient.class);

    private final String backendUrl;
    private final ObjectMapper objectMapper;
    private final CloseableHttpClient httpClient;

    public PredictionClient(String backendUrl) {
        this.backendUrl = backendUrl;
        this.objectMapper = new ObjectMapper();
        this.httpClient = HttpClients.createDefault();
    }

    /**
     * Gửi features tới backend để prediction
     * @param features Network features
     * @return Prediction result hoặc null nếu error
     */
    public PredictionResult predict(NetworkFeatures features) {
        try {
            // Tạo request body
            Map<String, Object> requestBody = new HashMap<>();
            requestBody.put("features", features);

            String jsonPayload = objectMapper.writeValueAsString(requestBody);
            logger.debug("Sending payload: {}", jsonPayload);

            // Create HTTP POST request
            HttpPost httpPost = new HttpPost(backendUrl);
            httpPost.setEntity(new StringEntity(jsonPayload, ContentType.APPLICATION_JSON));
            httpPost.setHeader("Content-Type", "application/json");

            // Execute request
            return httpClient.execute(httpPost, response -> {
                int statusCode = response.getCode();
                String responseBody = new String(response.getEntity().getContent().readAllBytes());

                logger.info("Backend response status: {}", statusCode);

                if (statusCode == 200 || statusCode == 201) {
                    try {
                        PredictionResult result = objectMapper.readValue(
                                responseBody,
                                PredictionResult.class
                        );
                        logger.info("Prediction result: {}", result);
                        return result;
                    } catch (Exception e) {
                        logger.error("Error parsing response: {}", e.getMessage());
                        return null;
                    }
                } else {
                    logger.error("Backend returned error: {} - {}", statusCode, responseBody);
                    return null;
                }
            });

        } catch (Exception e) {
            logger.error("Error sending prediction request: {}", e.getMessage(), e);
            return null;
        }
    }

    /**
     * Shutdown HTTP client
     */
    public void close() {
        try {
            httpClient.close();
        } catch (Exception e) {
            logger.error("Error closing HTTP client: {}", e.getMessage());
        }
    }

    /**
     * Response model từ backend
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class PredictionResult {
        private String prediction;
        private double confidence;

        @JsonProperty("prediction_label")
        private String predictionLabel;

        private long timestamp;

        public PredictionResult() {
            this.timestamp = System.currentTimeMillis();
        }

        public String getPrediction() { return prediction; }
        public void setPrediction(String prediction) { this.prediction = prediction; }

        public double getConfidence() { return confidence; }
        public void setConfidence(double confidence) { this.confidence = confidence; }

        public String getPredictionLabel() { return predictionLabel; }
        public void setPredictionLabel(String predictionLabel) { this.predictionLabel = predictionLabel; }

        public long getTimestamp() { return timestamp; }
        public void setTimestamp(long timestamp) { this.timestamp = timestamp; }

        @Override
        public String toString() {
            return "PredictionResult{" +
                    "prediction='" + prediction + '\'' +
                    ", label='" + predictionLabel + '\'' +
                    ", confidence=" + confidence +
                    ", timestamp=" + timestamp +
                    '}';
        }
    }
}
