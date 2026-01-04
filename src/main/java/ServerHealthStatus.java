import utils.LogObj;

/**
 * Represents the health status of the Python Model Server.
 * Contains information about loaded models, server status, and feature count.
 */
public class ServerHealthStatus {
    private boolean encoderLoaded;
    private boolean featuresLoaded;
    private boolean modelLoaded;
    private boolean scalerLoaded;
    private String status;
    private int totalFeatures;
    private String errorMessage;

    // Logger
     private static final LogObj log = new LogObj("ServerHealthStatus");

    /**
     * Constructor for successful health check
     * 
     * @param encoderLoaded Whether the encoder model is loaded
     * @param featuresLoaded Whether the features are loaded
     * @param modelLoaded Whether the main model is loaded
     * @param scalerLoaded Whether the scaler is loaded
     * @param status The server status message
     * @param totalFeatures The total number of features
     */
    public ServerHealthStatus(boolean encoderLoaded, boolean featuresLoaded, boolean modelLoaded, 
                             boolean scalerLoaded, String status, int totalFeatures) {
        this.encoderLoaded = encoderLoaded;
        this.featuresLoaded = featuresLoaded;
        this.modelLoaded = modelLoaded;
        this.scalerLoaded = scalerLoaded;
        this.status = status;
        this.totalFeatures = totalFeatures;
        this.errorMessage = null;

        log.info("ServerHealthStatus created");
    }

    /**
     * Constructor for failed health check
     * 
     * @param errorMessage The error message
     */
    public ServerHealthStatus(String errorMessage) {
        this.encoderLoaded = false;
        this.featuresLoaded = false;
        this.modelLoaded = false;
        this.scalerLoaded = false;
        this.status = "error";
        this.totalFeatures = 0;
        this.errorMessage = errorMessage;

        log.error("ServerHealthStatus error: " + errorMessage);
    }

    /**
     * Checks if the health check was successful
     * 
     * @return true if the health check was successful, false otherwise
     */
    public boolean isHealthy() {
        return errorMessage == null && "healthy".equals(status);
    }

    /**
     * Gets whether all models are loaded
     * 
     * @return true if all models are loaded, false otherwise
     */
    public boolean areAllModelsLoaded() {
        return encoderLoaded && featuresLoaded && modelLoaded && scalerLoaded;
    }

    /**
     * Gets whether the encoder model is loaded
     * 
     * @return true if the encoder model is loaded, false otherwise
     */
    public boolean isEncoderLoaded() {
        return encoderLoaded;
    }

    /**
     * Gets whether the features are loaded
     * 
     * @return true if the features are loaded, false otherwise
     */
    public boolean isFeaturesLoaded() {
        return featuresLoaded;
    }

    /**
     * Gets whether the main model is loaded
     * 
     * @return true if the main model is loaded, false otherwise
     */
    public boolean isModelLoaded() {
        return modelLoaded;
    }

    /**
     * Gets whether the scaler is loaded
     * 
     * @return true if the scaler is loaded, false otherwise
     */
    public boolean isScalerLoaded() {
        return scalerLoaded;
    }

    /**
     * Gets the server status message
     * 
     * @return The server status message
     */
    public String getStatus() {
        return status;
    }

    /**
     * Gets the total number of features
     * 
     * @return The total number of features
     */
    public int getTotalFeatures() {
        return totalFeatures;
    }

    /**
     * Gets the error message if the health check failed
     * 
     * @return The error message, or null if the health check was successful
     */
    public String getErrorMessage() {
        return errorMessage;
    }
}