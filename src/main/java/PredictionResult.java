import utils.LogObj;

/**
 * Class to store and manage prediction results from the model server.
 * Contains fields for prediction value, label, confidence, and probabilities.
 */
public class PredictionResult {
    private int prediction;
    private String predictionLabel;
    private double confidence;
    private double normalProbability;
    private double attackProbability;
    private String status;
    private String errorMessage;

    // Logger
     private static final LogObj log = new LogObj("PredictionResult");

    /**
     * Default constructor
     */
    public PredictionResult() {
        this.status = "unknown";
    }

    /**
     * Constructor for successful predictions
     * 
     * @param prediction The prediction value (0 for Normal, 1 for Attack)
     * @param predictionLabel The prediction label ("Normal" or "Attack")
     * @param confidence The confidence value of the prediction
     * @param normalProbability The probability of being Normal
     * @param attackProbability The probability of being Attack
     */
    public PredictionResult(int prediction, String predictionLabel, double confidence, 
                           double normalProbability, double attackProbability) {
        this.prediction = prediction;
        this.predictionLabel = predictionLabel;
        this.confidence = confidence;
        this.normalProbability = normalProbability;
        this.attackProbability = attackProbability;
        this.status = "success";

        log.info("PredictionResult created");
    }

    /**
     * Constructor for error cases
     * 
     * @param errorMessage The error message
     */
    public PredictionResult(String errorMessage) {
        log.info(errorMessage);
        this.status = "error";
        this.errorMessage = errorMessage;
    }

    /**
     * @return The prediction value (0 for Normal, 1 for Attack)
     */
    public int getPrediction() {
        return prediction;
    }

    /**
     * @param prediction The prediction value to set
     */
    public void setPrediction(int prediction) {
        this.prediction = prediction;
    }

    /**
     * @return The prediction label ("Normal" or "Attack")
     */
    public String getPredictionLabel() {
        return predictionLabel;
    }

    /**
     * @param predictionLabel The prediction label to set
     */
    public void setPredictionLabel(String predictionLabel) {
        this.predictionLabel = predictionLabel;
    }

    /**
     * @return The confidence value of the prediction
     */
    public double getConfidence() {
        return confidence;
    }

    /**
     * @param confidence The confidence value to set
     */
    public void setConfidence(double confidence) {
        this.confidence = confidence;
    }

    /**
     * @return The probability of being Normal
     */
    public double getNormalProbability() {
        return normalProbability;
    }

    /**
     * @param normalProbability The normal probability to set
     */
    public void setNormalProbability(double normalProbability) {
        this.normalProbability = normalProbability;
    }

    /**
     * @return The probability of being Attack
     */
    public double getAttackProbability() {
        return attackProbability;
    }

    /**
     * @param attackProbability The attack probability to set
     */
    public void setAttackProbability(double attackProbability) {
        this.attackProbability = attackProbability;
    }

    /**
     * @return The status of the prediction ("success" or "error")
     */
    public String getStatus() {
        return status;
    }

    /**
     * @param status The status to set
     */
    public void setStatus(String status) {
        this.status = status;
    }

    /**
     * @return The error message (if status is "error")
     */
    public String getErrorMessage() {
        return errorMessage;
    }

    /**
     * @param errorMessage The error message to set
     */
    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    /**
     * @return A formatted string representation of the prediction result
     */
    public String getFormattedResult() {
        log.info("Generating formatted result");

        if ("error".equals(status)) {
            return "Error: " + errorMessage;
        }
        
        StringBuilder result = new StringBuilder();
        result.append("Prediction: ").append(predictionLabel)
              .append(" (").append(prediction).append(")\n");
        result.append("Confidence: ").append(String.format("%.2f", confidence)).append("\n");
        result.append("Probabilities: Normal=").append(String.format("%.2f", normalProbability))
              .append(", Attack=").append(String.format("%.2f", attackProbability)).append("\n");
        result.append("Status: ").append(status);
        
        return result.toString();
    }

    /**
     * @return A CSV string representation of the prediction result
     */
    public String toCsvString() {
        log.info("Converting CSV string");

        if ("error".equals(status)) {
            return "error,,,," + errorMessage;
        }
        
        return String.format("%d,%s,%.4f,%.4f,%.4f,%s", 
                prediction, predictionLabel, confidence, 
                normalProbability, attackProbability, status);
    }

    /**
     * @return The CSV header for prediction results
     */
    public static String getCsvHeader() {
        log.info("Converting CSV header");

        return "prediction,prediction_label,confidence,normal_probability,attack_probability,status,error_message";
    }
}