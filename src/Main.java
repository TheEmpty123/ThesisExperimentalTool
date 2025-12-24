import javax.swing.*;
import java.awt.*;

/**
 * Main class for the Thesis Experimental Tool.
 * This tool allows testing network attack detection models by:
 * 1. Inputting test data
 * 2. Sending data to a Python Model Server via HTTP
 * 3. Receiving and displaying prediction results
 */
public class Main {
    public static void main(String[] args) {
        // Set look and feel to system default
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception e) {
            e.printStackTrace();
        }

        // Create and show the GUI on the Event Dispatch Thread
        SwingUtilities.invokeLater(() -> {
            ExperimentalToolGUI gui = new ExperimentalToolGUI();
            gui.setVisible(true);
        });
    }
}
