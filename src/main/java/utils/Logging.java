package utils;

import java.text.SimpleDateFormat;
import java.util.Date;

public class Logging {
    public static boolean shouldLog = true;

    public static void log(Object msg) {
        if (shouldLog) {
            System.out.println(msg);
        }
    }

    public static void log(Object log, Object context) {
        if (shouldLog) {
            System.out.print(log + " ");
            System.out.println(context);
        }
    }

    public static void warn(Object msg) {
        if (shouldLog) {
            System.err.println(msg);
        }
    }

    public static void warn(Object log, Object context) {
        if (shouldLog) {
            System.err.print(log + " ");
            System.out.println(context);
        }
    }

    public static void error(Object msg) {
        if (shouldLog) {
            System.err.println(msg);
        }
    }

    public static void error(Object log, Object context) {
        if (shouldLog) {
            System.err.print(log + " ");
            System.out.println(context);
        }
    }
}