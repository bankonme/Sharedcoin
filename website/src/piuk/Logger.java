package piuk;

import javax.servlet.http.HttpServletRequest;
import java.util.Date;

public class Logger {
    public static final int SeverityWARN = 0;
    public static final int SeverityError = 1;
    public static final int SeveritySeriousError = 2;
    public static final int SeveritySecurityError = 3;
    public static final int SeverityINFO = 4;

    public static boolean log = true;
    public static boolean logInfo = false;

    public static void log(int severity, final Object args) {
        if (severity == SeverityINFO) {
            if (logInfo) System.out.println(new Date() + " INFO: " + args);
        } else if (log) {
            System.out.println(args);
        }
    }

    public static void log(int severity, final Exception e) {
        log(severity, e, null);
    }

    public static void log(int severity, Exception e, HttpServletRequest req) {

        if (severity == SeveritySecurityError || severity == SeveritySeriousError) {
            e.printStackTrace();
        } else if (log) {
            e.printStackTrace();
        }
    }
}
