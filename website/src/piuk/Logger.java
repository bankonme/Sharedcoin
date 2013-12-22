package piuk;

import javax.servlet.http.HttpServletRequest;

public class Logger {
    public static final int SeverityWARN = 0;
    public static final int SeverityError = 1;
    public static final int SeveritySeriousError = 2;
    public static final int SeveritySecurityError = 3;

    public static boolean log = true;

    public static void log(int severity, Object args) {
        if (log) System.out.println(args);
    }

    public static void log(int severity, Exception e) {
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
