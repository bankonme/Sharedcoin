package piuk.website;

import com.google.bitcoin.core.Base58;
import com.google.bitcoin.core.ECKey;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringEscapeUtils;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import piuk.MyRemoteWallet;
import piuk.MyTransactionOutPoint;
import piuk.Util;
import piuk.common.Pair;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.*;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Collections;
import java.util.Map;

@WebServlet({"/sharedcoin-admin"})
public class AdminServlet extends HttpServlet {
    public static final String RecentlyCompletedTransactionsTempPath = System.getProperty("user.home") + "/Sites/" + "recently_completed_transactions_temp.ser";
    public static final String PKSeedCounterFilePath = System.getProperty("user.home") + "/Sites/PK_SEED_COUNTER";
    public static final String DeletedPrivateKeysLogFilePath = System.getProperty("user.home") + "/Sites/DELETED_KEYS";
    public static final String RecentlyCompletedTransactionsPath = System.getProperty("user.home") + "/Sites/" + "recently_completed_transactions.ser";

    public static final String SharedWalletGUID = Settings.instance().getString("wallet_guid");
    public static final String SharedWalletSharedKey = Settings.instance().getString("wallet_shared_key");
    public static final String SharedWalletPassword = Settings.instance().getString("wallet_password");
    public static final String SharedWalletSecondPassword = Settings.instance().getString("wallet_second_password");
    public static final String PKSeed = Settings.instance().getString("pk_seed");
    public static final String TokenEncryptionPassword = Settings.instance().getString("token_encryption_password");
    public static final String AuthCode = Settings.instance().getString("auth_code");

    public static void writePKSeedCounter(int value) throws IOException {
        FileWriter fWriter = new FileWriter(PKSeedCounterFilePath, false);

        fWriter.write(""+value);

        fWriter.flush();

        fWriter.close();
    }

    public static boolean constantEquals(String a, String b) {
        boolean equal = true;
        if (a.length() != b.length()) {
            equal = false;
        }

        for ( int i = 0; i < AuthCode.length(); i++ ) {
            if (Character.toLowerCase(a.charAt(i%a.length())) != Character.toLowerCase(b.charAt(i%b.length())) ) {
                equal = false;
            }
        }

        return equal;
    }

    public static int readPKSeedCounter() throws IOException {
        if (new File(PKSeedCounterFilePath).exists()) {
            FileReader reader = new FileReader(PKSeedCounterFilePath);

            return Integer.valueOf(IOUtils.toString(reader));
        }

        return 0;
    }

    public static String runBASH(String command) throws IOException {
        Process p = Runtime.getRuntime().exec(new String[]{"bash", "-c", command});

        String stdOut = IOUtils.toString(p.getInputStream());
        String stdError = IOUtils.toString(p.getErrorStream());

        if (stdError != null)
            return stdOut + stdError;
        else
            return stdOut;
    }

    public static String getRealIP(HttpServletRequest req) {
        if (req.getHeader("cf-connecting-ip") != null && Settings.instance().getBoolean("cloudflare_enabled"))
            return req.getHeader("cf-connecting-ip");
        else
            return req.getRemoteAddr();
    }

    public static boolean isAuthorized(HttpServletRequest req) {

        HttpSession session = req.getSession(true);
        String code = req.getParameter("code");
        if (session.getAttribute("authorized") != null && session.getAttribute("authorized").equals("true")) {
            return true;
        } else if (code != null && constantEquals(code, AuthCode)) {
            session.setAttribute("authorized", "true");
            return true;
        } else {
            return false;
        }
    }

    public static ECKey decodeBase58PK(String base58Priv) throws Exception {
        byte[] privBytes = Base58.decode(base58Priv);

        // Prppend a zero byte to make the biginteger unsigned
        byte[] appendZeroByte = ArrayUtils.addAll(new byte[1], privBytes);

        ECKey ecKey = new ECKey(new BigInteger(appendZeroByte));

        return ecKey;
    }

    public static void handleResults(List<Pair<String, String>> results) throws Exception {
        StringBuffer params = new StringBuffer("api_code="+Settings.instance().getString("api_code")+"&simple=true&active=");
        for (Pair<String, String> pair : results) {
            params.append(pair.getFirst() + "|");
        }
        params.deleteCharAt(params.length()-1);

        String response = Util.postURL("https://blockchain.info/multiaddr", params.toString(), null);

        Map<String, JSONObject> obj = (JSONObject) new JSONParser().parse(response);

        for (Map.Entry<String, JSONObject> entry : obj.entrySet()) {
            long final_balance = Long.valueOf(entry.getValue().get("final_balance").toString());
            if (final_balance > 0) {

                System.out.println("Final Balance " + final_balance + " address " + entry.getKey());

                final String address = entry.getKey();
                String key = null;

                for (Pair<String, String> pair : results) {
                    if (pair.getFirst().equals(address)) {
                        key = pair.getSecond();
                        break;
                    }
                }

                if (key == null) {
                    throw new Exception("Key null address " + address);
                }

                ECKey ecKey = decodeBase58PK(key);

                if (!SharedCoin.ourWallet.addECKey(address, ecKey))
                    throw new Exception("Error Importing ECKey");

            }
        }
    }

    private static void checkDeletedPrivateKeysLog() throws Exception {
        List<Pair<String, String>> keys = new ArrayList<>();

        File file = new File(DeletedPrivateKeysLogFilePath);

        FileInputStream fstream = new FileInputStream(file);
        BufferedReader br = new BufferedReader(new InputStreamReader(fstream));

        int lineCount = 0;
        while (br.readLine() != null)   {
            ++lineCount;
        }
        System.out.println("Line count " + lineCount);

        fstream = new FileInputStream(file);
        br = new BufferedReader(new InputStreamReader(fstream));

        String strLine;

        int line = 0;
        while ((strLine = br.readLine()) != null)   {
            String[] components = strLine.split(" ");

            if (components.length == 2) {
                keys.add(new Pair<>(components[0], components[1]));
            }

            ++line;
        }
        br.close();

        Collections.reverse(keys);

        List<Pair<String, String>> keysTmp = new ArrayList<>();
        int ii = 0;
        for (Pair<String, String> addressKeyPair : keys) {
            keysTmp.add(addressKeyPair);

            if (keysTmp.size() == 1000 || ii == keysTmp.size()-1) {

                System.out.println("Handle Results " + ii);

                handleResults(keysTmp);

                keysTmp.clear();
            }

            ++ii;
        }
    }

    @Override
    protected void doGet(HttpServletRequest req, final HttpServletResponse res) throws ServletException, IOException {

        if (!isAuthorized(req)) {
            res.setStatus(404);
            return;
        }

        String method = req.getParameter("method");
        if (method != null) {
            if (method.equals("show")) {
                FileInputStream file = new FileInputStream(System.getProperty("catalina.base") + "/logs/catalina.out");

                String log = IOUtils.toString(file, "UTF-8");

                res.setContentType("text/plain");

                res.getWriter().print(StringEscapeUtils.escapeHtml4(log));

            } else if (method.equals("clear")) {
                FileOutputStream erasor = new FileOutputStream(System.getProperty("catalina.base") + "/logs/catalina.out");
                erasor.write(new String().getBytes());
                erasor.close();

                res.sendRedirect("/sharedcoin-admin");
            } else if (method.equals("threads")) {
                res.setContentType("text/plain");


                res.getWriter().print("Threads \n\n");

                ThreadGroup root = Thread.currentThread().getThreadGroup().getParent();
                while (root.getParent() != null) {
                    root = root.getParent();
                }

                StringBuffer buff = new StringBuffer();

                visitThread(root, 0, buff);

                res.getWriter().print(buff);
            } else {
                throw new ServletException("Unknown Method");
            }
        } else {
            getServletContext().getRequestDispatcher("/WEB-INF/sharedcoin-admin-index.jsp").forward(req, res);
        }
    }


    // This method recursively visits all thread groups under `group'.
    public static void visitThread(ThreadGroup group, int level, StringBuffer buff) {
        // Get threads in `group'
        int numThreads = group.activeCount();
        Thread[] threads = new Thread[numThreads * 2];
        numThreads = group.enumerate(threads, false);

        // Enumerate each thread in `group'
        for (int i = 0; i < numThreads; i++) {
            // Get thread
            Thread thread = threads[i];

            buff.append("Thread: " + thread.toString() + "\n");

            StackTraceElement[] stackTrace = thread.getStackTrace();

            if (stackTrace != null) {
                for (StackTraceElement element : stackTrace) {
                    buff.append(element.toString());
                    buff.append("\n");
                }
            }

            buff.append("\n");
        }

        // Get thread subgroups of `group'
        int numGroups = group.activeGroupCount();
        ThreadGroup[] groups = new ThreadGroup[numGroups * 2];
        numGroups = group.enumerate(groups, false);

        // Recursively visit each subgroup
        for (int i = 0; i < numGroups; i++) {
            visitThread(groups[i], level + 1, buff);
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, final HttpServletResponse res) throws ServletException, IOException {

        if (!isAuthorized(req)) {
            res.setStatus(404);
            return;
        }

        try {
            String method = req.getParameter("method");
            if (method != null) {
                if (method.equals("git_pull_and_restart")) {
                    runBASH("cd ~/Sites/api.sharedcoin.com && git stash save --keep-index");

                    System.out.println(runBASH("cd ~/Sites/api.sharedcoin.com && git pull"));

                    System.out.println(runBASH("cd ~/Sites/api.sharedcoin.com && ant stop-tomcat && ant start-tomcat"));
                } else if (method.equals("tidy_wallet")) {
                    SharedCoin.ourWallet.tidyTheWallet();

                    res.sendRedirect("/sharedcoin-admin");
                } else if (method.equals("wallet_balance")) {
                    String payload = MyRemoteWallet.getWalletPayload(AdminServlet.SharedWalletGUID, AdminServlet.SharedWalletSharedKey);

                    MyRemoteWallet remoteWallet = new MyRemoteWallet(payload, AdminServlet.SharedWalletPassword);

                    remoteWallet.doMultiAddr();

                    res.getWriter().print(remoteWallet.getFinal_balance());
                } else if (method.equals("divide_large_outputs")) {
                    SharedCoin.ourWallet.divideLargeOutputs();
                } else if (method.equals("print_unspent")) {
                    List<MyTransactionOutPoint> outputs = SharedCoin.ourWallet.getUnspentOutputs(1000);

                    res.getWriter().println("Size : " + outputs.size());

                    res.getWriter().print(outputs);
                } else if (method.equals("check_deleted_private_keys_log")) {

                    new Thread(new Runnable() {
                        @Override
                        public void run() {
                            try {
                                checkDeletedPrivateKeysLog();
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        }
                    }).start();


                    res.sendRedirect("/sharedcoin-admin");
                } else {
                    throw new Exception("Unknown Method");
                }
            } else {
                throw new Exception("No Method");
            }
        } catch (Exception e) {
            e.printStackTrace();

            res.setStatus(500);

            res.getWriter().print(e.getLocalizedMessage());
        }
    }
}
