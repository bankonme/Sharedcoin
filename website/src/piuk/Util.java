package piuk;

import org.apache.commons.io.IOUtils;
import org.spongycastle.util.encoders.Hex;

import java.io.DataOutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.util.*;


public final class Util {
    public static String postURL(String request, String urlParameters) throws Exception {
        return postURL(request, urlParameters, null);
    }

    public static String postURL(String request) throws Exception {

        URL url = new URL(request);

        String hostString = url.getProtocol() + "://" + url.getHost();

        if (url.getPort() > 0) {
            hostString += ":" + url.getPort();
        }

        if (url.getPath() != null && url.getPath().length() > 0)
            hostString += url.getPath();
        else
            hostString += "/";

        return postURL(hostString, url.getQuery(), null);
    }

    public static <T> List<List<T>> divideListInSublistsOfNSize(List<T> list, int n) {
        final List<List<T>> container = new ArrayList<>();

        List<T> cList = new ArrayList<>();
        for (T o : list) {
            cList.add(o);

            if (cList.size() == n) {
                container.add(cList);
                cList = new ArrayList<>();
            }
        }

        if (cList != null && cList.size() > 0) {
            container.add(cList);
        }

        return container;
    }

    public static <K, V extends Comparable<? super V>>
    SortedSet<Map.Entry<K, V>> entriesSortedByValues(Map<K, V> map) {
        SortedSet<Map.Entry<K, V>> sortedEntries = new TreeSet<Map.Entry<K, V>>(
                new Comparator<Map.Entry<K, V>>() {
                    @Override
                    public int compare(Map.Entry<K, V> e1, Map.Entry<K, V> e2) {
                        int res = e2.getValue().compareTo(e1.getValue());
                        return res != 0 ? res : 1; // Special fix to preserve items with equal values

                    }
                }
        );
        sortedEntries.addAll(map.entrySet());
        return sortedEntries;
    }

    public static String uppercaseFirstLetters(String str)
    {
        boolean prevWasWhiteSp = true;
        char[] chars = str.toCharArray();
        for (int i = 0; i < chars.length; i++) {
            if (Character.isLetter(chars[i])) {
                if (prevWasWhiteSp) {
                    chars[i] = Character.toUpperCase(chars[i]);
                }
                prevWasWhiteSp = false;
            } else {
                prevWasWhiteSp = Character.isWhitespace(chars[i]) || chars[i] == '.';
            }
        }
        return new String(chars);
    }


    public static String getLongestWord(String str) {
        String[] words = str.split("\\W+");
        String longest = null;

        for (String word : words) {
            if (longest == null || word.length() > longest.length())
                longest = word;
        }

        return longest;
    }


    public static String SHA256Hex(String str) throws Exception {
        return new String(Hex.encode(MessageDigest.getInstance("SHA-256").digest(str.getBytes("UTF-8"))), "UTF-8");
    }

    public static Hash SHA256(String str) throws Exception {
        return new Hash(MessageDigest.getInstance("SHA-256").digest(str.getBytes("UTF-8")));
    }

    public static String getURL(String urlString, int timeout) throws Exception {

        URL url = new URL(urlString);

        HttpURLConnection connection = (HttpURLConnection) url.openConnection();

        connection.setConnectTimeout(timeout);
        connection.setReadTimeout(timeout);
        connection.setInstanceFollowRedirects(false);
        connection.setRequestProperty("Accept-Charset", "UTF-8");
        connection.setRequestProperty("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) AppleWebKit/534.53.11 (KHTML, like Gecko) Version/5.1.3 Safari/534.53.10");
        connection.connect();

        if (connection.getResponseCode() != 200) {
            throw new Exception("Invalid HTTP Response code " + connection.getResponseCode());
        }

        return IOUtils.toString(connection.getInputStream(), "UTF-8");
    }
    public static String getURL(String urlString) throws Exception {
        return getURL(urlString, 10000);
    }

    public static Locale getLocaleByCountryCode(String code) {
        code = code.toUpperCase();

        Locale[] availableLocales = Locale.getAvailableLocales();
        for (Locale l : availableLocales) {
            if (l.getCountry().toUpperCase().equals(code))
                return l;
        }

        return null;
    }

    public static String postURL(String request, String urlParameters, Map<String, String> headers) throws Exception {
        URL url = new URL(request);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        try {
            if (connection == null)
                throw new Exception("Error Opening connection");

            connection.setDoOutput(true);
            connection.setDoInput(true);
            connection.setUseCaches(false);
            connection.setInstanceFollowRedirects(true);
            connection.setRequestMethod("POST");
            connection.setRequestProperty("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) AppleWebKit/534.53.11 (KHTML, like Gecko) Version/5.1.3 Safari/534.53.10");
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
            connection.setRequestProperty("Content-Length", "" + Integer.toString(urlParameters.getBytes("UTF-8").length));
            connection.setRequestProperty("Accept-Charset", "UTF-8");

            if (headers != null) {
                for (Map.Entry<String, String> entry : headers.entrySet()) {
                    connection.setRequestProperty(entry.getKey(), entry.getValue());
                }
            }
            connection.connect();

            DataOutputStream wr = new DataOutputStream(connection.getOutputStream());
            wr.write(urlParameters.getBytes("UTF-8"));
            wr.flush();
            wr.close();

            connection.setConnectTimeout(25000);
            connection.setReadTimeout(25000);

            connection.setInstanceFollowRedirects(false);

            if (connection.getResponseCode() != 200) {
                if (connection.getErrorStream() == null && connection.getInputStream() != null)
                    throw new Exception("Null Error - Response Code: " + connection.getResponseCode() + " " + IOUtils.toString(connection.getInputStream(), "UTF-8"));
                else if (connection.getErrorStream() == null)
                    throw new Exception("Null Error Stream - Code: " + connection.getResponseCode());

                throw new Exception("Response Code: " + connection.getResponseCode() + " " + IOUtils.toString(connection.getErrorStream(), "UTF-8"));
            } else {
                return IOUtils.toString(connection.getInputStream(), "UTF-8");
            }

        } finally {
            connection.disconnect();
        }
    }
}
