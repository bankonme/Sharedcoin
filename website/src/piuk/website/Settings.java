package piuk.website;

import org.apache.commons.io.IOUtils;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import piuk.MyWallet;

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;


public class Settings {
    private static Settings instance;
    private JSONObject root;
    public static final String DefaultNamespace = "sharedcoin.com";

    private String getEncryptionPassword() throws IOException {
        return System.getProperty("settings-encryption-password");
    }

    static {
        reloadSettings();
    }

    private JSONObject getNamespace(String namespace) {
        return (JSONObject) root.get(namespace);
    }

    public boolean getBoolean(String namespace, String key) {
        try {
            return (Boolean) getNamespace(namespace).get(key);
        } catch (Exception e) {
            return false;
        }
    }

    public boolean getBoolean(String key) {
        return getBoolean(DefaultNamespace, key);
    }

    public Object getObject(String namespace, String key) {
        try {
            return getNamespace(namespace).get(key);
        } catch (Exception e) {
            return null;
        }
    }

    public Object getObject(String key) {
        return getObject(DefaultNamespace, key);
    }

    public String getString(String namespace, String key) {
        try {
            Object obj = getNamespace(namespace).get(key);

            if (obj == null)
                return null;
            else
                return obj.toString();

        } catch (Exception e) {
            return null;
        }
    }

    public String getString(String key) {
        return getString(DefaultNamespace, key);
    }

    public int getInt(String namespace, String key) {
        try {
            Object obj = getNamespace(namespace).get(key);

            if (obj instanceof Integer)
                return (Integer) obj;
            else if (obj instanceof Long)
                return ((Long) obj).intValue();
            else
                throw new Exception("Cannot Cast to int");

        } catch (Exception e) {
            return 0;
        }
    }

    public int getInt(String key) {
        return getInt(DefaultNamespace, key);
    }

    public long getLong(String namespace, String key) {
        try {
            return ((Number) getNamespace(namespace).get(key)).longValue();
        } catch (Exception e) {
            return 0;
        }
    }

    public long getLong(String key) {
        return getLong(DefaultNamespace, key);
    }

    public double getDouble(String namespace, String key) {
        try {
            return ((Number) getNamespace(namespace).get(key)).doubleValue();
        } catch (Exception e) {
            return 0;
        }
    }

    public double getDouble(String key) {
        return getDouble(DefaultNamespace, key);
    }

    public List<Object> getList(String namespace, String key) {
        JSONArray array = (JSONArray) getNamespace(namespace).get(key);

        List<Object> list = new ArrayList<>();

        if (array == null) {
            return list;
        }
        for (Object obj : array) {
            list.add(obj);
        }

        return list;
    }

    public List<String> getStringList(String namespace, String key) {
        return (List<String>) (List<?>) getList(namespace, key);
    }

    public List<String> getStringList(String key) {
        return getStringList(DefaultNamespace, key);
    }

    public List<Object> getList(String key) {
        return getList(DefaultNamespace, key);
    }

    public Map<String, Object> getMap(String namespace, String key) {
        return (JSONObject) getNamespace(namespace).get(key);
    }

    public Map<String, Object> getMap(String key) {
        return getMap(DefaultNamespace, key);
    }

    public static Settings instance() {
        return instance;
    }

    private void setGlobalSettings(String encrypted_settings) throws Exception {
        System.out.println(getEncryptionPassword());

        String decrypted_settings = MyWallet.decrypt(encrypted_settings, getEncryptionPassword(), MyWallet.DefaultPBKDF2Iterations);

        JSONObject globalObj = (JSONObject) new JSONParser().parse(decrypted_settings);

        for (Object namespace : globalObj.keySet()) {
            getNamespace((String) namespace).putAll((JSONObject) globalObj.get(namespace));
        }
    }

    public static String getGlobalAESSettingsFile() throws Exception {
        String path = System.getProperty("catalina.base") + "/../settings_global.aes.json";

        if (!new File(path).exists())
            throw new Exception("Error Reading " + path);

        return IOUtils.toString(new FileInputStream(path));
    }

    public static String getLocalSettingsFile() throws Exception {
        String path =System.getProperty("catalina.base") + "/../settings_local.json";

        if (!new File(path).exists())
            throw new Exception("Error Reading " + path);

        return IOUtils.toString(new FileInputStream(path));
    }

    public static FileOutputStream openGlobalSettingsFile() throws FileNotFoundException {
        return new FileOutputStream(System.getProperty("user.home") + "/Sites/settings_global.aes.json");
    }

    public static void reloadSettings() {
        System.out.println( System.getProperty("catalina.base"));

        try {
            Settings settings = new Settings();

            JSONObject localObj = (JSONObject) new JSONParser().parse(getLocalSettingsFile());

            Settings.instance = settings;

            settings.root = localObj;

            settings.setGlobalSettings(getGlobalAESSettingsFile());
        } catch (Exception e) {
            e.printStackTrace();

            System.exit(0);
        }
    }
}
