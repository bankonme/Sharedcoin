/*
 * Copyright 2011-2012 the original author or authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


package piuk;

import com.google.bitcoin.core.*;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.params.HttpConnectionParams;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;
import org.json.simple.parser.JSONParser;
import org.spongycastle.util.encoders.Hex;
import piuk.common.Pair;
import piuk.website.AdminServlet;
import piuk.website.Settings;

import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.*;
import java.util.*;


@SuppressWarnings("unchecked")
public class MyRemoteWallet extends MyWallet {

    private String _checksum;
    private boolean _isNew = false;
    private MyBlock latestBlock;
    private long lastMultiAddress;
    private BigInteger final_balance = BigInteger.ZERO;
    private BigInteger total_received = BigInteger.ZERO;
    private BigInteger total_sent = BigInteger.ZERO;
    private String currencyCode;
    private double currencyConversion;
    private Map<String, JSONObject> multiAddrBalancesRoot;
    private double sharedFee;
    private List<MyTransaction> transactions = Collections.synchronizedList(new ArrayList<MyTransaction>());
    public byte[] extra_seed;

    public static String getApiCode() {
        return Settings.instance().getString("api_code");
    }


    public MyBlock getLatestBlock() {
        return latestBlock;
    }

    public void setFinal_balance(BigInteger final_balance) {
        this.final_balance = final_balance;
    }

    public void setTotal_received(BigInteger total_received) {
        this.total_received = total_received;
    }

    public void setTotal_sent(BigInteger total_sent) {
        this.total_sent = total_sent;
    }

    public long getLastMultiAddress() {
        return lastMultiAddress;
    }

    public void setLatestBlock(MyBlock latestBlock) {
        this.latestBlock = latestBlock;
    }

    public BigInteger getFinal_balance() {
        return final_balance;
    }

    public BigInteger getTotal_received() {
        return total_received;
    }

    public BigInteger getTotal_sent() {
        return total_sent;
    }

    public String getCurrencyCode() {
        return currencyCode;
    }


    public double getCurrencyConversion() {
        return currencyConversion;
    }


    public Map<String, JSONObject> getMultiAddrBalancesRoot() {
        return multiAddrBalancesRoot;
    }


    public double getSharedFee() {
        return sharedFee;
    }

    public boolean isAddressMine(String address) {
        for (Map<String, Object> map : this.getKeysMap()) {
            String addr = (String) map.get("addr");

            if (address.equals(addr))
                return true;
        }

        return false;
    }

    public static class Latestblock {
        int height;
        int block_index;
        Hash hash;
        long time;
    }

    public synchronized BigInteger getBalance() {
        return final_balance;
    }


    public synchronized BigInteger getBalance(String address) {
        if (this.multiAddrBalancesRoot != null && this.multiAddrBalancesRoot.containsKey(address)) {
            return BigInteger.valueOf(((Number) this.multiAddrBalancesRoot.get(address).get("final_balance")).longValue());
        }

        return BigInteger.ZERO;
    }

    public synchronized int getNtx(String address) {
        if (this.multiAddrBalancesRoot != null && this.multiAddrBalancesRoot.containsKey(address)) {
            return ((Number) this.multiAddrBalancesRoot.get(address).get("n_tx")).intValue();
        }

        return 0;
    }

    public boolean isNew() {
        return _isNew;
    }

    public MyRemoteWallet() throws Exception {
        super();

        this.temporyPassword = null;

        this._checksum = null;

        this._isNew = true;
    }

    public MyRemoteWallet(String base64Payload, String password) throws Exception {
        super(base64Payload, password);

        this.temporyPassword = password;

        this._checksum = new String(Hex.encode(MessageDigest.getInstance("SHA-256").digest(base64Payload.getBytes("UTF-8"))));

        this._isNew = false;
    }

    public static String fetchAPI(String path) throws Exception {

        final List<String> apiRoots = AdminServlet.getApiRoots();

        Exception _e = null;

        for (String root : apiRoots) {
            try {
                return fetchURL(root + path);
            } catch (Exception e) {
                _e = e;
            }
        }

        if (_e != null)
            throw _e;
        else
            throw new Exception("Shouldn't be here. apiRoots is empty?");
    }

    private static String fetchURL(String URL) throws Exception {

        if (URL.indexOf("?") > 0) {
            URL += "&api_code=" + getApiCode();
        } else {
            URL += "?api_code=" + getApiCode();
        }

        URL url = new URL(URL);

        HttpURLConnection connection = (HttpURLConnection) url.openConnection();

        try {
            connection.setRequestProperty("Accept", "application/json");
            connection.setRequestProperty("charset", "utf-8");
            connection.setRequestMethod("GET");

            connection.setConnectTimeout(180000);
            connection.setReadTimeout(180000);

            connection.setInstanceFollowRedirects(false);

            connection.connect();

            if (connection.getResponseCode() == 200)
                return IOUtils.toString(connection.getInputStream(), "UTF-8");
            else if (connection.getResponseCode() == 500)
                throw new Exception("Error From Server: " + IOUtils.toString(connection.getErrorStream(), "UTF-8"));
            else
                throw new Exception("Unknown response from server (" + connection.getResponseCode() + ") " + IOUtils.toString(connection.getErrorStream(), "UTF-8"));

        } finally {
            connection.disconnect();
        }
    }

    private List<MyTransactionOutPoint> filter(List<MyTransactionOutPoint> unspent, List<ECKey> tempKeys) throws Exception {
        List<MyTransactionOutPoint> filtered = new ArrayList<>();

        Set<String> alreadyAskedFor = new HashSet<>();

        for (MyTransactionOutPoint output : unspent) {
            BitcoinScript script = new BitcoinScript(output.getScriptBytes());

            String addr = script.getAddress().toString();

            Map<String, Object> keyMap = findKey(addr);

            if (keyMap.get("priv") != null) {
                filtered.add(output);
            }
        }

        return filtered;
    }


    public boolean send(final String[] from, final String toAddress, final String changeAddress, final BigInteger amount, final BigInteger baseFee, boolean consumeAllOutputs) throws Exception {

        final List<ECKey> tempKeys = new ArrayList<>();

        List<MyTransactionOutPoint> allUnspent = getUnspentOutputPoints(from, 0, 200);

        Pair<Transaction, Long> pair = null;

        //Try without asking for watch only addresses
        List<MyTransactionOutPoint> unspent = filter(allUnspent, tempKeys);

        pair = makeTransaction(unspent, toAddress, changeAddress, amount, baseFee, consumeAllOutputs);

        //Transaction cancelled
        if (pair == null)
            return false;

        Transaction tx = pair.getFirst();

        Wallet wallet = new Wallet(NetworkParameters.prodNet());

        for (String _from : from) {
            wallet.addKey(getECKey(_from));
        }

        wallet.addKeys(tempKeys);

        //Now sign the inputs
        tx.signInputs(Transaction.SigHash.ALL, wallet);

        return pushTx(tx);
    }


    public static String postAPI(String path, String urlParameters) throws Exception {

        final List<String> apiRoots = AdminServlet.getApiRoots();

        Exception _e = null;

        for (String root : apiRoots) {
            try {
                return postURL(root + path, urlParameters);
            } catch (Exception e) {
                _e = e;
            }
        }

        if (_e != null)
            throw _e;
        else
            throw new Exception("Shouldn't be here. apiRoots is empty?");
    }


    private static String postURL(String request, String urlParameters) throws Exception {
        if (urlParameters.length() > 0) {
            urlParameters += "&";
        }

        urlParameters += "api_code=" + getApiCode();

        DefaultHttpClient client = new DefaultHttpClient();

        HttpConnectionParams.setConnectionTimeout(client.getParams(), 180000);
        HttpConnectionParams.setSoTimeout(client.getParams(), 180000);

        final HttpPost httpPost = new HttpPost(request);

        httpPost.setEntity(new StringEntity(urlParameters, "application/x-www-form-urlencoded", "UTF-8"));

        final HttpResponse response = client.execute(httpPost);

        if (response.getStatusLine().getStatusCode() != 200) {
            throw new Exception("Invalid HTTP Response code " + response.getStatusLine().getStatusCode() + " " + IOUtils.toString(response.getEntity().getContent()));
        }

        String responseString = IOUtils.toString(response.getEntity().getContent(), "UTF-8");

        return responseString;
    }

    public List<MyTransaction> getMyTransactions() {
        return transactions;
    }

    public boolean addTransaction(MyTransaction tx) {

        for (MyTransaction existing_tx : transactions) {
            if (existing_tx.getTxIndex() == tx.getTxIndex())
                return false;
        }

        this.transactions.add(tx);

        return true;
    }

    public boolean prependTransaction(MyTransaction tx) {

        for (MyTransaction existing_tx : transactions) {
            if (existing_tx.getTxIndex() == tx.getTxIndex())
                return false;
        }

        this.transactions.add(0, tx);

        return true;
    }

    public BigInteger getBaseFee() {
        BigInteger baseFee = null;
        if (getFeePolicy() == -1) {
            baseFee = Utils.toNanoCoins("0.0001");
        } else if (getFeePolicy() == 1) {
            baseFee = Utils.toNanoCoins("0.001");
        } else {
            baseFee = Utils.toNanoCoins("0.0005");
        }

        return baseFee;
    }

    public List<MyTransaction> getTransactions() {
        return this.transactions;
    }

    public void parseMultiAddr(String response) throws Exception {

        transactions.clear();

        Map<String, Object> top = (Map<String, Object>) JSONValue.parse(response);

        Map<String, Object> info_obj = (Map<String, Object>) top.get("info");

        Map<String, Object> block_obj = (Map<String, Object>) info_obj.get("latest_block");

        if (block_obj != null) {
            Sha256Hash hash = new Sha256Hash(Hex.decode((String) block_obj.get("hash")));
            int blockIndex = ((Number) block_obj.get("block_index")).intValue();
            int blockHeight = ((Number) block_obj.get("height")).intValue();
            long time = ((Number) block_obj.get("time")).longValue();

            MyBlock block = new MyBlock();

            block.height = blockHeight;
            block.hash = hash;
            block.blockIndex = blockIndex;
            block.time = time;

            this.latestBlock = block;
        }

        List<JSONObject> multiAddrBalances = (List<JSONObject>) top.get("addresses");

        Map<String, JSONObject> multiAddrBalancesRoot = new HashMap<String, JSONObject>();

        for (JSONObject obj : multiAddrBalances) {
            multiAddrBalancesRoot.put((String) obj.get("address"), obj);
        }

        this.multiAddrBalancesRoot = multiAddrBalancesRoot;

        Map<String, Object> symbol_local = (Map<String, Object>) info_obj.get("symbol_local");

        if (symbol_local != null && symbol_local.containsKey("code")) {
            String currencyCode = (String) symbol_local.get("code");
            Double currencyConversion = (Double) symbol_local.get("conversion");

            if (currencyConversion == null)
                currencyConversion = 0d;

            if (this.currencyCode == null || !this.currencyCode.equals(currencyCode) || this.currencyConversion != currencyConversion) {
                this.currencyCode = currencyCode;
                this.currencyConversion = currencyConversion;
            }
        }

        if (top.containsKey("mixer_fee")) {
            sharedFee = ((Number) top.get("mixer_fee")).doubleValue();
        }

        Map<String, Object> wallet_obj = (Map<String, Object>) top.get("wallet");

        this.final_balance = BigInteger.valueOf(((Number) wallet_obj.get("final_balance")).longValue());
        this.total_sent = BigInteger.valueOf(((Number) wallet_obj.get("total_sent")).longValue());
        this.total_received = BigInteger.valueOf(((Number) wallet_obj.get("total_received")).longValue());

        List<Map<String, Object>> transactions = (List<Map<String, Object>>) top.get("txs");

        MyTransaction newestTransaction = null;
        if (transactions != null) {
            for (Map<String, Object> transactionDict : transactions) {
                MyTransaction tx = MyTransaction.fromJSONDict(transactionDict);

                if (tx == null)
                    continue;

                if (newestTransaction == null)
                    newestTransaction = tx;

                addTransaction(tx);
            }
        }
    }

    public boolean isUptoDate(long time) {
        long now = System.currentTimeMillis();

        if (lastMultiAddress < now - time) {
            return false;
        } else {
            return true;
        }
    }

    public synchronized String doMultiAddr() throws Exception {
        String url = "multiaddr";

        String params = "active=" + StringUtils.join(getActiveAddresses(), "|");

        String response = postAPI(url, params);

        parseMultiAddr(response);

        lastMultiAddress = System.currentTimeMillis();

        return response;
    }


    public static Map<String, Long> getMultiAddrBalances(List<String> addresses) throws Exception {
        String url = "multiaddr";

        String params = "simple=true&active=" + StringUtils.join(addresses, "|");

        String response = postAPI(url, params);

        Map<String, Object> top = (Map<String, Object>) JSONValue.parse(response);

        Map<String, Long> results = new HashMap<>();
        for (Map.Entry<String, Object> entry : top.entrySet()) {
            String address = entry.getKey();
            Long final_balance = Long.valueOf(((JSONObject) entry.getValue()).get("final_balance").toString());

            results.put(address, final_balance);
        }
        return results;
    }

    public static long getLatestBlockHeightFromQueryAPI() throws Exception {
        return Long.valueOf(fetchAPI("q/getblockcount"));
    }

    public static long getMaxConfirmingBlockHeightForTransactionConfirmations(String addresses) throws Exception {
        String url = "multiaddr";

        String params = "active=" + addresses;

        String response = postAPI(url, params);

        Map<String, Object> top = (Map<String, Object>) JSONValue.parse(response);

        if (top == null) {
            return -1;
        }

        JSONArray txs = (JSONArray) top.get("txs");

        if (txs == null) {
            return -1;
        }

        long maxBlockHeight = -1;
        for (Object obj : txs) {
            JSONObject txObj = (JSONObject) obj;

            long blockHeight = 0;

            if (txObj.get("block_height") == null)
                blockHeight = 0;
            else
                blockHeight = Long.valueOf(txObj.get("block_height").toString());

            if (blockHeight == 0)
                return -1;

            if (blockHeight > maxBlockHeight) {
                maxBlockHeight = blockHeight;
            }
        }

        return maxBlockHeight;
    }


    public synchronized boolean remoteSave() throws Exception {
        return remoteSave(null);
    }

    //Returns response message
    public static boolean pushTx(Transaction tx) throws Exception {

        String hexString = new String(Hex.encode(tx.bitcoinSerialize()));

        postAPI("pushtx", "tx=" + hexString);

        return true;
    }

    public static class InsufficientFundsException extends Exception {
        private static final long serialVersionUID = 1L;

        public InsufficientFundsException(String string) {
            super(string);
        }
    }

    //You must sign the inputs
    public Pair<Transaction, Long> makeTransaction(List<MyTransactionOutPoint> unspent, String toAddress, String changeAddress, BigInteger amount, BigInteger baseFee, boolean consumeAllOutputs) throws Exception {

        long priority = 0;

        if (unspent == null || unspent.size() == 0)
            throw new InsufficientFundsException("No free outputs to spend.");

        if (amount == null || amount.compareTo(BigInteger.ZERO) <= 0)
            throw new Exception("You must provide an amount");

        //Construct a new transaction
        Transaction tx = new Transaction(params);

        //Add the output
        BitcoinScript toOutputScript = BitcoinScript.createSimpleOutBitoinScript(new BitcoinAddress(toAddress));

        TransactionOutput output = new TransactionOutput(params, null, amount, toOutputScript.getProgram());

        tx.addOutput(output);

        //Now select the appropriate inputs
        BigInteger valueSelected = BigInteger.ZERO;
        BigInteger valueNeeded = amount.add(baseFee);
        BigInteger minFreeOutputSize = BigInteger.valueOf(1000000);

        for (MyTransactionOutPoint outPoint : unspent) {

            BitcoinScript script = new BitcoinScript(outPoint.getScriptBytes());

            if (script.getOutType() == BitcoinScript.ScriptOutTypeStrange)
                continue;

            MyTransactionInput input = new MyTransactionInput(params, null, new byte[0], outPoint);

            input.outpoint = outPoint;

            tx.addInput(input);

            valueSelected = valueSelected.add(outPoint.getValue());

            priority += outPoint.getValue().longValue() * outPoint.confirmations;

            if (!consumeAllOutputs) {
                if (valueSelected.compareTo(valueNeeded) == 0 || valueSelected.compareTo(valueNeeded.add(minFreeOutputSize)) >= 0)
                    break;
            }
        }

        //Check the amount we have selected is greater than the amount we need
        if (valueSelected.compareTo(valueNeeded) < 0) {
            throw new InsufficientFundsException("Insufficient Funds");
        }

        long estimatedSize = tx.bitcoinSerialize().length + (138 * tx.getInputs().size());

        BigInteger fee = BigInteger.valueOf((int) Math.ceil(estimatedSize / 1000d)).multiply(baseFee);

        BigInteger change = valueSelected.subtract(amount).subtract(fee);

        if (change.compareTo(BigInteger.ZERO) < 0) {
            throw new Exception("Insufficient Value for Fee. Fix this lazy.");
        } else if (change.compareTo(BigInteger.ZERO) > 0) {
            //Now add the change if there is any
            final BitcoinScript change_script = BitcoinScript.createSimpleOutBitoinScript(new BitcoinAddress(changeAddress));

            TransactionOutput change_output = new TransactionOutput(params, null, change, change_script.getProgram());

            tx.addOutput(change_output);
        }

        estimatedSize = tx.bitcoinSerialize().length + (138 * tx.getInputs().size());

        priority /= estimatedSize;

        return new Pair<Transaction, Long>(tx, priority);
    }


    public static byte[] getScriptForOutpoint(int txIndex, int txOuputN) throws Exception {
        StringBuffer buffer = new StringBuffer("q/outscript?tx_index=" + txIndex + "&tx_output_n=" + txOuputN);

        String response = fetchAPI(buffer.toString());

        return Hex.decode(response);
    }

    public static MyTransaction getTransactionByHash(Hash hash, boolean scripts) throws Exception {
        StringBuffer buffer = new StringBuffer("tx/" + hash + "?format=json&show_adv=true&scripts=" + scripts);

        String response = fetchAPI(buffer.toString());

        Map<String, Object> root = (Map<String, Object>) JSONValue.parse(response);

        return MyTransaction.fromJSONDict(root);
    }

    public static List<MyTransactionOutPoint> getUnspentOutputPoints(String[] from, int min_confirmations, int limit) throws Exception {

        String rootURL = "unspent";

        StringBuffer params = new StringBuffer("limit=" + limit + "&confirmations=" + min_confirmations + "&active=");

        int ii = 0;
        for (String address : from) {
            params.append(address);

            if (ii < from.length - 1)
                params.append("|");

            ++ii;
        }

        List<MyTransactionOutPoint> outputs = new ArrayList<>();

        String response = postAPI(rootURL, params.toString());

        Map<String, Object> root = (Map<String, Object>) JSONValue.parse(response);

        List<Map<String, Object>> outputsRoot = (List<Map<String, Object>>) root.get("unspent_outputs");

        for (Map<String, Object> outDict : outputsRoot) {

            byte[] hashBytes = Hex.decode((String) outDict.get("tx_hash"));

            ArrayUtils.reverse(hashBytes);

            Sha256Hash txHash = new Sha256Hash(hashBytes);

            int txOutputN = ((Number) outDict.get("tx_output_n")).intValue();
            BigInteger value = BigInteger.valueOf(((Number) outDict.get("value")).longValue());
            byte[] scriptBytes = Hex.decode((String) outDict.get("script"));
            int confirmations = ((Number) outDict.get("confirmations")).intValue();

            //Contrstuct the output
            MyTransactionOutPoint outPoint = new MyTransactionOutPoint(txHash, txOutputN, value, scriptBytes);

            outPoint.setConfirmations(confirmations);

            outputs.add(outPoint);
        }

        return outputs;
    }

    /**
     * Register this account/device pair within the server.
     *
     * @throws Exception
     */
    public boolean registerNotifications(final String regId) throws Exception {
        if (_isNew) return false;

        StringBuilder args = new StringBuilder();

        args.append("guid=" + getGUID());
        args.append("&sharedKey=" + getSharedKey());
        args.append("&method=register-android-device");
        args.append("&payload=" + URLEncoder.encode(regId));
        args.append("&length=" + regId.length());

        String response = postAPI("wallet", args.toString());

        return response != null && response.length() > 0;
    }

    /**
     * k
     * Unregister this account/device pair within the server.
     *
     * @throws Exception
     */
    public boolean unregisterNotifications(final String regId) throws Exception {
        if (_isNew) return false;

        StringBuilder args = new StringBuilder();

        args.append("guid=" + getGUID());
        args.append("&sharedKey=" + getSharedKey());
        args.append("&method=unregister-android-device");
        args.append("&payload=" + URLEncoder.encode(regId));
        args.append("&length=" + regId.length());

        String response = postAPI("wallet", args.toString());

        return response != null && response.length() > 0;
    }

    public JSONObject getAccountInfo() throws Exception {
        if (_isNew) return null;

        StringBuilder args = new StringBuilder();

        args.append("guid=" + getGUID());
        args.append("&sharedKey=" + getSharedKey());
        args.append("&method=get-info");
        ;

        String response = postAPI("wallet", args.toString());

        return (JSONObject) new JSONParser().parse(response);
    }

    public boolean updateRemoteCurrency(String currency_code) throws Exception {
        if (_isNew) return false;

        StringBuilder args = new StringBuilder();

        args.append("guid=" + getGUID());
        args.append("&sharedKey=" + getSharedKey());
        args.append("&payload=" + currency_code);
        args.append("&length=" + currency_code.length());
        args.append("&method=update-currency");
        ;

        String response = postAPI("wallet", args.toString());

        return response != null;
    }

    /**
     * Get the tempoary paring encryption password
     *
     * @throws Exception
     */
    public static String getPairingEncryptionPassword(final String guid) throws Exception {
        StringBuilder args = new StringBuilder();

        args.append("guid=" + guid);
        args.append("&method=pairing-encryption-password");

        return postAPI("wallet", args.toString());
    }

    public static BigInteger getAddressBalance(final String address) throws Exception {
        return new BigInteger(fetchAPI("q/addressbalance/" + address));
    }

    public static String getWalletManualPairing(final String guid) throws Exception {
        StringBuilder args = new StringBuilder();

        args.append("guid=" + guid);
        args.append("&method=pairing-encryption-password");

        String response = fetchAPI("wallet/" + guid + "?format=json&resend_code=false");

        JSONObject object = (JSONObject) new JSONParser().parse(response);

        String payload = (String) object.get("payload");
        if (payload == null || payload.length() == 0) {
            throw new Exception("Error Fetching Wallet Payload");
        }

        return payload;
    }

    public synchronized boolean remoteSave(String kaptcha) throws Exception {

        String payload = this.getPayload();

        String old_checksum = this._checksum;

        this._checksum = new String(Hex.encode(MessageDigest.getInstance("SHA-256").digest(payload.getBytes("UTF-8"))));

        String method = _isNew ? "insert" : "update";

        if (kaptcha == null && _isNew) {
            throw new Exception("Must provide a kaptcha to insert wallet");
        } else if (kaptcha == null) {
            kaptcha = "";
        }

        String urlEncodedPayload = URLEncoder.encode(payload);

        StringBuilder args = new StringBuilder();
        args.append("guid=");
        args.append(URLEncoder.encode(this.getGUID(), "utf-8"));
        args.append("&sharedKey=");
        args.append(URLEncoder.encode(this.getSharedKey(), "utf-8"));
        args.append("&payload=");
        args.append(urlEncodedPayload);
        args.append("&method=");
        args.append(method);
        args.append("&length=");
        args.append(payload.length());
        args.append("&checksum=");
        args.append(URLEncoder.encode(_checksum, "utf-8"));
        args.append("&kaptcha=");
        args.append(kaptcha);
        args.append("&device=");
        args.append("android");

        if (old_checksum != null && old_checksum.length() > 0) {
            args.append("&old_checksum=");
            args.append(old_checksum);
        }

        postAPI("wallet", args.toString());

        _isNew = false;

        return true;
    }

    public void remoteDownload() {

    }

    public String getChecksum() {
        return _checksum;
    }

    public synchronized String setPayload(String payload) throws Exception {

        MyRemoteWallet tempWallet = new MyRemoteWallet(payload, temporyPassword);

        this.root = tempWallet.root;
        this.rootContainer = tempWallet.rootContainer;

        if (this.temporySecondPassword != null && !this.validateSecondPassword(temporySecondPassword)) {
            this.temporySecondPassword = null;
        }

        this._checksum = tempWallet._checksum;

        _isNew = false;

        return payload;
    }

    public static class NotModfiedException extends Exception {
        private static final long serialVersionUID = 1L;
    }

    public static String getWalletPayload(String guid, String sharedKey, String checkSumString) throws Exception {
        String payload = fetchAPI("wallet/wallet.aes.json?guid=" + guid + "&sharedKey=" + sharedKey + "&checksum=" + checkSumString);

        if (payload == null) {
            throw new Exception("Error downloading wallet");
        }

        if (payload.equals("Not modified")) {
            throw new NotModfiedException();
        }

        return payload;
    }

    public static String getWalletPayload(String guid, String sharedKey) throws Exception {
        String payload = fetchAPI("wallet/wallet.aes.json?guid=" + guid + "&sharedKey=" + sharedKey);

        if (payload == null) {
            throw new Exception("Error downloading wallet");
        }

        return payload;
    }

}
