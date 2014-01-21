package piuk.website;

import com.google.bitcoin.core.*;
import org.apache.commons.lang3.ArrayUtils;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.spongycastle.util.encoders.Hex;
import piuk.*;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

@WebServlet({"/home"})
public class SharedCoin extends HttpServlet {
    final static Map<Long, Offer> pendingOffers = new ConcurrentHashMap<>();
    final static Map<Long, Proposal> activeProposals = new ConcurrentHashMap<>();
    final static Map<Hash, CompletedTransaction> recentlyCompletedTransactions = new ConcurrentHashMap<>();

    final static Set<String> usedAddresses = new HashSet<>();

    public static int PKSeedCounter = 0;

    public static final long COIN = 100000000;

    private static final int TargetNumberActiveAddresses = 800;
    private static final int MaxActiveAddresses = 1000; //16KB

    private static final int TidyWalletInterval = 120000; //2 minutes
    private static long lastTidyTransactionTime = 0;
    private static long lastPushedTransactionTime = 0;
    private static final long MinimumOutputValue = COIN / 100; //0.01 BTC
    private static final long MinimumOutputChangeSplitValue = COIN / 100; //0.01 BTC
    private static final long MinimumOutputValueExcludeFee = (long) (COIN * 0.0000543);
    private static final long MinimumFeeToDiscard = (long) (COIN * 0.0000543);

    private static final long MaximumHardTransactionSize = 100; //100KB
    private static final long MaximumSoftTransactionSize = 16; //16KB

    private static final long MaxPollTime = 10000;

    private static final double DefaultFeePercent = 0.0; //Per rep
    private static final long MinimumFee = (long) (COIN * 0.0001); //At this point transaction fees start costing more

    private static final long HardErrorMaximumOutputValue = COIN * 55; //55 BTC
    private static final long MaximumOutputValue = COIN * 50; //50 BTC

    private static final long HardErrorMinimumInputValue = (long)(COIN * 0.005); //0.005 BTC
    private static final long MinimumInputValue = (long)(COIN * 0.01); //0.01 BTC

    private static final long MaximumInputValue = COIN * 1000; //1000 BTC
    private static final long MaximumOfferNumberOfInputs = 20;
    private static final long MaximumOfferNumberOfOutputs = 20;
    private static final long VarianceWhenMimicingOutputValue = 10; //15%

    private static final long RecommendedMinIterations = 2;
    private static final long RecommendedMaxIterations = 10;
    private static final long RecommendedIterationsMin = 2;
    private static final long RecommendedIterationsMax = 5;

    private static final long MaxChangeSingleUnconfirmedInput = 20 * COIN;
    private static final long MaxChangeSingleConfirmedInput = 2 * COIN;

    private static final long ForceDivideLargeOutputSize = 50 * COIN;
    private static final long RandomDivideLargeOutputSize = 25 * COIN;

    private static final long ProtocolVersion = 3;
    private static final long MinSupportedVersion = 2;

    private static final long TargetNumberOfOutputs = 15; //The number of outputs to aim for in a single transaction
    private static final long MinNumberOfOutputs = 3; //The number of outputs to aim for in a single transaction including change outputs
    private static final long MaxNumberOfOutputsIncludingChange = 40; //The number of outputs to aim for in a single transaction including change outputs
    private static final long TargetMaxNumberOfInputs = 25; //The soft max number of inputs to use for in a single transaction
    private static final long MaxNumberOfInputs = 100; //The soft max number of inputs to use for in a single transaction

    private static final long ProposalExpiryTime = 240000; //4 Minutes
    private static final long OfferExpiryTime = 600000; //10 Minutes
    private static final long ProposalExpiryTimeAfterCompletion = 86400000; //24 Hours
    private static final long ProposalExpiryTimeFailedToBroadcast = 1800000; //30 Minutes

    private static final long OfferForceProposalAgeMax = 40000; //When an offer reaches this age force a proposal creation
    private static final long OfferForceProposalAgeMin = 10000; //When an offer reaches this age force a proposal creation

    private static final long TokenExpiryTime = 1800000; //Expiry time of tokens. 30 minutes

    public static final int scriptSigSize = 138; //107 compressed
    public static final BigInteger TransactionFeePer1000Bytes = BigInteger.valueOf((long) (COIN * 0.0001)); //0.0001 BTC Fee
    public static final BigInteger MinStandardOutputSize = BigInteger.valueOf((long) (COIN * 0.01)); //0.01 BTC

    private static boolean _scheduleDivideLargeOutputs = false;

    private static final boolean enabled = true; //Enable or disabled the shared coin engine

    public static final OurWallet ourWallet = new OurWallet();

    private static final ExecutorService exec = Executors.newSingleThreadExecutor();

    private static final ExecutorService tidyExec = Executors.newSingleThreadExecutor();

    private static final ExecutorService multiThreadExec = Executors.newCachedThreadPool();

    private static final ReadWriteLock modifyPendingOffersLock = new ReentrantReadWriteLock();

    public static class CompletedTransaction implements Serializable, Comparable<CompletedTransaction> {
        static final long serialVersionUID = 1L;

        long proposalID;
        Transaction transaction;
        boolean isConfirmedBroadcastSuccessfully = false;
        long lastCheckedConfirmed = 0;
        long completedTime;
        int pushCount = 0;
        int nParticipants;

        @Override
        public int compareTo(CompletedTransaction o) {
            if (getCompletedTime() > o.getCompletedTime())
                return -1;

            if (getCompletedTime() < o.getCompletedTime())
                return 1;

            return 0;
        }

        public int getnParticipants() {
            return nParticipants;
        }

        public int getPushCount() {
            return pushCount;
        }

        public long getCompletedTime() {
            return completedTime;
        }

        public boolean isConfirmedBroadcastSuccessfully() {
            return isConfirmedBroadcastSuccessfully;
        }

        public Transaction getTransaction() {
            return transaction;
        }

        public long getLastCheckedConfirmed() {
            return lastCheckedConfirmed;
        }


        public synchronized boolean pushTransaction() throws Exception {
            if (completedTime == 0)
                completedTime = System.currentTimeMillis();

            Exception _e = null;
            boolean pushed = false;
            for (int ii = 0; ii < 3; ++ii) {
                try {
                    pushed = MyRemoteWallet.pushTx(transaction);

                    if (pushed) {
                        break;
                    }

                    Thread.sleep(1000);
                } catch (Exception e) {
                    _e = e;
                }
            }

            if (!pushed) {
                System.out.println("Error Pushing transaction " + transaction);

                if (_e != null)
                    _e.printStackTrace();
            }

            pushCount += 1;

            return pushed;
        }

        public long getProposalID() {
            return proposalID;
        }
    }

    public static class Token {
        public double fee_percent;
        public long created;
        public String created_ip;

        public String encrypt() throws Exception {
            JSONObject obj = new JSONObject();

            obj.put("fee_percent", fee_percent);
            obj.put("created", created);
            obj.put("created_ip", created_ip);

            return MyWallet.encrypt(obj.toJSONString(), AdminServlet.TokenEncryptionPassword, MyWallet.DefaultPBKDF2Iterations);
        }

        public static Token decrypt(String input) throws Exception {
            String decrypted = MyWallet.decrypt(input, AdminServlet.TokenEncryptionPassword, MyWallet.DefaultPBKDF2Iterations);

            JSONParser parser = new JSONParser();

            JSONObject obj = (JSONObject) parser.parse(decrypted);

            Token token = new Token();

            try {
                token.fee_percent = Double.valueOf(obj.get("fee_percent").toString());
            } catch (Exception e) {
                throw new Exception("Invalid Integer");
            }

            try {
                token.created = Long.valueOf(obj.get("created").toString());
            } catch (Exception e) {
                throw new Exception("Invalid Integer");
            }

            token.created_ip = obj.get("created_ip").toString();

            return token;
        }
    }
    public static class OurWallet {
        private volatile MyRemoteWallet _cached = null;
        public ReadWriteLock updateLock = new ReentrantReadWriteLock();

        private MyRemoteWallet getWallet() throws Exception {
            if (_cached == null) {

                String payload = MyRemoteWallet.getWalletPayload(AdminServlet.SharedWalletGUID, AdminServlet.SharedWalletSharedKey);

                MyRemoteWallet remoteWallet = new MyRemoteWallet(payload, AdminServlet.SharedWalletPassword);

                remoteWallet.setTemporySecondPassword(AdminServlet.SharedWalletSecondPassword);

                _cached = remoteWallet;

                return _cached;
            } else {
                return _cached;
            }
        }

        public ECKey makeECKey() throws Exception {
            ++PKSeedCounter;

            AdminServlet.writePKSeedCounter(PKSeedCounter);

            byte[] bytes = Util.SHA256(AdminServlet.PKSeed + PKSeedCounter).getBytes();

            //Prppend a zero byte to make the biginteger unsigned
            byte[] appendZeroByte = ArrayUtils.addAll(new byte[1], bytes);

            ECKey ecKey = new ECKey(new BigInteger(appendZeroByte));

            return ecKey;
        }

        public ECKey findECKey(String address) throws Exception {
            Lock lock = updateLock.readLock();

            lock.lock();
            try{
                MyWallet wallet = getWallet();

                return wallet.getECKey(address.toString());
            } finally {
                lock.unlock();
            }
        }

        public boolean isOurAddress(String address) throws Exception {
            Lock lock = updateLock.readLock();

            lock.lock();
            try{
                MyWallet wallet = getWallet();

                return wallet.isMine(address);
            } finally {
                lock.unlock();
            }
        }

        public List<MyTransactionOutPoint> getUnspentOutputs(int limit) throws Exception {
            Lock lock = updateLock.readLock();

            lock.lock();
            try{
                MyWallet wallet = getWallet();

                try {
                    return MyRemoteWallet.getUnspentOutputPoints(wallet.getActiveAddresses(), 0, limit);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            } finally {
                lock.unlock();
            }

            return new ArrayList<>();
        }

        public List<MyTransactionOutPoint> getUnspentOutputsCreatedByTransaction(MyTransaction transaction) throws Exception {

            Lock lock = updateLock.readLock();

            lock.lock();
            try{
                MyWallet wallet = getWallet();

                Set<Address> addresses = new HashSet<>();

                for (TransactionOutput output : transaction.getOutputs()) {
                    Address address = ((MyTransactionOutput)output).getToAddress();
                    if (wallet.isMine(address.toString())) {
                        addresses.add(address);
                    }
                }

                String[] array = new String[addresses.size()];

                int ii = 0;
                for (Address address : addresses) {
                    array[ii] = address.toString();
                    ++ii;
                }

                try {
                    return MyRemoteWallet.getUnspentOutputPoints(array, 0, 500);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            } finally {
                lock.unlock();
            }

            return new ArrayList<>();
        }

        private Address getRandomAddressNoLock() throws Exception {

            MyWallet wallet = getWallet();

            Set<String> activeAddresses = new HashSet<>();
            for (String address : wallet.getActiveAddresses()) {
                activeAddresses.add(address);
            }

            activeAddresses.removeAll(usedAddresses);

            String selectedAddress;
            if (activeAddresses.size() > 0) {
                selectedAddress = activeAddresses.iterator().next();
            } else {
                selectedAddress = wallet.getRandomActiveAddress().toString();
            }

            usedAddresses.add(selectedAddress);

            return new Address(NetworkParameters.prodNet(), selectedAddress);
        }

        public Address getRandomAddress() throws Exception {
            Lock lock = updateLock.readLock();

            lock.lock();
            try{
                return getRandomAddressNoLock();
            } finally {
                lock.unlock();
            }
        }

        private void logDeletedPrivateKey(String address, ECKey key) throws IOException {
            FileWriter fWriter = new FileWriter(AdminServlet.DeletedPrivateKeysLogFilePath, true);

            fWriter.write(address + " " + Base58.encode(key.getPrivKeyBytes()) + "\n");

            fWriter.flush();

            fWriter.close();
        }

        private  static int lastMinDeletionBlockHeight = 0;

        public void removeConfirmedArchivedWallet(int latestBlockHeight) throws Exception {

            List<String> toUnarchive = new ArrayList<>();
            List<String> toRemove = new ArrayList<>();

            {
                if (latestBlockHeight == 0) {
                    throw new Exception("latestBlockHeight == 0");
                }

                int minDeletionBlockHeight = latestBlockHeight - 6;

                if (minDeletionBlockHeight == lastMinDeletionBlockHeight) {
                    return;
                }

                MyRemoteWallet wallet = getWallet();

                String[] archived = wallet.getArchivedAddresses();

                String[] tmp_archived = null;

                int ii = 0;
                int iii = 0;
                for (String _address : archived) {
                    if (ii == 0) {
                        tmp_archived = new String[1000];
                    }

                    tmp_archived[ii] = _address;

                    ++ii;
                    ++iii;
                    if (ii == 1000 || iii == archived.length) {
                        Map<String, Long> extraBalances = MyRemoteWallet.getMultiAddrBalances(tmp_archived);

                        for (String address : tmp_archived) {
                            if (address == null)
                                continue;

                            Long balance = extraBalances.get(address);

                            if (balance != null && balance > 0) {
                                toUnarchive.add(address);
                            } else if (balance != null && balance == 0) {

                                long blockHeight = MyRemoteWallet.getMinConfirmingBlockHeightForTransactionConfirmations(address);

                                if (blockHeight == -1 || (blockHeight > 0 && blockHeight <= minDeletionBlockHeight)) {
                                    toRemove.add(address);
                                }
                            }
                        }
                        ii = 0;
                    }
                }

                lastMinDeletionBlockHeight = minDeletionBlockHeight;
            }

            Lock lock = updateLock.writeLock();

            lock.lock();
            try{
                boolean didModify = false;

                MyRemoteWallet wallet = getWallet();

                for (String address : toUnarchive) {
                    wallet.setTag(address, 0);

                    didModify = true;
                }

                for (String address : toRemove) {
                    //Log before deleting
                    logDeletedPrivateKey(address, wallet.getECKey(address));

                    //And remove it
                    wallet.removeAddressAndKey(address);

                    didModify = true;
                }

                if (didModify) {
                    _cached = null;

                    if (!wallet.remoteSave(null)) {
                        throw new Exception("Error Saving Wallet");
                    }
                }
            } finally {
                lock.unlock();
            }
        }


        public void divideLargeOutputs() throws Exception {
            Lock lock = updateLock.writeLock();

            lock.lock();
            try{
                //Do multiaddr
                //Archive ZERO balance addresses with more than one transaction
                //Delete archived addresses with transactions > 6 confirmations

                MyRemoteWallet wallet = getWallet();

                for (int ii = 0; ii < 2; ++ii) {
                    try {
                        wallet.doMultiAddr();

                        break;
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }

                for (String address : wallet.getActiveAddresses()) {
                    BigInteger balance = wallet.getBalance(address);

                    if (balance.compareTo(BigInteger.valueOf(ForceDivideLargeOutputSize)) >= 0) {
                        _scheduleDivideLargeOutputs = true;
                    }

                    if (balance.longValue() >= ForceDivideLargeOutputSize || (Math.random() > 0.75 && balance.longValue() >= RandomDivideLargeOutputSize)) {

                        long split = (long)((balance.longValue() / 2) * (Math.random()+0.5));

                        String destination = getRandomAddressNoLock().toString();

                        Logger.log(Logger.SeverityWARN, "divideLargeOutputs() Send From [" + address + "] to destination " + destination +" value " + split);

                        if (isAddressInUse(address)) {
                            Logger.log(Logger.SeverityWARN, "Address in use");
                            continue;
                        }


                        wallet.send(new String[]{address}, destination, BigInteger.valueOf(split), TransactionFeePer1000Bytes);

                        break;
                    }
                }
            } finally {
                lock.unlock();
            }
        }

        public void tidyTheWallet() throws Exception {
            Lock lock = updateLock.writeLock();

            int latestBlockHeight = 0;

            lock.lock();
            try{
                //Do multiaddr
                //Archive ZERO balance addresses with more than one transaction
                //Delete archived addresses with transactions > 6 confirmations

                MyRemoteWallet wallet = getWallet();

                for (int ii = 0; ii < 2; ++ii) {
                    try {
                        wallet.doMultiAddr();

                        break;
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }

                boolean didModify = false;

                try {
                    if (wallet.getBalance().compareTo(BigInteger.ZERO) == 0) {
                        throw new Exception("Tidy Wallet: Wallet Balance Zero");
                    }

                    //Archive any 0 balance addreses
                    for (String address : wallet.getActiveAddresses()) {
                        BigInteger balance = wallet.getBalance(address);
                        int n_tx = wallet.getNtx(address);

                        if (n_tx > 0) {
                            usedAddresses.add(address);
                        }

                        if (balance.compareTo(BigInteger.valueOf(ForceDivideLargeOutputSize)) >= 0) {
                            _scheduleDivideLargeOutputs = true;
                        }

                        if (n_tx > 0 && balance.compareTo(BigInteger.ZERO) == 0 && !isAddressTargetOfAnActiveOutput(address)) {
                            //Logger.log(Logger.SeverityWARN, "Tidy Wallet: Archive Address " + address + " ntx " + n_tx);

                            didModify = true;

                            wallet.setTag(address, 2);
                        }
                    }

                    latestBlockHeight = wallet.getLatestBlock().getHeight();

                } catch (Exception e) {
                    e.printStackTrace();
                }

                String[] allAddresses = wallet.getActiveAddresses();

                if (allAddresses.length > MaxActiveAddresses) {
                    Logger.log(Logger.SeverityWARN, "Tidy Wallet: Too Many Active Addresses " + allAddresses.length + " new addresses");

                    for (int ii = MaxActiveAddresses-1; ii < allAddresses.length; ++ii) {

                        String address = allAddresses[ii];

                        //Logger.log(Logger.SeverityWARN, "Tidy Wallet: Archive " + address);

                        wallet.setTag(address, 2);

                        didModify = true;
                    }

                } else {
                    //Generate New Addresses To Fill the wallet
                    int nAddressToCreate = TargetNumberActiveAddresses - allAddresses.length;

                    //Logger.log(Logger.SeverityWARN, "Tidy Wallet: Generate " + nAddressToCreate + " new addresses");

                    for (int ii = 0; ii < nAddressToCreate; ++ii) {
                        ECKey key = makeECKey();

                        didModify = true;

                        wallet.addKey(key, null, Math.random() >= 0.5, "sharedcoin", "" + ProtocolVersion);
                    }
                }

                if (didModify) {
                    _cached = null;

                    if (!wallet.remoteSave(null)) {
                        throw new Exception("Error Saving Wallet");
                    }
                }
            } finally {
                lock.unlock();
            }

            if (latestBlockHeight > 0) {
                removeConfirmedArchivedWallet(latestBlockHeight);
            }
        }
    }

    public static int numberOfDecimalPlaces(double input) {
        String text = Double.toString(Math.abs(input));

        int integerPlaces = text.indexOf('.');
        int decimalPlaces = text.length() - integerPlaces - 1;

        return decimalPlaces;
    }

    public static long randomID() {
        long x = 10000;
        long y = 107199254740992L;
        Random r = new Random();

        return x+((long)(r.nextDouble()*(y-x)));
    }

    static {
        run();
    }

    public static void save() throws IOException {
        File tempFile = new File(AdminServlet.RecentlyCompletedTransactionsTempPath);

        {
            FileOutputStream fos = new FileOutputStream(tempFile);
            ObjectOutputStream oos = new ObjectOutputStream(fos);
            oos.writeObject(new HashMap<>(recentlyCompletedTransactions));
            oos.close();
        }

        {
            File realFile = new File(AdminServlet.RecentlyCompletedTransactionsPath);
            tempFile.renameTo(realFile);
        }
    }

    public static void restore() throws IOException, ClassNotFoundException {
        PKSeedCounter = AdminServlet.readPKSeedCounter();

        FileInputStream fis = new FileInputStream(AdminServlet.RecentlyCompletedTransactionsPath);
        ObjectInputStream ois = new ObjectInputStream(fis);
        recentlyCompletedTransactions.putAll((Map<Hash, CompletedTransaction>) ois.readObject());

        ois.close();
    }

    public static Script newScript(byte[] bytes) throws ScriptException {
        return new Script(NetworkParameters.prodNet(), bytes, 0, bytes.length);
    }

    public static boolean IsCanonicalSignature(Script inputScript) throws ScriptException {
        return IsCanonicalSignature(inputScript.getSignature());
    }

    public static boolean IsCanonicalSignature(byte[] vchSig) throws ScriptException {

        int SIGHASH_ALL = 1;
        int SIGHASH_NONE = 2;
        int SIGHASH_SINGLE = 3;
        int SIGHASH_ANYONECANPAY = 80;

        if (vchSig.length < 9)
            throw new ScriptException("Non-canonical signature: too short");
        if (vchSig.length > 73)
            throw new ScriptException("Non-canonical signature: too long");
        int nHashType = vchSig[vchSig.length - 1];
        if (nHashType != SIGHASH_ALL && nHashType != SIGHASH_NONE && nHashType != SIGHASH_SINGLE && nHashType != SIGHASH_ANYONECANPAY)
            throw new ScriptException("Non-canonical signature: unknown hashtype byte " + nHashType);
        if (vchSig[0] != 0x30)
            throw new ScriptException("Non-canonical signature: wrong type");
        if (vchSig[1] != vchSig.length - 3)
            throw new ScriptException("Non-canonical signature: wrong length marker");
        int nLenR = vchSig[3];
        if (5 + nLenR >= vchSig.length)
            throw new ScriptException("Non-canonical signature: S length misplaced");
        int nLenS = vchSig[5 + nLenR];
        if (nLenR + nLenS + 7 != vchSig.length)
            throw new ScriptException("Non-canonical signature: R+S length mismatch");

        {
            int n = 4;
            if (vchSig[n - 2] != 0x02)
                throw new ScriptException("Non-canonical signature: R value type mismatch");
            if (nLenR == 0)
                throw new ScriptException("Non-canonical signature: R length is zero");
            if ((vchSig[n + 0] & 0x80) > 0)
                throw new ScriptException("Non-canonical signature: R value negative");
            if (nLenR > 1 && (vchSig[n + 0] == 0x00) && (vchSig[n + 1] & 0x80) == 0)
                throw new ScriptException("Non-canonical signature: R value excessively padded");
        }

        {
            int n = 6 + nLenR;
            if (vchSig[n - 2] != 0x02)
                throw new ScriptException("Non-canonical signature: S value type mismatch");
            if (nLenS == 0)
                throw new ScriptException("Non-canonical signature: S length is zero");
            if ((vchSig[n + 0] & 0x80) > 0)
                throw new ScriptException("Non-canonical signature: S value negative");
            if (nLenS > 1 && (vchSig[n + 0] == 0x00) && (vchSig[n + 1] & 0x80) == 0)
                throw new ScriptException("Non-canonical signature: S value excessively padded");
        }

        return true;
    }


    public void addOfferToPending(Offer offer) throws Exception {
        Lock lock = modifyPendingOffersLock.writeLock();

        lock.lock();
        try{
            //Finalize the inputs and outputs
            offer.requestedOutputs = Collections.unmodifiableList(offer.requestedOutputs);
            offer.offeredOutpoints = Collections.unmodifiableList(offer.offeredOutpoints);

            if (pendingOffers.containsKey(offer.getOfferID())) {
                throw new Exception("Duplicate Offer ID");
            }

            pendingOffers.put(offer.getOfferID(), offer);
        } finally {
            lock.unlock();
        }
    }

    public static double feePercentForRequest(HttpServletRequest request) throws Exception {

        if (DefaultFeePercent == 0) {
            return 0;
        } else {
            String seedString = AdminServlet.getRealIP(request);

            BigInteger seed = new BigInteger(Util.SHA256(seedString + "----" + (long)(System.currentTimeMillis()/86400000)).getBytes());

            BigDecimal seedValue = BigDecimal.valueOf(seed.longValue());

            double mod = seedValue.remainder(BigDecimal.TEN).doubleValue();

            double even = seedValue.setScale(0, BigDecimal.ROUND_HALF_UP).remainder(BigDecimal.valueOf(2)).doubleValue();

            BigDecimal extra = BigDecimal.valueOf(((DefaultFeePercent / 100d) * mod));

            double value;
            if (even == 1 || even == -1)
                value = DefaultFeePercent - extra.doubleValue();
            else
                value = DefaultFeePercent + extra.doubleValue();

            return BigDecimal.valueOf(value).setScale(2, BigDecimal.ROUND_HALF_UP).doubleValue();
        }
    }

    public static void run() {

        final Timer timer = new Timer();

        timer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                exec.execute(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            createProposalsIfNeeded();
                        } catch (Exception e) {
                            e.printStackTrace();
                        }

                        cleanExpiredProposals();

                        cleanExpiredOffers();

                        cleanRecentlyCompletedProposals();

                        checkIfProposalsAreBroadcastSuccessfully();
                    }
                });
            }
        }, 500, 500);


        timer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {

                final AtomicBoolean tidyIsRunning = new AtomicBoolean();

                tidyExec.execute(new Runnable() {
                    @Override
                    public void run() {
                        if (tidyIsRunning.compareAndSet(false, true)) {
                            try {
                                if (_scheduleDivideLargeOutputs) {
                                    _scheduleDivideLargeOutputs = false;
                                    ourWallet.divideLargeOutputs();
                                }

                                if (lastTidyTransactionTime != lastPushedTransactionTime) {
                                    lastTidyTransactionTime = lastPushedTransactionTime;
                                    ourWallet.tidyTheWallet();
                                }
                            } catch (Exception e) {
                                e.printStackTrace();
                            } finally {
                                tidyIsRunning.set(false);
                            }
                        }
                    }
                });
            }
        }, TidyWalletInterval, TidyWalletInterval);
    }

    public static void checkIfProposalsAreBroadcastSuccessfully() {

        long now = System.currentTimeMillis();
        for (CompletedTransaction completedTransaction : recentlyCompletedTransactions.values()) {

            long completedTime = completedTransaction.getCompletedTime();

            long age = 0;
            if (completedTime > 0)
                age = now - completedTime;

            if (age < 60000) {
                continue;
            }

            if (completedTransaction.lastCheckedConfirmed == 0 || now > completedTransaction.lastCheckedConfirmed+600000) {
                completedTransaction.lastCheckedConfirmed = now;

                boolean didAlreadyFail = !completedTransaction.isConfirmedBroadcastSuccessfully;

                try {
                    Transaction transaction = MyRemoteWallet.getTransactionByHash(new Hash(completedTransaction.transaction.getHash().getBytes()), false);

                    if (transaction == null) {
                        throw new Exception("Null Transaction");
                    }

                    completedTransaction.isConfirmedBroadcastSuccessfully = true;

                    continue;
                } catch (Exception e) {
                    completedTransaction.isConfirmedBroadcastSuccessfully = false;

                    e.printStackTrace();
                }

                if (!didAlreadyFail)
                    continue;

                System.out.println("Transaction Not Found " + completedTransaction.getTransaction().getHash() + ". Proposal Age " + age + "ms");

                if (age > ProposalExpiryTimeFailedToBroadcast) {
                    recentlyCompletedTransactions.remove(new Hash(completedTransaction.getTransaction().getHash().getBytes()));
                } else if (completedTransaction.getPushCount() < 3) {
                    System.out.println("Re-broadcasting transaction");

                    try {
                        completedTransaction.pushTransaction();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }
        }
    }

    public static void cleanExpiredProposals() {
        long now = System.currentTimeMillis();
        for (Proposal proposal : activeProposals.values()) {
            if (proposal.getCreatedTime() > 0 && proposal.getCreatedTime() < now-ProposalExpiryTime) {
                activeProposals.remove(proposal.getProposalID());
            }
        }
    }


    public static void cleanRecentlyCompletedProposals() {
        long now = System.currentTimeMillis();
        for (CompletedTransaction completedTransaction : recentlyCompletedTransactions.values()) {
            if (completedTransaction.getCompletedTime() > 0 && completedTransaction.getCompletedTime() < now-ProposalExpiryTimeAfterCompletion) {
                recentlyCompletedTransactions.remove(new Hash(completedTransaction.getTransaction().getHash().getBytes()));
            }
        }
    }

    public static void cleanExpiredOffers() {
        long now = System.currentTimeMillis();
        for (Offer offer : pendingOffers.values()) {
            if (offer.getReceivedTime() > 0 && offer.getReceivedTime() < now-OfferExpiryTime) {
                pendingOffers.remove(offer.getOfferID());
            }
        }
    }


    public static void createProposalsIfNeeded() throws Exception {
        long now = System.currentTimeMillis();

        for (Offer offer : pendingOffers.values()) {
            //If the oldest offer has reached a certain age force creation
            if (offer.getReceivedTime() < now-offer.forceProposalMaxAge) {
                runCreateProposals();
                break;
            }
        }
    }


    public static boolean isTransactionCreatedByUs(Hash hash) {
        Sha256Hash _hash = new Sha256Hash(hash.getBytes());
        for (CompletedTransaction completedTransaction : recentlyCompletedTransactions.values()) {
            if (completedTransaction.getTransaction() != null && completedTransaction.getTransaction().getHash().equals(_hash)) {
                return true;
            }
        }

        for (Proposal proposal : activeProposals.values()) {
            if (proposal.getTransaction() != null && proposal.getTransaction().getHash().equals(_hash)) {
                return true;
            }
        }

        return false;
    }

    public synchronized static void runCreateProposals() throws Exception {
        Lock lock = modifyPendingOffersLock.writeLock();

        lock.lock();
        try{
            Proposal proposal = new Proposal();

            synchronized (proposal) {
                {
                    int nInputs = 0;
                    int nOutputs = 0;
                    Set<String> allDestinationAddresses = new HashSet<>();
                    for (Offer offer : pendingOffers.values()) {

                        nInputs += offer.getOfferedOutpoints().size();
                        nOutputs += offer.getRequestedOutputs().size();

                        if (nInputs >= TargetMaxNumberOfInputs) {
                            break;
                        }

                        if (nOutputs >= TargetNumberOfOutputs) {
                            break;
                        }

                        Set<String> thisOfferDestinationAddresses = offer.getRequestedOutputAddresses();
                        if (!Collections.disjoint(allDestinationAddresses, offer.getRequestedOutputAddresses())) {
                            //All output addresses must be unique
                            //If there are any duplicates don't put them in the same proposal
                            continue;
                        }

                        allDestinationAddresses.addAll(thisOfferDestinationAddresses);

                        if (!proposal.addOffer(offer)) {
                            throw new Exception("Error Adding Offer To Proposal");
                        }
                    }
                }

                if (proposal.getOffers().size() == 0) {
                    return;
                }

                //Sanity Check for duplicate
                if (activeProposals.containsKey(proposal.getProposalID()))
                    throw new Exception("Duplicate Proposal ID");

                //Promote the proposal to active
                activeProposals.put(proposal.getProposalID(), proposal);

                //Remove the offer from pending
                pendingOffers.values().removeAll(proposal.getOffers());

                //Finalize the user offers
                proposal.offers = Collections.unmodifiableList(proposal.offers);

                Lock walletLock = ourWallet.updateLock.writeLock();
                Lock offersLock = modifyPendingOffersLock.writeLock();

                walletLock.lock();
                offersLock.lock();
                try {
                    proposal.mixWithOurWallet();

                    //Finalize our offers
                    proposal.ourOffers = Collections.unmodifiableList(proposal.ourOffers);

                    if (proposal.getRequestedOutputCount() < MinNumberOfOutputs) {
                        throw new Exception("proposal.getRequestedOutputCount() ( " + proposal.getRequestedOutputCount() + ") < MinNumberOfOutputs (" + MinNumberOfOutputs + ")");
                    }

                    //TODO recover if these fail
                    proposal.constructTransaction();
                } catch (Exception e) {
                    activeProposals.remove(proposal.getProposalID());

                    throw e;
                } finally {
                    offersLock.unlock();
                    walletLock.unlock();
                }

                //Wake up the long pollers
                for (Offer offer : proposal.getOffers()) {
                    synchronized(offer) {
                        offer.notifyAll();
                    }
                }
            }
        } finally {
            lock.unlock();
        }
    }


    public static long randomLong(long x, long y) {
        Random r = new Random();
        return x+((long)(r.nextDouble()*(y-x)));
    }

    public static double randomDouble(double rangeMin, double rangeMax) {
        return rangeMin + ((rangeMax - rangeMin) * Math.random());
    }

    public static class Proposal implements Serializable, Comparable<Proposal> {
        static final long serialVersionUID = 1L;

        private List<Offer> offers = new CopyOnWriteArrayList<>();
        private List<Offer> ourOffers = new CopyOnWriteArrayList<>();
        private transient Map<Integer, Script> input_scripts = new ConcurrentHashMap<>();
        private transient Set<OutpointWithValue> outpointsSpentSoFar = Collections.newSetFromMap(new ConcurrentHashMap<OutpointWithValue, Boolean>());

        private final long proposalID;
        private long createdTime = System.currentTimeMillis();
        private Transaction transaction;
        boolean isFinalized = false;

        public synchronized Transaction getTransaction() {
            return transaction;
        }

        public Offer findOffer(long offerID) {
            for (Offer offer : offers) {
                if (offer.getOfferID() == offerID)
                    return offer;
            }

            return null;
        }

        public synchronized boolean sanityCheckBeforePush() throws Exception {
            long transactionFee = getTransactionFee();

            int nKB = (int)Math.ceil(transaction.bitcoinSerialize().length / 1000d);

            boolean feeMatches = false;
            for (int ii = -4; ii < 4; ++ii) { //Allow -4 + 4 KB each side
                if (transactionFee != (nKB+ii)*TransactionFeePer1000Bytes.longValue()) {
                    feeMatches = true;
                }
            }

            if (!feeMatches) {
                throw new Exception("Sanity Check Failed. Unexpected Network Fee " + transactionFee + " != " +nKB + " * " + TransactionFeePer1000Bytes);
            }

            if (nKB > MaximumHardTransactionSize) {
                throw new Exception("Sanity Check Failed. Transaction too large");
            }

            Map<Long, Long> offerIDToValueOutput = new HashMap<>();
            for (TransactionOutput output : getTransaction().getOutputs()) {
                String destinationAddress = output.getScriptPubKey().getToAddress().toString();

                if (ourWallet.isOurAddress(output.getScriptPubKey().getToAddress().toString())) {
                    continue; //One of our addresses, looks good
                }

                boolean found = false;
                for (Offer offer : offers) {
                    for (Output requestedOutput : offer.getRequestedOutputs()) {
                        if (requestedOutput.getAddress().toString().equals(destinationAddress)) {

                            //Multiple offers with same output address will confuse this
                            if (offerIDToValueOutput.containsKey(offer.getOfferID())) {
                                offerIDToValueOutput.put(offer.getOfferID(), offerIDToValueOutput.get(offer.getOfferID())+output.getValue().longValue());
                            } else {
                                offerIDToValueOutput.put(offer.getOfferID(), output.getValue().longValue());
                            }

                            found = true;

                            break;
                        }
                    }
                }

                if (!found) {
                    throw new Exception("Sanity Check Failed. Unknown destinationAddress address " + destinationAddress);
                }
            }

            for (Offer offer : offers) {
                Long valueOutput = offerIDToValueOutput.get(offer.getOfferID());
                long amountInput = offer.getValueOffered();

                if (amountInput < valueOutput) {
                    throw new Exception("Sanity Check Failed. Greater value being sent to offer than was input");
                }

                for (OutpointWithValue outpointWithValue : offer.getOfferedOutpoints()) {
                    if (wasOutpointRecentlySpentByUs(outpointWithValue.getHash(), outpointWithValue.getIndex(), proposalID)) {
                        throw new Exception("Sanity Check Failed. User Offer Outpoint already Spent " + outpointWithValue);
                    }
                }
            }

            for (Offer offer : ourOffers) {
                for (OutpointWithValue outpointWithValue : offer.getOfferedOutpoints()) {
                    if (wasOutpointRecentlySpentByUs(outpointWithValue.getHash(), outpointWithValue.getIndex(), proposalID)) {
                        throw new Exception("Sanity Check Failed. Our Offer Outpoint already Spent " + outpointWithValue);
                    }
                }
            }

            return true;
        };

        public synchronized boolean pushTransaction() throws Exception {
            if (!isFinalized) {
                throw new Exception("Cannot push transaction, not finalized");
            }

            if (recentlyCompletedTransactions.containsKey(new Hash(getTransaction().getHash().getBytes()))) {
                throw new Exception("Proposal Already Pushed");
            }

            if (!sanityCheckBeforePush()) {
                throw new Exception("Sanity Check Returned False");
            }

            CompletedTransaction completedTransaction = new CompletedTransaction();

            completedTransaction.isConfirmedBroadcastSuccessfully = false;
            completedTransaction.transaction = getTransaction();
            completedTransaction.completedTime = System.currentTimeMillis();
            completedTransaction.pushCount = 0;
            completedTransaction.lastCheckedConfirmed = 0;
            completedTransaction.proposalID = getProposalID();
            completedTransaction.nParticipants = getOffers().size();

            recentlyCompletedTransactions.put(new Hash(getTransaction().getHash().getBytes()), completedTransaction);

            activeProposals.remove(getProposalID());

            boolean pushed = completedTransaction.pushTransaction();

            lastPushedTransactionTime = System.currentTimeMillis();

            synchronized(this) {
                this.notifyAll();
            }

            return pushed;
        }

        public synchronized void finalizeTransaction() throws Exception {

            if (isFinalized) {
                return;
            }

            try {
                if (getNSigned() < getNSignaturesNeeded()) {
                    throw new Exception("Cannot finalize transaction as not all inputs are signed");
                }

                int ii = 0;
                for (TransactionInput input : getTransaction().getInputs()) {
                    Script inputScript = input_scripts.get(ii);

                    if (inputScript != null) {
                        input.scriptBytes = inputScript.program;
                        input.scriptSig = null;
                    }

                    ++ii;
                }

                //Sign our inputs
                try {
                    Wallet wallet = new Wallet(NetworkParameters.prodNet());
                    for (Offer offer : ourOffers) {
                        for (OutpointWithValue outpointWithValue : offer.getOfferedOutpoints()) {
                            Address address = outpointWithValue.getScript().getToAddress();

                            ECKey key = ourWallet.findECKey(address.toString());

                            wallet.addKey(key);
                        }
                    }

                    getTransaction().signInputs(Transaction.SigHash.ALL, wallet);
                } catch (Exception e) {
                    Logger.log(Logger.SeverityWARN, e);

                    throw new Exception("Error signing our inputs");
                }


                isFinalized = true;
            } catch (Exception e) {
                isFinalized = false;
                throw e;
            }
        }

        @Override
        public int compareTo(Proposal o) {
            if (getCreatedTime() > o.getCreatedTime())
                return -1;

            if (getCreatedTime() < o.getCreatedTime())
                return 1;

            return 0;
        }

        public static class SignatureRequest {
            int tx_input_index;
            int offer_outpoint_index;
            Script connected_script;
        }

        public List<SignatureRequest> getSignatureRequests(Offer offer) throws ScriptException {
            List<SignatureRequest> requests = new ArrayList<>();

            int ii = 0;
            for (TransactionInput input : getTransaction().getInputs()) {
                Hash hash = new Hash(input.getOutpoint().getHash().getBytes());
                int index = (int)input.getOutpoint().getIndex();

                int iii = 0;
                for (OutpointWithValue outputWithValue : offer.getOfferedOutpoints()) {
                    if (outputWithValue.getHash().equals(hash) && outputWithValue.getIndex() == index) {
                        SignatureRequest request = new SignatureRequest();

                        request.tx_input_index = ii;
                        request.offer_outpoint_index = iii;
                        request.connected_script = outputWithValue.getScript();

                        requests.add(request);

                        continue;
                    }

                    ++iii;
                }

                ++ii;
            }

            return requests;
        }

        public List<OutpointWithValue> getTransactionOutpoints() throws Exception {
            List<OutpointWithValue> outpoints = new ArrayList<>();

            for (TransactionInput input : getTransaction().getInputs()) {
                OutpointWithValue outpoint = new OutpointWithValue();

                outpoint.value = input.getOutpoint().getConnectedOutput().getValue().longValue();
                outpoint.script = input.getOutpoint().getConnectedPubKeyScript();
                outpoint.index = (int)input.getOutpoint().getIndex();
                outpoint.hash = new Hash(input.getOutpoint().getHash().getBytes());

                outpoints.add(outpoint);
            }

            return outpoints;
        }

        public List<Output> getTransactionOutputs() throws Exception {
            List<Output> outputs = new ArrayList<>();

            for (TransactionOutput _output : getTransaction().getOutputs()) {
                Output output = new Output();

                output.value = _output.getValue().longValue();
                output.script = _output.getScriptBytes();

                outputs.add(output);
            }

            return outputs;
        }

        public long getTransactionFee() {
            BigInteger totalValueOutput = BigInteger.ZERO;
            for (TransactionOutput output : getTransaction().getOutputs()) {
                totalValueOutput = totalValueOutput.add(output.getValue());
            }

            BigInteger totalValueInput = BigInteger.ZERO;
            for (TransactionInput input : getTransaction().getInputs()) {
                totalValueInput = totalValueInput.add(input.getOutpoint().getConnectedOutput().getValue());
            }

            return totalValueInput.subtract(totalValueOutput).longValue();
        }

        public long getNSigned() {
            return input_scripts.size();
        }

        public long getNSignaturesNeeded() {
            long nOutpoints = 0;
            for (Offer offer : offers) {
                nOutpoints += offer.getOfferedOutpoints().size();
            }

            return nOutpoints;
        }

        private static MyTransactionOutPoint closestUnspentToValueNotInList(long value, List<MyTransactionOutPoint> unspent, List<MyTransactionOutPoint> alreadySelected, boolean allowUnconfirmed) {

            long closestDifference = Long.MAX_VALUE;
            MyTransactionOutPoint output = null;

            for (MyTransactionOutPoint unspentOutPoint : unspent) {

                //Allow unconfirmed outpoints only when specified
                if (allowUnconfirmed == false && unspentOutPoint.getConfirmations() == 0) {
                    continue;
                }

                //Ignore very small unconfirmed
                if (unspentOutPoint.getConfirmations() == 0 && unspentOutPoint.getValue().longValue() < MinimumOutputValue) {
                    continue;
                }

                long difference = value - unspentOutPoint.getValue().longValue();

                if (difference < 0) {
                    difference = -difference;
                }

                if (difference < closestDifference) {
                    boolean alreadyExists = false;
                    for (MyTransactionOutPoint existing : alreadySelected) {
                        if (existing.getTxHash().equals(unspentOutPoint.getTxHash()) && existing.getTxOutputN() == unspentOutPoint.getTxOutputN()) {
                            alreadyExists = true;
                            break;
                        }
                    }

                    if (!alreadyExists) {
                        closestDifference = difference;
                        output = unspentOutPoint;
                    }
                }
            }

            return output;
        }

        private int scaleForInputValue(long value) {
            int nDecimals = numberOfDecimalPlaces(value / (double)COIN);

            double scale;
            if (nDecimals > 4)
                scale = randomDouble(-2, 6);
            else if (nDecimals > 2)
                scale = randomDouble(-1, 4);
            else
                scale = randomDouble(0, 3);

            return (int) scale + nDecimals;
        }

        public long[] genNumbers(long sum, int n) {
            long[] nums = new long[n];
            long upperbound = Math.round(sum * 1.0 / n);
            long offset = Math.round(0.5 * upperbound);

            long cursum = 0;
            Random random = new Random(new Random().nextInt());
            for (int i = 0; i < n; i++)
            {
                long rand = random.nextInt((int)upperbound) + offset;
                if (cursum + rand > sum || i == n - 1)
                {
                    rand = sum - cursum;
                }
                cursum += rand;
                nums[i] = rand;
                if (cursum == sum)
                {
                    break;
                }
            }
            return nums;
        }

        private boolean addInputsForValue(List<MyTransactionOutPoint> unspent, Offer offer, final long totalValueNeeded) throws Exception {

            //Pick the unspent outputs we will use
            long totalSelected = 0;
            List<MyTransactionOutPoint> selectedBeans = new ArrayList<>();

            for (int ii = 0; ii < 2; ++ii) {
                List<MyTransactionOutPoint> alreadyTested = new ArrayList<>();

                boolean allowUnconfirmed = false;

                if (ii == 1) {
                    allowUnconfirmed = true;
                }

                while (true) {
                    MyTransactionOutPoint outpoint = closestUnspentToValueNotInList(totalValueNeeded-totalSelected, unspent, alreadyTested, allowUnconfirmed);

                    if (outpoint == null) {
                        //Logger.log(Logger.SeverityWARN, "Null outpoint unspent size " + unspent.size());
                        break;
                    }

                    alreadyTested.add(outpoint);

                    if (selectedBeans.contains(outpoint) || wasOutpointRecentlySpentByUs(new Hash(outpoint.getTxHash().getBytes()), outpoint.getTxOutputN(), proposalID) || isOutpointInUse(new Hash(outpoint.getTxHash().getBytes()), outpoint.getTxOutputN())) {
                        continue;
                    }

                    long maxChange = allowUnconfirmed ? MaxChangeSingleUnconfirmedInput : MaxChangeSingleConfirmedInput;

                    if ((totalSelected + outpoint.getValue().longValue()) - totalValueNeeded > maxChange) {
                        continue;
                    }

                    selectedBeans.add(outpoint);

                    if (selectedBeans.size() > TargetMaxNumberOfInputs && !allowUnconfirmed) {
                        break;
                    }

                    totalSelected += outpoint.getValue().longValue();

                    if (totalSelected >= totalValueNeeded) {
                        break;
                    }
                }
            }

            if (totalSelected < totalValueNeeded) {
                Logger.log(Logger.SeverityWARN, "addInputsForValue() totalSelected < totalValueNeeded. unspent size " + unspent.size());
                return false;
            }

            {
                for (MyTransactionOutPoint myOutpoint : selectedBeans) {
                    OutpointWithValue outpoint = new OutpointWithValue();

                    outpoint.script = myOutpoint.getScriptBytes();

                    if (outpoint.script == null) {
                        throw new Exception("Null output script");
                    }

                    outpoint.hash = new Hash(myOutpoint.getTxHash().getBytes());
                    outpoint.index = myOutpoint.getTxOutputN();
                    outpoint.value = myOutpoint.getValue().longValue();

                    offer.addOfferedOutpoint(outpoint);

                    if (offer.getOfferedOutpoints().size() > MaxNumberOfInputs) {
                        System.out.println("offer.getOfferedOutpoints().size() > MaxNumberOfInputs");
                        return false;
                    }
                }
            }

            return true;
        }

        private synchronized boolean addOutputsWhichMimicsOffer(List<MyTransactionOutPoint> unspent, final Offer offer) throws Exception {

            long offerTotalValueOutput = offer.getValueOutputRequested();

            long ourValueUnspent = 0;
            for (MyTransactionOutPoint outpoint : unspent) {
                ourValueUnspent += outpoint.getValue().longValue();
            }

            //Not sufficient funds to mimic this
            if (ourValueUnspent < offerTotalValueOutput) {
                Logger.log(Logger.SeverityWARN, "Add output to mimic ourValueUnspent < offerTotalValueOutput");
                return false;
            }

            long feePayingOutputValue = 0;
            long noneFeePayingOutputValue = 0;
            int nSplits = 0;

            for (Output out : offer.getRequestedOutputs()) {
                if (!out.isExcludeFromFee()) {
                    ++nSplits;
                    feePayingOutputValue += out.value;
                } else {
                    noneFeePayingOutputValue += out.value;
                }
            }

            List<Long> splits = new ArrayList<>();

            long average = feePayingOutputValue / nSplits;

            long maxVariance = (long)((average / 100d) * (double)VarianceWhenMimicingOutputValue);

            if (nSplits == 1) {
                long variance = (long)((average / 100d) * (VarianceWhenMimicingOutputValue * Math.random()));

                long remainderRounded = BigDecimal.valueOf(feePayingOutputValue+variance).divide(BigDecimal.valueOf(COIN)).setScale(scaleForInputValue(noneFeePayingOutputValue), BigDecimal.ROUND_HALF_UP).multiply(BigDecimal.valueOf(COIN)).longValue();

                remainderRounded = Math.max(MinimumOutputValue, remainderRounded);

                splits.add(remainderRounded);
            } else {
                while (true) {
                    long[] vSplits = genNumbers(feePayingOutputValue, nSplits);

                    boolean allWithinVariance = true;
                    for (long split : vSplits) {
                        long difference = average - split;

                        if (difference < 0) {
                            difference = -difference;
                        }

                        if (difference > maxVariance) {
                            allWithinVariance = false;
                        }
                    }

                    if (!allWithinVariance) {
                        continue;
                    } else {
                        for (long split : vSplits) {
                            long rounded = BigDecimal.valueOf(split).divide(BigDecimal.valueOf(COIN)).setScale(scaleForInputValue(feePayingOutputValue), BigDecimal.ROUND_HALF_UP).multiply(BigDecimal.valueOf(COIN)).longValue();

                            rounded = Math.max(MinimumOutputValue, rounded);

                            splits.add(rounded);
                        }
                        break;
                    }
                }
            }

            if (noneFeePayingOutputValue > 0) {
                long remainder = offerTotalValueOutput - splits.get(0);

                long remainderRounded = BigDecimal.valueOf(remainder).divide(BigDecimal.valueOf(COIN)).setScale(scaleForInputValue(noneFeePayingOutputValue), BigDecimal.ROUND_HALF_UP).multiply(BigDecimal.valueOf(COIN)).longValue();

                remainderRounded = Math.max(MinimumOutputChangeSplitValue, remainderRounded);

                splits.add(remainderRounded);
            }

            Offer newOffer = new Offer();

            long totalValueNeeded = 0;

            newOffer.feePercent = 0;

            for (Long splitValue : splits) {
                Output outOne = new Output();

                outOne.excludeFromFee = false;
                outOne.script = Script.createOutputScript(ourWallet.getRandomAddress());
                outOne.value = splitValue;

                newOffer.addRequestedOutput(outOne);

                totalValueNeeded += splitValue;
            }

            if (!addInputsForValue(unspent, newOffer, totalValueNeeded)) {
                Logger.log(Logger.SeverityWARN, "Error Adding inputs for offer");
                return false;
            }

            {
                //Here we consume any excess change
                long totalValueInput = 0;
                for (OutpointWithValue outpoint : newOffer.getOfferedOutpoints()) {
                    totalValueInput += outpoint.getValue();
                }

                long remainder = totalValueInput - totalValueNeeded;
                int ii = 0;
                while (remainder > totalValueNeeded && ii < 4) {
                    for (Long splitValue : splits) {
                        Output outOne = new Output();

                        outOne.excludeFromFee = false;
                        outOne.script = Script.createOutputScript(ourWallet.getRandomAddress());
                        outOne.value = splitValue;

                        newOffer.addRequestedOutput(outOne);
                    }

                    remainder -= totalValueNeeded;

                    ++ii;
                }
            }

            if (!addOurOffer(newOffer)) {
                Logger.log(Logger.SeverityWARN, "Error Adding Our Offer");
                return false;
            }

            return true;
        }

        public long getRequestedOutputCount() {
            long count = 0;
            for (Offer offer : offers) {
                count += offer.getRequestedOutputs().size();
            }

            for (Offer offer : ourOffers) {
                count += offer.getRequestedOutputs().size();
            }

            return count;
        }

        public long getOfferedInputCount() {
            long count = 0;
            for (Offer offer : offers) {
                count += offer.getOfferedOutpoints().size();
            }

            for (Offer offer : ourOffers) {
                count += offer.getOfferedOutpoints().size();
            }

            return count;
        }

        public synchronized void mixWithOurWallet() throws Exception {

            List<MyTransactionOutPoint> allUnspent = ourWallet.getUnspentOutputs(1000);

            Map<Offer, List<MyTransactionOutPoint>> unspentFromOurTransaction = new HashMap<>();

            int allFailedCount = 0;
            while (allFailedCount < 10) {
                boolean allFailed = true;
                boolean fullBreak = false;
                for (Offer offer : offers) {
                    List<MyTransactionOutPoint> unspent;
                    if (offer.zeroConfirmationTransactionAllowedToSpend != null && Math.random() >= 0.90) {
                        if (!unspentFromOurTransaction.containsKey(offer)) {
                            unspentFromOurTransaction.put(offer, ourWallet.getUnspentOutputsCreatedByTransaction(offer.zeroConfirmationTransactionAllowedToSpend));
                        }

                        unspent = unspentFromOurTransaction.get(offer);
                    } else {
                        unspent = allUnspent;
                    }

                    try {
                        if (addOutputsWhichMimicsOffer(unspent, offer)) {
                            allFailed = false;
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }

                    if (getRequestedOutputCount() >= TargetNumberOfOutputs || getOfferedInputCount() >= TargetMaxNumberOfInputs) {
                        fullBreak = true;
                        break;
                    }
                }

                if (allFailed) {
                    ++allFailedCount;
                }

                if (fullBreak) {
                    break;
                }
            }

            try {
                while (getRequestedOutputCount() < MinNumberOfOutputs && allUnspent.size() > 0) {
                    Offer newOffer = new Offer();

                    newOffer.feePercent = 0;

                    Output outOne = new Output();

                    outOne.excludeFromFee = false;
                    outOne.script = Script.createOutputScript(ourWallet.getRandomAddress());
                    outOne.value = allUnspent.iterator().next().getValue().longValue();

                    newOffer.addRequestedOutput(outOne);

                    if (!addInputsForValue(allUnspent, newOffer, outOne.value)) {
                        Logger.log(Logger.SeverityWARN, "getRequestedOutputCount() < MinNumberOfOutputs - Error Adding inputs for offer");
                        break;
                    }

                    if (!addOurOffer(newOffer)) {
                        Logger.log(Logger.SeverityWARN, "getRequestedOutputCount() < MinNumberOfOutputs - Error Adding Our Offer");
                        break;
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        public synchronized void constructTransaction() throws Exception {

            Transaction transaction = new Transaction(NetworkParameters.prodNet());

            List<Output> allRequestedOutputs = new ArrayList<>();
            List<OutpointWithValue> allOfferedOutpoints = new ArrayList<>();

            for (Offer offer : offers) {
                for (Output outputRequest : offer.getRequestedOutputs()) {
                    allRequestedOutputs.add(outputRequest);
                }

                for (OutpointWithValue outpoint : offer.getOfferedOutpoints()) {
                    allOfferedOutpoints.add(outpoint);
                }
            }

            for (Offer offer : ourOffers) {
                for (Output outputRequest : offer.getRequestedOutputs()) {
                    allRequestedOutputs.add(outputRequest);
                }

                for (OutpointWithValue outpoint : offer.getOfferedOutpoints()) {
                    allOfferedOutpoints.add(outpoint);
                }
            }

            //Randomize input order
            Collections.shuffle(allRequestedOutputs);

            //Randomize output order
            Collections.shuffle(allOfferedOutpoints);

            //Add all the outputs
            for (Output outputRequest : allRequestedOutputs) {
                TransactionOutput out = new TransactionOutput(NetworkParameters.prodNet(), transaction, BigInteger.valueOf(outputRequest.value), outputRequest.script);

                transaction.addOutput(out);
            }

            for (OutpointWithValue outpoint : allOfferedOutpoints) {
                TransactionOutPoint outPoint = new MyTransactionOutPointWrapper(outpoint);

                TransactionInput input = new TransactionInput(NetworkParameters.prodNet(), null, new byte[0], outPoint);

                input.outpoint = outPoint;

                transaction.addInput(input);
            }


            BigInteger totalValueOutput = BigInteger.ZERO;
            for (TransactionOutput output :transaction.getOutputs()) {
                totalValueOutput = totalValueOutput.add(output.getValue());
            }

            BigInteger totalValueInput = BigInteger.ZERO;
            for (TransactionInput input : transaction.getInputs()) {
                totalValueInput = totalValueInput.add(input.getOutpoint().getConnectedOutput().getValue());
            }

            if (totalValueInput.compareTo(totalValueOutput) < 0) {
                throw new Exception("totalValueInput < totalValueOutput");
            }

            //Always Pay Default Fee
            BigInteger change = totalValueInput.subtract(totalValueOutput);

            BigInteger feedPaid = BigInteger.ZERO;

            int nKB = (int)Math.ceil((transaction.bitcoinSerialize().length + (transaction.getInputs().size()*scriptSigSize)) / 1000d);

            //Check fee
            BigInteger extraFeeNeeded = BigInteger.valueOf(nKB).multiply(TransactionFeePer1000Bytes).subtract(feedPaid);
            if (extraFeeNeeded.compareTo(BigInteger.ZERO) > 0) {
                change = change.subtract(extraFeeNeeded);
                feedPaid = feedPaid.add(extraFeeNeeded);
            }

            final List<Offer> allOffers = new ArrayList<>(this.offers);

            allOffers.addAll(this.ourOffers);

            int cOfferOffset = 0;

            final Set<Long> alreadyAddedDifferenceValues = new HashSet<>();

            //All new outputs using the value difference between offers
            //e.g. if offer 1 has a value of 5 BTC and offer 2 has a value of 6 BTC we add a 1 BTC random output
            while (change.longValue() >= MinimumOutputValue) {
                boolean allFailed = true;

                for (Offer firstOffer : offers) {
                    if (transaction.getOutputs().size() > MaxNumberOfOutputsIncludingChange || transaction.getInputs().size() > MaxNumberOfInputs) {
                        break;
                    }

                    if (nKB >= MaximumSoftTransactionSize) {
                        break;
                    }

                    long firstOfferTotalOutputValue = firstOffer.getValueOutputRequested();

                    boolean _break = false;

                    for (int ii = 0; ii < allOffers.size(); ++ii) {
                        final Offer secondOffer = allOffers.get((ii+cOfferOffset) % allOffers.size());

                        if (secondOffer.getOfferID() == firstOffer.getOfferID()) {
                            continue;
                        }

                        long secondOfferTotalOutputValue = secondOffer.getValueOutputRequested();

                        long difference = secondOfferTotalOutputValue - firstOfferTotalOutputValue;

                        if (difference < 0) {
                            difference = -difference;
                        }

                        if (difference < MinimumOutputValueExcludeFee) {
                            continue;
                        }

                        BigInteger differenceBN = BigInteger.valueOf(difference);

                        //Make sure the difference is less than the change value (i.e. we have enough change to spend)
                        if (differenceBN.compareTo(change.subtract(BigInteger.valueOf(MinimumOutputValue))) <= 0) {

                            if (!alreadyAddedDifferenceValues.add(differenceBN.longValue()))
                                continue;

                            //If it is add an output with the difference value
                            transaction.addOutput(differenceBN, ourWallet.getRandomAddress());

                            change = change.subtract(differenceBN);

                            //Check fee
                            nKB = (int)Math.ceil((transaction.bitcoinSerialize().length + (transaction.getInputs().size()*scriptSigSize)) / 1000d);
                            extraFeeNeeded = BigInteger.valueOf(nKB).multiply(TransactionFeePer1000Bytes).subtract(feedPaid);

                            if (extraFeeNeeded.compareTo(BigInteger.ZERO) > 0) {
                                change = change.subtract(extraFeeNeeded);
                                feedPaid = feedPaid.add(extraFeeNeeded);
                            }

                            allFailed = false;

                            _break = true;

                            break;
                        }
                    }

                    if (_break) {
                        break;
                    }

                    ++cOfferOffset;
                }

                if (allFailed) {
                    break;
                }
            }

            //Try cloning some offer outputs with variance
            while (change.longValue() >= MinimumOutputValue) {
                boolean allFailed = true;

                for (Offer offer : offers) {
                    if (transaction.getOutputs().size() > MaxNumberOfOutputsIncludingChange || transaction.getInputs().size() > MaxNumberOfInputs) {
                        break;
                    }

                    if (nKB >= MaximumSoftTransactionSize) {
                        break;
                    }

                    boolean _break = false;
                    for (Output output : offer.requestedOutputs) {
                        if (!output.isExcludeFromFee() && output.value <= change.longValue()-MinStandardOutputSize.longValue()) {
                            double rand = (Math.random()-0.5)*2; //-1 to 1

                            long randomVariance = (long)((output.getValue() / 100d) * (VarianceWhenMimicingOutputValue*rand));

                            BigInteger rounded = BigDecimal.valueOf(output.value + randomVariance).divide(BigDecimal.valueOf(COIN)).setScale(scaleForInputValue(output.getValue()), BigDecimal.ROUND_HALF_UP).multiply(BigDecimal.valueOf(COIN)).toBigInteger();

                            if (rounded.compareTo(change.subtract(BigInteger.valueOf(MinimumOutputValue))) <= 0) {
                                transaction.addOutput(rounded, ourWallet.getRandomAddress());

                                change = change.subtract(rounded);

                                //Check fee
                                nKB = (int)Math.ceil((transaction.bitcoinSerialize().length + (transaction.getInputs().size()*scriptSigSize)) / 1000d);
                                extraFeeNeeded = BigInteger.valueOf(nKB).multiply(TransactionFeePer1000Bytes).subtract(feedPaid);

                                if (extraFeeNeeded.compareTo(BigInteger.ZERO) > 0) {
                                    change = change.subtract(extraFeeNeeded);
                                    feedPaid = feedPaid.add(extraFeeNeeded);
                                }

                                allFailed = false;

                                _break = true;

                                break;
                            }
                        }
                    }

                    if (_break) {
                        break;
                    }
                }

                if (allFailed) {
                    break;
                }
            }


            //Check fee
            nKB = (int)Math.ceil((transaction.bitcoinSerialize().length + (transaction.getInputs().size()*scriptSigSize)) / 1000d);
            extraFeeNeeded = BigInteger.valueOf(nKB).multiply(TransactionFeePer1000Bytes).subtract(feedPaid);

            if (extraFeeNeeded.compareTo(BigInteger.ZERO) > 0) {
                change = change.subtract(extraFeeNeeded);
            }

            if (change.compareTo(BigInteger.ZERO) > 0) {
                transaction.addOutput(change, ourWallet.getRandomAddress());
            }

            Collections.shuffle(transaction.getInputs());

            Collections.shuffle(transaction.getOutputs());

            transaction.hash = null;

            this.transaction = transaction;
        }

        public long getCreatedTime() {
            return createdTime;
        }

        public Proposal() {
            proposalID = randomID();
        }

        public synchronized boolean addOurOffer(Offer offer) {
            for (OutpointWithValue outpointWithValue : offer.getOfferedOutpoints()) {
                if (outpointsSpentSoFar.contains(outpointWithValue)) {
                    return false;
                }
            }

            if (ourOffers.add(offer)) {
                outpointsSpentSoFar.addAll(offer.getOfferedOutpoints());
                return true;
            } else {
                return false;
            }
        }

        public synchronized boolean addOffer(Offer offer) {
            for (OutpointWithValue outpointWithValue : offer.getOfferedOutpoints()) {
                if (outpointsSpentSoFar.contains(outpointWithValue)) {
                    return false;
                }
            }

            if (offers.add(offer)) {
                outpointsSpentSoFar.addAll(offer.getOfferedOutpoints());
                return true;
            } else {
                return false;
            }
        }

        public List<Offer> getOffers() {
            return offers;
        }

        public long getProposalID() {
            return proposalID;
        }

        @Override
        public String toString() {
            return "Proposal{" +
                    "offers=" + offers +
                    ", proposalID=" + proposalID +
                    '}';
        }
    }


    public static Proposal findProposal(long proposalID) {
        Proposal proposal = activeProposals.get(proposalID);

        if (proposal != null)
            return proposal;

        return null;
    }


    public static CompletedTransaction findCompletedTransactionByProposalID(long proposalID) {
        for (CompletedTransaction completedTransaction : recentlyCompletedTransactions.values()) {
            if (completedTransaction.getProposalID() == proposalID) {
                return completedTransaction;
            }
        }

        return null;
    }

    public static Offer findOffer(long offerID) {
        Offer offer = pendingOffers.get(offerID);

        if (offer != null)
            return offer;

        for (Proposal proposal : activeProposals.values()) {
            for (Offer _offer : proposal.getOffers()) {
                if (_offer.getOfferID() == offerID)
                    return _offer;
            }
        }

        return null;
    }

    public static boolean isAddressTargetOfAnActiveOutput(String address) {
        return findActiveOfferTargetingAddress(address) != null || findActiveProposalTargetingAddress(address) != null;
    }

    public static Offer findActiveOfferTargetingAddress(String address) {
        for (Offer offer : pendingOffers.values()) {
            for (Output output : offer.getRequestedOutputs())
                if (output.getAddress().toString().equals(address))
                    return offer;
        }

        return null;
    }

    public static Proposal findActiveProposalTargetingAddress(String address) {
        for (Proposal proposal : activeProposals.values()) {
            for (Offer offer : proposal.getOffers()) {
                for (Output output : offer.getRequestedOutputs())
                    if (output.getAddress().toString().equals(address))
                        return proposal;
            }

            for (Offer offer : proposal.ourOffers) {
                for (Output output : offer.getRequestedOutputs())
                    if (output.getAddress().toString().equals(address))
                        return proposal;
            }
        }
        return null;
    }


    public static boolean isOutpointInUse(Hash hash, int index) {
        return findOfferConsumingOutpoint(hash, index) != null;
    }

    public static boolean isAddressInUse(String address) throws ScriptException {
        return findOfferConsumingAddress(address) != null;
    }

    public static Offer findOfferConsumingAddress(String address) throws ScriptException {
        for (Offer offer : pendingOffers.values()) {
            for (OutpointWithValue outpointWithValue : offer.getOfferedOutpoints())
                if (outpointWithValue.getAddress().equals(address))
                    return offer;
        }

        for (Proposal proposal : activeProposals.values()) {
            for (Offer offer : proposal.getOffers()) {
                for (OutpointWithValue outpointWithValue : offer.getOfferedOutpoints())
                    if (outpointWithValue.getAddress().equals(address))
                        return offer;
            }

            for (Offer offer : proposal.ourOffers) {
                for (OutpointWithValue outpointWithValue : offer.getOfferedOutpoints())
                    if (outpointWithValue.getAddress().equals(address))
                        return offer;
            }
        }

        return null;
    }


    public static boolean wasOutpointRecentlySpentByUs(Hash hash, int index, long proposalID) {

        for (Proposal proposal : activeProposals.values()) {

            //Ignore a single proposal
            if (proposal.getProposalID() == proposalID)
                continue;

            for (Offer offer : proposal.offers) {
               for (OutpointWithValue outpointWithValue : offer.getOfferedOutpoints()) {
                   if (new Hash(outpointWithValue.getHash().getBytes()).equals(hash) && outpointWithValue.getIndex() == index)
                       return true;
               }
            }

            for (Offer offer : proposal.ourOffers) {
                for (OutpointWithValue outpointWithValue : offer.getOfferedOutpoints()) {
                    if (new Hash(outpointWithValue.getHash().getBytes()).equals(hash) && outpointWithValue.getIndex() == index)
                        return true;
                }
            }
        }

        for (CompletedTransaction completedTransaction : recentlyCompletedTransactions.values()) {
            List<TransactionInput> inputs = completedTransaction.getTransaction().getInputs();

            for (TransactionInput input : inputs) {
                TransactionOutPoint outPoint = input.getOutpoint();

                if (new Hash(outPoint.getHash().getBytes()).equals(hash) && outPoint.getIndex() == index)
                    return true;
            }
        }

        return false;
    }

    public static Offer findOfferConsumingOutpoint(Hash hash, int index) {
        for (Offer offer : pendingOffers.values()) {
            for (OutpointWithValue outpointWithValue : offer.getOfferedOutpoints())
                if (outpointWithValue.getHash().equals(hash) && outpointWithValue.getIndex() == index)
                    return offer;
        }

        for (Proposal proposal : activeProposals.values()) {
            for (Offer offer : proposal.getOffers()) {
                for (OutpointWithValue outpointWithValue : offer.getOfferedOutpoints())
                    if (outpointWithValue.getHash().equals(hash) && outpointWithValue.getIndex() == index)
                        return offer;
            }

            for (Offer offer : proposal.ourOffers) {
                for (OutpointWithValue outpointWithValue : offer.getOfferedOutpoints())
                    if (outpointWithValue.getHash().equals(hash) && outpointWithValue.getIndex() == index)
                        return offer;
            }
        }

        return null;
    }

    public static Proposal findActiveProposalByTransaction(Hash hash) {
        for (Proposal proposal : activeProposals.values()) {
            if (proposal.isFinalized && proposal.transaction != null)
                if (new Hash(proposal.transaction.getHash().getBytes()).equals(hash))
                    return proposal;
        }

        return null;
    }

    public static Proposal findActiveProposalFromOffer(Offer offer) {
        for (Proposal proposal : activeProposals.values()) {
            for (Offer _offer : proposal.getOffers()) {
                if (_offer.equals(offer))
                    return proposal;
            }

        }
        return null;
    }

    public static class MyTransactionOutPointWrapper extends TransactionOutPoint {
        private static final long serialVersionUID = 1L;
        Script script;
        BigInteger value;

        public MyTransactionOutPointWrapper(OutpointWithValue out) throws ProtocolException, ScriptException {
            super(NetworkParameters.prodNet(), out.index, new Sha256Hash(out.hash.getBytes()));
            this.script = out.getScript();
            this.value = BigInteger.valueOf(out.value);
        }

        @Override
        public TransactionOutput getConnectedOutput() {
            return new TransactionOutput(params, null, value, script.program);
        }

        @Override
        public byte[] getConnectedPubKeyScript() {
            return script.program;
        }
    }

    public static class Output implements Serializable  {
        static final long serialVersionUID = 1L;

        private byte[] script;
        private long value;
        private boolean excludeFromFee;

        public Script getScript() throws ScriptException {
            return newScript(script);
        }

        public long getValue() {
            return value;
        }

        public boolean isExcludeFromFee() {
            return excludeFromFee;
        }

        public Address getAddress() {
            try {
                return getScript().getToAddress();
            } catch (ScriptException e) {
                e.printStackTrace();
                return null;
            }
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            Output output = (Output) o;

            if (excludeFromFee != output.excludeFromFee) return false;
            if (value != output.value) return false;
            if (!Arrays.equals(script, output.script)) return false;

            return true;
        }

        @Override
        public int hashCode() {
            int result = script != null ? Arrays.hashCode(script) : 0;
            result = 31 * result + (int) (value ^ (value >>> 32));
            result = 31 * result + (excludeFromFee ? 1 : 0);
            return result;
        }

        @Override
        public String toString() {
            return "Output{" +
                    "address=" + getAddress() +
                    ", value=" + value +
                    ", excludeFromFee=" + excludeFromFee +
                    '}';
        }
    }

    public static class OutpointWithValue implements Serializable  {
        static final long serialVersionUID = 1L;

        private byte[] script;
        private Hash hash;
        private int index;
        private long value;

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            OutpointWithValue that = (OutpointWithValue) o;

            if (index != that.index) return false;
            if (hash != null ? !hash.equals(that.hash) : that.hash != null) return false;

            return true;
        }

        @Override
        public int hashCode() {
            int result = hash != null ? hash.hashCode() : 0;
            result = 31 * result + index;
            return result;
        }

        @Override
        public String toString() {
            return "OutpointWithValue{" +
                    "script=" + script +
                    ", hash=" + hash +
                    ", index=" + index +
                    ", value=" + value +
                    '}';
        }

        public Script getScript() throws ScriptException {
            return newScript(script);
        }

        public String getAddress() throws ScriptException {
            return getScript().getToAddress().toString();
        }

        public Hash getHash() {
            return hash;
        }

        public int getIndex() {
            return index;
        }

        public long getValue() {
            return value;
        }
    }

    public static class Offer implements Serializable  {
        static final long serialVersionUID = 1L;

        private long receivedTime;
        private long offerID;
        private List<OutpointWithValue> offeredOutpoints = new CopyOnWriteArrayList<>();
        private List<Output> requestedOutputs = new CopyOnWriteArrayList<>();
        private double feePercent;
        private transient Token token;
        private transient MyTransaction zeroConfirmationTransactionAllowedToSpend;
        private transient long forceProposalMaxAge;

        public Offer() {
            offerID = randomID();
            receivedTime = System.currentTimeMillis();
        }

        public Token getToken() {
            return token;
        }

        private double getFeePercent() {
            return feePercent;
        }

        public long calculateFee() {
            return getValueOffered()-getValueOutputRequested();
        }

        public long getValueOffered() {
            long totalValueOffered = 0;
            for (OutpointWithValue outpoint : getOfferedOutpoints()) {
                totalValueOffered += outpoint.value;
            }
            return totalValueOffered;
        }

        public long getValueOutputRequested() {
            long totalOutputRequested = 0;
            for (Output output : getRequestedOutputs()) {
                totalOutputRequested += output.value;
            }
            return totalOutputRequested;
        }

        public long calculateFeeExpected() throws Exception {
            if (getFeePercent() == 0) {
                return 0;
            } else {
                long totalFeePayingOutputValue = 0;
                boolean hasBeenExcludedFromFee = false;
                for (Output output : getRequestedOutputs()) {
                    if (output.excludeFromFee) {
                        if (hasBeenExcludedFromFee) {
                            throw new Exception("You can only exclude one input from fee");
                        } else {
                            hasBeenExcludedFromFee = true;
                        }
                    } else {
                        totalFeePayingOutputValue += output.value;
                    }
                }

                if (totalFeePayingOutputValue == 0)
                    throw new Exception("You must have at least one fee paying output");

                return totalFeePayingOutputValue / (long)Math.ceil(100 / getFeePercent());
            }
        }

        public boolean addOfferedOutpoint(OutpointWithValue outpointWithValue) {
            return offeredOutpoints.add(outpointWithValue);
        }

        public Set<String> getRequestedOutputAddresses() {
            Set<String> set = new HashSet<>();
            for (Output output : requestedOutputs ){
                set.add(output.getAddress().toString());
            }
            return set;
        }

        public boolean addRequestedOutput(Output pair) {
            return requestedOutputs.add(pair);
        }

        public long getReceivedTime() {
            return receivedTime;
        }

        public long getOfferID() {
            return offerID;
        }

        public List<OutpointWithValue> getOfferedOutpoints() {
            return Collections.unmodifiableList(offeredOutpoints);
        }

        public Collection<Output> getRequestedOutputs() {
            return Collections.unmodifiableList(requestedOutputs);
        }

        public boolean isTheSameAsOffer(Offer _offer) {

            if (offeredOutpoints.size() != _offer.offeredOutpoints.size())
                return false;

            if (requestedOutputs.size() != _offer.requestedOutputs.size())
                return false;

            for (OutpointWithValue outpointWithValue : offeredOutpoints) {
                boolean found = false;

                for (OutpointWithValue _outpointWithValue : _offer.offeredOutpoints) {
                    if (outpointWithValue.equals(_outpointWithValue)) {
                        found = true;
                        break;
                    }
                }

                if (!found) {
                    return false;
                }
            }

            for (Output output : requestedOutputs) {
                boolean found = false;

                for (Output _output : requestedOutputs) {
                    if (output.equals(_output)) {
                        found = true;
                        break;
                    }
                }

                if (!found) {
                    return false;
                }
            }

            return true;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            Offer offer = (Offer) o;

            if (offerID != offer.offerID) return false;

            return true;
        }

        @Override
        public int hashCode() {
            return (int) (offerID ^ (offerID >>> 32));
        }

        @Override
        public String toString() {
            return "Offer{" +
                    "receivedTime=" + receivedTime +
                    ", offerID=" + offerID +
                    ", offeredOutpoints=" + offeredOutpoints +
                    ", requestedOutputs=" + requestedOutputs +
                    '}';
        }
    }

    @Override
    protected void doGet(HttpServletRequest req, final HttpServletResponse res) throws ServletException, IOException {

        if (!AdminServlet.isAuthorized(req)) {
            res.setStatus(404);
            return;
        }

        req.setAttribute("pending_offers", pendingOffers.values());
        req.setAttribute("active_proposals", activeProposals.values());



        List<CompletedTransaction> recentlyCompleted = new ArrayList<>(recentlyCompletedTransactions.values());

        Collections.sort(recentlyCompleted);


        int totalParticipants = 0;
        long totalOutputValue = 0;
        for (CompletedTransaction completedTransaction : recentlyCompleted) {
            totalParticipants += completedTransaction.nParticipants;

            for (TransactionOutput output : completedTransaction.getTransaction().getOutputs()) {
                totalOutputValue += output.getValue().longValue();
            }
        }

        req.setAttribute("total_participants", totalParticipants);
        req.setAttribute("average_participants", ((double)totalParticipants / (double)recentlyCompleted.size()));
        req.setAttribute("recently_completed_transactions",recentlyCompleted);
        req.setAttribute("total_output_value", (totalOutputValue / (double)COIN));

        getServletContext().getRequestDispatcher("/WEB-INF/sharedcoin-status.jsp").forward(req, res);
    }

    @Override
    public void doOptions(HttpServletRequest req, HttpServletResponse resp) throws IOException, ServletException {
        resp.setHeader("Access-Control-Allow-Origin", "*");
        resp.setHeader("Access-Control-Allow-Methods", "GET, POST");
        resp.setHeader("Access-Control-Allow-Headers", "X-Requested-With, Content-Type, Accept, Origin, If-Modified-Since, Cache-Control, User-Agent");
        resp.setHeader("Access-Control-Max-Age", "86400");
        resp.setHeader("Allow", "GET, POST, OPTIONS");
    }

    public void setCORSAllowAll(HttpServletResponse res) {
        res.setHeader("Access-Control-Allow-Origin", "*");
    }

    @Override
    protected void doPost(HttpServletRequest req, final HttpServletResponse res) throws ServletException, IOException {

        try {
            setCORSAllowAll(res);

            if (enabled == false && !AdminServlet.isAuthorized(req)) {
                throw new Exception("Shared Coin is currently disabled");
            }

            String versionString = req.getParameter("version");
            int version = 1;
            if (versionString != null) {
                try {
                    version = Integer.valueOf(versionString);

                    if (version < MinSupportedVersion)
                        throw new Exception("Unsupported Version");
                } catch (Exception e) {
                    throw new Exception("Unsupported Version");
                }
            }

            String method = req.getParameter("method");
            if (method != null) {
                if (method.equals("submit_offer")) {
                    Offer existingConflictingOffer = null;
                    MyTransactionOutput outputAlreadySpent = null;

                    Offer offer = new Offer();

                    JSONObject jsonObject = (JSONObject) new JSONParser().parse(req.getParameter("offer"));

                    JSONArray inputs = (JSONArray) jsonObject.get("offered_outpoints");

                    if (inputs == null || inputs.size() == 0) {
                        throw new Exception("You Must Provide One Or More Inputs");
                    }

                    if (inputs.size() > MaximumOfferNumberOfInputs) {
                        throw new Exception("Maximum number of inputs exceeded");
                    }

                    JSONArray outputs = (JSONArray) jsonObject.get("request_outputs");

                    if (outputs == null || outputs.size() == 0) {
                        throw new Exception("You Must Provide One Or More Outputs");
                    }

                    if (outputs.size() > MaximumOfferNumberOfOutputs) {
                        throw new Exception("Maximum number of outputs exceeded");
                    }

                    if (version >= 3) {
                        String tokenString = req.getParameter("token");

                        if (tokenString == null) {
                            throw new Exception("You must provide a token");
                        }

                        Token token = Token.decrypt(tokenString);

                        if (token.created < System.currentTimeMillis()-TokenExpiryTime) {
                            throw new Exception("Token has expired");
                        }

                        if (!token.created_ip.equals(AdminServlet.getRealIP(req))) {
                            throw new Exception("Token Requester Changed");
                        }

                        offer.token = token;
                        offer.feePercent = token.fee_percent;
                    } else {
                        offer.feePercent = feePercentForRequest(req);
                    }

                    String userMaxAgeString = req.getParameter("offer_max_age");
                    if (userMaxAgeString != null) {
                        try {
                            long userMaxAge = Long.valueOf(userMaxAgeString);

                            if (userMaxAge < 10000) {
                                throw new Exception("Max Age Must Be Greater 10s");
                            }

                            if (userMaxAge > 3600000) {
                                throw new Exception("Max Age Must Be Less Than 1 Hour");
                            }

                            offer.forceProposalMaxAge = userMaxAge;
                        } catch (Exception e) {
                            throw new Exception("Invalid Numerical Value");
                        }
                    } else {
                        offer.forceProposalMaxAge = randomLong(OfferForceProposalAgeMin, OfferForceProposalAgeMax);
                    }

                    Map<Hash, MyTransaction> _transactionCache = new HashMap<>();
                    for (Object _input : inputs) {
                        JSONObject input = (JSONObject)_input;

                        Hash hash = new Hash((String)input.get("hash"));
                        short index;
                        try {
                            index = Short.valueOf(input.get("index").toString());
                        } catch (Exception e) {
                            throw new Exception("Invalid Integer");
                        }

                        MyTransaction transaction = _transactionCache.get(hash);
                        if (transaction == null) {
                            Exception _e = null;

                            for (int ii = 0; ii < 2; ++ii) {
                                try {
                                    transaction = MyRemoteWallet.getTransactionByHash(hash, true);

                                    if (transaction != null) {
                                        break;
                                    }
                                } catch (Exception e) {
                                    _e = e;
                                }

                                Thread.sleep(5000);
                            }

                            if (transaction == null) {
                                for (int ii = 0; ii < 5; ++ii) {
                                    //If it is a transaction we recently broadcast may be blockchain.info is lagging
                                    //Wait a bit
                                    if (recentlyCompletedTransactions.containsKey(hash) || findActiveProposalByTransaction(hash) != null) {
                                        try {
                                            transaction = MyRemoteWallet.getTransactionByHash(hash, true);

                                            if (transaction != null) {
                                                break;
                                            }
                                        } catch (Exception e) {
                                            _e = e;
                                        }

                                        Thread.sleep(10000);
                                    }
                                }
                            }

                            if (transaction == null) {
                                if (_e != null) _e.printStackTrace();

                                throw new Exception("Input Tx is null " + hash);
                            }

                            _transactionCache.put(hash, transaction);
                        }

                        if (transaction.getHeight() == 0) {
                            //Allow unconfirmed inputs from transaction we created
                            if (!isTransactionCreatedByUs(hash)) {
                                throw new Exception("Only confirmed inputs accepted " + hash);
                            } else {
                                offer.zeroConfirmationTransactionAllowedToSpend = transaction;
                            }
                        }

                        if (transaction.getOutputs().size() <= index) {
                            throw new Exception("Outputs size less than index");
                        }

                        TransactionOutput outPoint = transaction.getOutputs().get(index);

                        OutpointWithValue outpointWithValue = new OutpointWithValue();

                        outpointWithValue.hash = hash;
                        outpointWithValue.index = index;
                        outpointWithValue.value = outPoint.getValue().longValue();

                        if (outpointWithValue.value < HardErrorMinimumInputValue) {
                            throw new Exception("The Minimum Input Value is " + (HardErrorMinimumInputValue / (double)COIN) + " BTC");
                        }

                        if (outpointWithValue.value > MaximumInputValue) {
                            throw new Exception("The Maximum Input Value is " + (MaximumInputValue / (double)COIN) + " BTC");
                        }

                        MyTransactionOutput output = (MyTransactionOutput) transaction.getOutputs().get(index);

                        if (output.isSpent()) {
                            outputAlreadySpent = output;
                        }

                        outpointWithValue.script = output.getScriptBytes();

                        if (outpointWithValue.script == null) {
                            throw new Exception("Output Script is null");
                        }

                        if (!outpointWithValue.getScript().isSentToAddress() && !outpointWithValue.getScript().isSentToRawPubKey()) {
                            throw new Exception("Invalid output script. Only Address or PubKey Outputs currently supported.");
                        }

                        if (!offer.addOfferedOutpoint(outpointWithValue)) {
                            throw new Exception("Error Adding Outpoint");
                        }
                    }

                    for (Object _output : outputs) {
                        JSONObject output = (JSONObject)_output;

                        Script script = newScript(Hex.decode((String) output.get("script")));
                        long value;
                        try {
                            value = Long.valueOf(output.get("value").toString());
                        } catch (Exception e) {
                            throw new Exception("Invalid Integer");
                        }

                        if (!script.isSentToAddress() && !script.isSentToRawPubKey() && !script.isPayToScriptHash()) {
                            throw new Exception("Strange script output");
                        }

                        //The client can cheat here by requesting the largest output be excluded even if it isn't the change address
                        //Can be detected next repetition
                        //Or enforced by checking the available inputs and determining if the client was able to use smaller inputs (Also possible to predict change address this method)
                        boolean excludeFromFee = false;

                        if (output.get("exclude_from_fee") != null) {
                            excludeFromFee = Boolean.valueOf(output.get("exclude_from_fee").toString());
                        }

                        if (value < MinimumOutputValue && !excludeFromFee) {
                            throw new Exception("The Minimum Output Value Size is " + (MinimumOutputValue / (double)COIN) + " BTC  (Actual: " + (value / (double)COIN) + ")");
                        } else if (value < MinimumOutputValueExcludeFee && excludeFromFee) {
                            throw new Exception("The Minimum Output Value Excluding Fee is " + (MinimumOutputValueExcludeFee / (double)COIN) + " BTC  (Actual: " + (value / (double)COIN) + ")");
                        }

                        if (value > HardErrorMaximumOutputValue && !excludeFromFee) {
                            throw new Exception("The Maximum Output Value Size is " + (HardErrorMaximumOutputValue / (double)COIN) + " BTC (Actual: " + (value / (double)COIN) + ")");
                        }

                        Output outputContainer = new Output();

                        outputContainer.script = script.program;
                        outputContainer.value = value;
                        outputContainer.excludeFromFee = excludeFromFee;

                        if (offer.getRequestedOutputAddresses().contains(script.getToAddress().toString())) {
                            throw new Exception("Each Output Address must be unique");
                        }

                        if (!offer.addRequestedOutput(outputContainer)) {
                            throw new Exception("Error Adding Requested Output");
                        }
                    }

                    long totalInputValue = offer.getValueOffered();
                    long totalOutputValue = offer.getValueOutputRequested();

                    if (totalInputValue < totalOutputValue) {
                        throw new Exception("Input Value Greater Than Output Value");
                    }

                    long expectedFee = offer.calculateFeeExpected();

                    if (version >= 2) {
                        expectedFee = Math.max(expectedFee, MinimumFee);
                    }

                    if (totalInputValue-totalOutputValue < expectedFee) {
                        throw new Exception("Insufficient Fee " + (totalInputValue-totalOutputValue) + " expected " + expectedFee);
                    }

                    if (totalInputValue-totalOutputValue > expectedFee) {
                        throw new Exception("Paid too much fee. Possibly a client error. (Expected: " + expectedFee + " Paid: " + (totalInputValue-totalOutputValue) + ")");
                    }


                    //Everything looks good so far
                    //Check for any conflicting inputs
                    //Then add to pending

                    JSONObject obj = new JSONObject();

                    Lock lock = modifyPendingOffersLock.writeLock();

                    lock.lock();
                    try {
                        for (OutpointWithValue outpointWithValue : offer.getOfferedOutpoints()) {
                            Offer tmpExistingConflictingOffer = findOfferConsumingOutpoint(outpointWithValue.getHash(), outpointWithValue.getIndex());

                            if (existingConflictingOffer != null && existingConflictingOffer != tmpExistingConflictingOffer) {
                                throw new Exception("Multiple Conflicting Offers");
                            }

                            existingConflictingOffer = tmpExistingConflictingOffer;
                        }

                        if (existingConflictingOffer != null) {
                            Logger.log(Logger.SeverityWARN, "Offer " + offer + " has conflicting offer " + existingConflictingOffer);

                            if (offer.isTheSameAsOffer(existingConflictingOffer)) {
                                Logger.log(Logger.SeverityWARN, "Conflicting Offer Is Equal");

                                obj.put("offer_id", existingConflictingOffer.getOfferID());
                            } else {
                                throw new Exception("Conflicting Offer");
                            }
                        } else {
                            //Check we didn't recently spend any outputs
                            for (OutpointWithValue outpointWithValue : offer.getOfferedOutpoints()) {
                                if (wasOutpointRecentlySpentByUs(outpointWithValue.getHash(), outpointWithValue.getIndex(), 0)) {
                                    throw new Exception("Outpoint already Spent By Us " + outpointWithValue);
                                }
                            }

                            //If Blockchain.info reports an output is spent it is only fatal when a new offer is being submitted
                            if (outputAlreadySpent != null) {
                                throw new Exception("Outpoint already spent " + outputAlreadySpent);
                            }

                            addOfferToPending(offer);

                            obj.put("offer_id", offer.getOfferID());
                        }
                    } finally {
                        lock.unlock();
                    }

                    res.setContentType("application/json");

                    res.getWriter().print(obj.toJSONString());
                } else if (method.equals("get_offer_id")) {
                    Long offerID;
                    try {
                        offerID = Long.valueOf(req.getParameter("offer_id"));
                    } catch (Exception e) {
                        throw new Exception("Invalid Integer");
                    }

                    JSONObject obj = new JSONObject();

                    Offer offer = findOffer(offerID);

                    if (offer == null) {
                        obj.put("status", "not_found");
                    } else {
                        Proposal proposal = findActiveProposalFromOffer(offer);

                        if (proposal == null) {
                            //Long Polling
                            synchronized(offer) {
                                offer.wait(MaxPollTime);
                            }

                            proposal = findActiveProposalFromOffer(offer);
                        }

                        if (proposal == null) {
                            obj.put("status", "waiting");
                        } else {
                            obj.put("status", "active_proposal");
                            obj.put("proposal_id", proposal.getProposalID());
                        }
                    }

                    res.setContentType("application/json");

                    res.getWriter().print(obj.toJSONString());
                } else if (method.equals("get_info")) {
                    JSONObject obj = new JSONObject();

                    Token token = new Token();

                    token.fee_percent = feePercentForRequest(req);
                    token.created = System.currentTimeMillis();
                    token.created_ip = AdminServlet.getRealIP(req);

                    obj.put("fee_percent", token.fee_percent);
                    obj.put("token", token.encrypt());
                    obj.put("enabled", true);
                    obj.put("minimum_output_value_exclude_fee", MinimumOutputValueExcludeFee);
                    obj.put("minimum_output_value", MinimumOutputValue);
                    obj.put("maximum_output_value", MaximumOutputValue);
                    obj.put("minimum_input_value", MinimumInputValue);
                    obj.put("maximum_input_value", MaximumInputValue);
                    obj.put("maximum_offer_number_of_inputs", MaximumOfferNumberOfInputs);
                    obj.put("maximum_offer_number_of_outputs", MaximumOfferNumberOfOutputs);
                    obj.put("min_supported_version", MinSupportedVersion);
                    obj.put("recommended_min_iterations", RecommendedMinIterations);
                    obj.put("recommended_max_iterations", RecommendedMaxIterations);
                    obj.put("recommended_iterations", randomLong(RecommendedIterationsMin, RecommendedIterationsMax));
                    obj.put("minimum_fee", MinimumFee);

                    res.setContentType("application/json");

                    res.getWriter().print(obj.toJSONString());
                } else if (method.equals("get_proposal_id")) {
                    Long proposalID;
                    try {
                        proposalID = Long.valueOf(req.getParameter("proposal_id"));
                    } catch (Exception e) {
                        throw new Exception("Invalid Integer");
                    }

                    Long offerID;
                    try {
                        offerID = Long.valueOf(req.getParameter("offer_id"));
                    } catch (Exception e) {
                        throw new Exception("Invalid Integer");
                    }

                    Proposal proposal = findProposal(proposalID);

                    JSONObject obj = new JSONObject();

                    if (proposal == null) {

                        CompletedTransaction completedTransaction = findCompletedTransactionByProposalID(proposalID);
                        if (completedTransaction != null) {
                            obj.put("status", "complete");
                            obj.put("tx_hash", completedTransaction.getTransaction().getHash().toString());

                            ByteArrayOutputStream stream = new ByteArrayOutputStream();
                            completedTransaction.getTransaction().bitcoinSerializeToStream(stream);
                            byte[] serialized = stream.toByteArray();
                            obj.put("tx", new String(Hex.encode(serialized), "UTF-8"));
                        } else {
                            obj.put("status", "not_found");
                        }
                    } else if (proposal.isFinalized) {
                        obj.put("status", "complete");
                        obj.put("tx_hash", proposal.getTransaction().getHash().toString());

                        ByteArrayOutputStream stream = new ByteArrayOutputStream();

                        proposal.getTransaction().bitcoinSerializeToStream(stream);

                        byte[] serialized = stream.toByteArray();

                        obj.put("tx", new String(Hex.encode(serialized), "UTF-8"));
                    } else {
                        obj.put("proposal_id", proposal.getProposalID());

                        Offer offer = proposal.findOffer(offerID);

                        if (offer == null) {
                            obj.put("status", "not_found");
                        } else {
                            Transaction tx = proposal.getTransaction();

                            obj.put("status", "signatures_needed");

                            ByteArrayOutputStream stream = new ByteArrayOutputStream();

                            tx.bitcoinSerializeToStream(stream);

                            byte[] serialized = stream.toByteArray();

                            obj.put("tx", new String(Hex.encode(serialized), "UTF-8"));

                            JSONArray array = new JSONArray();
                            for (Proposal.SignatureRequest request : proposal.getSignatureRequests(offer)) {
                                JSONObject pairObj = new JSONObject();

                                pairObj.put("offer_outpoint_index", request.offer_outpoint_index);
                                pairObj.put("tx_input_index", request.tx_input_index);
                                pairObj.put("connected_script", new String(Hex.encode(request.connected_script.program), "UTF-8"));

                                array.add(pairObj);
                            }

                            obj.put("signature_requests", array);
                        }
                    }

                    res.setContentType("application/json");

                    res.getWriter().print(obj.toJSONString());
                } else if (method.equals("poll_for_proposal_completed")) {
                    Long proposalID;
                    try {
                        proposalID = Long.valueOf(req.getParameter("proposal_id"));
                    } catch (Exception e) {
                        throw new Exception("Invalid Integer");
                    }

                    JSONObject obj = new JSONObject();

                    Proposal proposal = findProposal(proposalID);

                    if (proposal == null) {
                        CompletedTransaction completedTransaction = findCompletedTransactionByProposalID(proposalID);
                        if (completedTransaction != null) {
                            obj.put("status", "complete");
                            obj.put("tx_hash", completedTransaction.getTransaction().getHash().toString());

                            ByteArrayOutputStream stream = new ByteArrayOutputStream();
                            completedTransaction.getTransaction().bitcoinSerializeToStream(stream);
                            byte[] serialized = stream.toByteArray();
                            obj.put("tx", new String(Hex.encode(serialized), "UTF-8"));
                        } else {
                            obj.put("status", "not_found");
                        }
                    } else {
                        synchronized(proposal) {
                            if (!proposal.isFinalized) {
                                proposal.wait(MaxPollTime);
                            }
                        }

                        if (proposal.isFinalized) {
                            obj.put("status", "complete");
                            obj.put("tx_hash", proposal.getTransaction().getHash().toString());

                            ByteArrayOutputStream stream = new ByteArrayOutputStream();

                            proposal.getTransaction().bitcoinSerializeToStream(stream);

                            byte[] serialized = stream.toByteArray();

                            obj.put("tx", new String(Hex.encode(serialized), "UTF-8"));
                        } else {
                            obj.put("status", "waiting");
                            obj.put("signatures_required", proposal.getNSignaturesNeeded());
                            obj.put("signatures_submitted", proposal.getNSigned());
                        }
                    }

                    res.setContentType("application/json");

                    res.getWriter().print(obj.toJSONString());
                } else if (method.equals("submit_signatures")) {
                    Long proposalID;
                    try {
                        proposalID = Long.valueOf(req.getParameter("proposal_id"));
                    } catch (Exception e) {
                        throw new Exception("Invalid Integer");
                    }

                    Long offerID;
                    try {
                        offerID = Long.valueOf(req.getParameter("offer_id"));
                    } catch (Exception e) {
                        throw new Exception("Invalid Integer");
                    }

                    final Proposal proposal = findProposal(proposalID);

                    JSONObject obj = new JSONObject();

                    if (proposal == null) {
                        CompletedTransaction completedTransaction = findCompletedTransactionByProposalID(proposalID);
                        if (completedTransaction != null) {
                            obj.put("status", "complete");
                            obj.put("tx_hash", completedTransaction.getTransaction().getHash().toString());

                            ByteArrayOutputStream stream = new ByteArrayOutputStream();
                            completedTransaction.getTransaction().bitcoinSerializeToStream(stream);
                            byte[] serialized = stream.toByteArray();
                            obj.put("tx", new String(Hex.encode(serialized), "UTF-8"));
                        } else {
                            obj.put("status", "not_found");
                        }
                    } else {
                        Offer offer = proposal.findOffer(offerID);

                        if (offer == null) {
                            obj.put("status", "not_found");
                        } else if (proposal.isFinalized) {
                            obj.put("status", "complete");
                            obj.put("tx_hash", proposal.getTransaction().getHash().toString());

                            ByteArrayOutputStream stream = new ByteArrayOutputStream();

                            proposal.getTransaction().bitcoinSerializeToStream(stream);

                            byte[] serialized = stream.toByteArray();

                            obj.put("tx", new String(Hex.encode(serialized), "UTF-8"));
                        } else {
                            JSONArray jsonSignaturesArray = (JSONArray) new JSONParser().parse(req.getParameter("input_scripts"));

                            boolean allSigned = false;
                            for (Object _jsonSignatureObject : jsonSignaturesArray) {
                                JSONObject jsonSignatureObject = (JSONObject)_jsonSignatureObject;

                                int tx_input_index;
                                try {
                                    tx_input_index = Integer.valueOf(jsonSignatureObject.get("tx_input_index").toString());
                                } catch (Exception e) {
                                    throw new Exception("Invalid Integer");
                                }

                                int offer_outpoint_index;
                                try {
                                    offer_outpoint_index = Integer.valueOf(jsonSignatureObject.get("offer_outpoint_index").toString());
                                } catch (Exception e) {
                                    throw new Exception("Invalid Integer");
                                }

                                byte[] inputScriptBytes = Hex.decode((String)jsonSignatureObject.get("input_script"));

                                Script bitcoinJInputScript = newScript(inputScriptBytes);

                                OutpointWithValue outpoint = offer.getOfferedOutpoints().get(offer_outpoint_index);

                                Script connected_script = outpoint.getScript();

                                try {
                                    if (!IsCanonicalSignature(bitcoinJInputScript)) {
                                        throw new ScriptException("IsCanonicalSignature() returned false");
                                    }

                                    bitcoinJInputScript.correctlySpends(proposal.getTransaction(), tx_input_index, connected_script, true);

                                    proposal.input_scripts.put(tx_input_index, bitcoinJInputScript);

                                    allSigned = true;
                                } catch (ScriptException e) {
                                    e.printStackTrace();

                                    allSigned = false;

                                    obj.put("status", "verification_failed");

                                    break;
                                }
                            }

                            if (allSigned) {
                                obj.put("status", "signatures_accepted");
                            }

                            if (proposal.getNSigned() == proposal.getNSignaturesNeeded()) {
                                multiThreadExec.execute(new Runnable() {
                                    @Override
                                    public void run() {
                                        try {
                                            synchronized (proposal) {
                                                proposal.finalizeTransaction();

                                                proposal.pushTransaction();
                                            }
                                        } catch (Exception e) {
                                            Logger.log(Logger.SeveritySeriousError, e);
                                        }
                                    }
                                });
                            }
                        }
                    }

                    res.setContentType("application/json");

                    res.getWriter().print(obj.toJSONString());
                } else if (method.equals("create_proposals")) {
                    runCreateProposals();

                    res.sendRedirect("/");
                } else if (method.equals("finalize_and_push_signed")) {
                    for (final Proposal proposal : activeProposals.values()) {
                        if (proposal.getNSigned() == proposal.getNSignaturesNeeded()) {
                            multiThreadExec.execute(new Runnable() {
                                @Override
                                public void run() {
                                    try {
                                        synchronized (proposal) {
                                            proposal.finalizeTransaction();

                                            proposal.pushTransaction();
                                        }
                                    } catch (Exception e) {
                                        Logger.log(Logger.SeveritySeriousError, e);
                                    }
                                }
                            });
                        }
                    }

                    res.sendRedirect("/home");
                }  else {
                    throw new Exception("Unknown Method");
                }
            } else {
                throw new Exception("No Method Provided");
            }
        } catch (Exception e) {
            Logger.log(Logger.SeverityWARN, e);

            res.setStatus(500);

            res.setContentType("text/plain");

            if (e.getLocalizedMessage() == null)
                res.getWriter().print("Unknown Error Message");
            else
                res.getWriter().print(e.getLocalizedMessage());
        }
    }
}
