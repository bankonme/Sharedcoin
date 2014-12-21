package piuk.website;

import org.bitcoinj.core.*;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.signers.LocalTransactionSigner;
import org.bitcoinj.signers.TransactionSigner;
import org.bitcoinj.wallet.KeyChainGroup;
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
    private final static Map<Long, Offer> pendingOffers = new ConcurrentHashMap<>();
    private final static Map<Long, Proposal> activeProposals = new ConcurrentHashMap<>();
    private final static Map<Hash, CompletedTransaction> recentlyCompletedTransactions = new ConcurrentHashMap<>();
    private final static Map<Long, Transaction> constructingTransactions = new ConcurrentHashMap<>();
    private final static Map<String, CompletedTransaction> _inputToRecentlyCompletedCache = new ConcurrentHashMap<>();
    private final static Map<String, CompletedTransaction> _outputAddressToRecentlyCompletedCache = new ConcurrentHashMap<>();
    private final static Map<String, CompletedTransaction> _inputAddressToRecentlyCompletedCache = new ConcurrentHashMap<>();

    public static int PKSeedCounter = 0;

    public static final long COIN = 100000000;

    private static final long MinimumOutputValue = COIN / 100; //0.01 BTC
    public static final long MinimumOutputChangeSplitValue = COIN / 100; //0.01 BTC
    public static final long MinimumNoneStandardOutputValue = 5460;
    private static final long MinimumOutputValueExcludeFee = MinimumNoneStandardOutputValue;

    private static final long MaximumHardTransactionSize = 100; //100KB
    private static final long MaximumSoftTransactionSize = 16; //16KB

    private static final long MaxPollTime = 5000;

    private static final double DefaultFeePercent = 0.0; //Per rep
    private static final long MinimumFee = (long) (COIN * 0.0005); //At this point transaction fees start costing more

    private static final long HardErrorMaximumOutputValue = COIN * 55; //55 BTC
    public static final long MaximumOutputValue = COIN * 50; //50 BTC

    private static final long HardErrorMinimumInputValue = (long) (COIN * 0.005); //0.005 BTC
    private static final long MinimumInputValue = (long) (COIN * 0.01); //0.01 BTC

    private static final long MaximumInputValue = COIN * 1000; //1000 BTC
    private static final long MaximumOfferNumberOfInputs = 20;
    private static final long MaximumOfferNumberOfOutputs = 20;
    private static final long VarianceWhenMimicingOutputValue = 25; //25%

    private static final long RecommendedMinIterations = 4;
    private static final long RecommendedMaxIterations = 10;
    private static final long RecommendedIterationsMin = 4;
    private static final long RecommendedIterationsMax = 8;

    private static final long MaxChangeSingleUnconfirmedInput = 50 * COIN;
    private static final long MaxChangeSingleConfirmedInput = 5 * COIN;

    public static final long ProtocolVersion = 3;
    private static final long MinSupportedVersion = 2;

    private static final long MinNumberOfOutputs = 2; //The number of outputs to aim for in a single transaction including change outputs
    private static final long MaxNumberOfOutputsIncludingChange = 40; //The number of outputs to aim for in a single transaction including change outputs
    private static final long MaxNumberOfInputs = 100; //The soft max number of inputs to use for in a single transaction

    private static final long ProposalExpiryTimeUnsigned = 120000; //2 Minutes
    private static final long ProposalExpiryTimeSigned = 240000; //4 Minutes

    private static final long OfferExpiryTime = 600000; //10 Minutes
    private static final long ProposalExpiryTimeAfterCompletion = 86400000; //24 Hours
    private static final long ProposalExpiryTimeFailedToBroadcast = 1800000; //30 Minutes

    private static final long OfferForceProposalAgeMax = 40000; //When an offer reaches this age force a proposal creation
    private static final long OfferForceProposalAgeMin = 10000; //When an offer reaches this age force a proposal creation

    private static final long TokenExpiryTime = 86400000; //Expiry time of tokens. 24 hours

    public static final int scriptSigSize = 138; //107 compressed

    public static final BigInteger TransactionFeePer1000Bytes = BigInteger.valueOf((long) (COIN * 0.0001)); //0.0001 BTC Fee

    public static final ExecutorService exec = Executors.newSingleThreadExecutor();

    private static final ExecutorService multiThreadExec = Executors.newCachedThreadPool();

    private static final ReadWriteLock insertPendingOffersLock = new ReentrantReadWriteLock();

    public static Set<Hash> getRecentlyCompletedTransactionHashes() {
        return new HashSet<>(recentlyCompletedTransactions.keySet());
    }

    public static void putRecentlyCompleted(CompletedTransaction completedTransaction) throws IOException {
        final Transaction transaction = completedTransaction.getTransaction();

        for (TransactionInput input : transaction.getInputs()) {
            _inputToRecentlyCompletedCache.put(input.getOutpoint().getHash() + ":" + input.getOutpoint().getIndex(), completedTransaction);
        }

        for (TransactionOutput output : transaction.getOutputs()) {
            try {
                String address = output.getScriptPubKey().getToAddress(MainNetParams.get()).toString();

                _outputAddressToRecentlyCompletedCache.put(address, completedTransaction);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        recentlyCompletedTransactions.put(new Hash(transaction.getHash().getBytes()), completedTransaction);
    }

    public synchronized static void saveRecentlyCompleted() {
        try {
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
        } catch (Exception e) {
            Logger.log(Logger.SeveritySeriousError, e);
        }
    }

    private static void removeRecentlyCompleted(CompletedTransaction completedTransaction) {

        final Transaction transaction = completedTransaction.getTransaction();

        for (TransactionInput input : transaction.getInputs()) {
            _inputToRecentlyCompletedCache.keySet().remove(input.getOutpoint().getHash() + ":" + input.getOutpoint().getIndex());
        }

        for (TransactionOutput output : transaction.getOutputs()) {
            try {
                String address = output.getScriptPubKey().getToAddress(MainNetParams.get()).toString();

                _outputAddressToRecentlyCompletedCache.keySet().remove(address);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }


        recentlyCompletedTransactions.keySet().remove(new Hash(transaction.getHash().getBytes()));
    }

    public static class CompletedTransaction implements Serializable, Comparable<CompletedTransaction> {
        static final long serialVersionUID = 1L;

        long proposalID;
        Transaction transaction;
        boolean isConfirmedBroadcastSuccessfully = false;
        boolean isConfirmed = false;
        boolean isDoubleSpend = false;

        long lastCheckedConfirmed = 0;
        long completedTime;
        volatile int pushCount = 0;
        int nParticipants;
        long fee;

        private transient long expected_fee = 0;

        public boolean getIsConfirmed() {
            return isConfirmed;
        }

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

        public long getExpectedFee() {
            if (expected_fee != 0) {
                int nKB = (int) Math.ceil(transaction.bitcoinSerialize().length / 1000d);

                expected_fee = (nKB + 1) * TransactionFeePer1000Bytes.longValue();
            }
            return expected_fee;
        }

        public boolean isOkToSpend() {
            return _isOkToSpend(new HashSet<Hash>());
        }

        private boolean _isOkToSpend(Set<Hash> testedHashes) {
            if (isConfirmed) {
                return true;
            }

            if (!isConfirmedBroadcastSuccessfully) {
                return false;
            }

            if (isDoubleSpend) {
                return false;
            }

            if (getFee() < getExpectedFee()) {
                return false;
            }

            for (TransactionOutput output : getTransaction().getOutputs()) {
                if (output.getValue().longValue() < MinimumNoneStandardOutputValue) {
                    return false;
                }
            }

            for (TransactionInput input : getTransaction().getInputs()) {
                final Hash hash = new Hash(input.getOutpoint().getHash().getBytes());

                if (!testedHashes.add(hash)) {
                    continue;
                }

                final CompletedTransaction parent = findCompletedTransaction(hash);

                if (parent == null) {
                    continue;
                }

                if (!parent._isOkToSpend(testedHashes))
                    return false;
            }

            return true;
        }

        public long getFee() {
            return fee;
        }

        public boolean pushTransaction() throws Exception {

            if (completedTime == 0)
                completedTime = System.currentTimeMillis();

            boolean pushed = false;

            try {
                pushed = MyRemoteWallet.pushTx(transaction);
            } catch (Exception e) {
                Logger.log(Logger.SeveritySeriousError, e);
            }

            if (!pushed) {
                Logger.log(Logger.SeveritySeriousError, "Error Pushing transaction " + transaction);
            }

            pushCount += 1;

            synchronized (this) {
                this.notifyAll();
            }

            return pushed;
        }

        public long getProposalID() {
            return proposalID;
        }

        @Override
        public String toString() {
            return "CompletedTransaction{" +
                    "proposalID=" + proposalID +
                    ", transaction=" + transaction +
                    ", isConfirmedBroadcastSuccessfully=" + isConfirmedBroadcastSuccessfully +
                    ", lastCheckedConfirmed=" + lastCheckedConfirmed +
                    ", completedTime=" + completedTime +
                    ", pushCount=" + pushCount +
                    ", nParticipants=" + nParticipants +
                    '}';
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

        return x + ((long) (r.nextDouble() * (y - x)));
    }

    static {
        run();
    }

    public static void restore() throws IOException, ClassNotFoundException {
        PKSeedCounter = AdminServlet.readPKSeedCounter();

        FileInputStream fis = new FileInputStream(AdminServlet.RecentlyCompletedTransactionsPath);
        ObjectInputStream ois = new ObjectInputStream(fis);

        Map<Hash, CompletedTransaction> map = (Map<Hash, CompletedTransaction>) ois.readObject();
        for (CompletedTransaction completedTransaction : map.values()) {
            putRecentlyCompleted(completedTransaction);
        }

        ois.close();
    }

    public static Script newScript(byte[] bytes) throws ScriptException {
        return new Script(bytes);
    }

    public void addOfferToPending(Offer offer) throws Exception {
        //Finalize the inputs and outputs
        offer.requestedOutputs = Collections.unmodifiableList(offer.requestedOutputs);
        offer.offeredOutpoints = Collections.unmodifiableList(offer.offeredOutpoints);

        synchronized (pendingOffers) {
            if (pendingOffers.containsKey(offer.getOfferID())) {
                throw new Exception("Duplicate Offer ID");
            }

            pendingOffers.put(offer.getOfferID(), offer);
        }
    }

    public static double feePercentForRequest(HttpServletRequest request) throws Exception {

        if (DefaultFeePercent == 0) {
            return 0;
        } else {
            String seedString = AdminServlet.getRealIP(request);

            BigInteger seed = new BigInteger(Util.SHA256(seedString + "----" + (long) (System.currentTimeMillis() / 86400000)).getBytes());

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
                            Logger.log(Logger.SeveritySeriousError, e);
                        }

                        cleanExpiredProposals();

                        cleanExpiredOffers();

                        cleanRecentlyCompletedProposals();
                    }
                });
            }
        }, 500, 500);

        timer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                multiThreadExec.execute(new Runnable() {
                    @Override
                    public void run() {
                        checkIfProposalsAreBroadcastSuccessfully();
                    }
                });
            }
        }, 1000, 1000);

    }

    private static void removeRecentlyCompletedAndChildren(CompletedTransaction completedTransaction) {
        List<CompletedTransaction> children = findCompletedTransactionsSpendingTransactionHash(new Hash(completedTransaction.getTransaction().getHash().getBytes()));

        for (CompletedTransaction child : children) {
            removeRecentlyCompletedAndChildren(child);
        }

        removeRecentlyCompleted(completedTransaction);
    }

    public static void checkIfProposalsAreBroadcastSuccessfully() {

        final List<CompletedTransaction> completedTransactions = new ArrayList<>(recentlyCompletedTransactions.values());

        for (CompletedTransaction completedTransaction : completedTransactions) {
            long now = System.currentTimeMillis();

            long completedTime = completedTransaction.getCompletedTime();

            long age = 0;
            if (completedTime > 0) {
                age = now - completedTime;
            }

            //Wait until a transaction is at least a few seconds old before checking
            if (age < 30000) {
                continue;
            }

            if (!completedTransaction.isConfirmed && completedTransaction.lastCheckedConfirmed < now - 30000) {
                completedTransaction.lastCheckedConfirmed = now;

                boolean didAlreadyFail = !completedTransaction.isConfirmedBroadcastSuccessfully;

                try {
                    MyTransaction transaction = MyRemoteWallet.getTransactionByHash(new Hash(completedTransaction.transaction.getHash().getBytes()), false);

                    if (transaction == null) {
                        throw new Exception("Null Transaction");
                    }

                    completedTransaction.isDoubleSpend = transaction.isDouble_spend();

                    completedTransaction.isConfirmedBroadcastSuccessfully = true;

                    completedTransaction.isConfirmed = transaction.getHeight() > 0;

                    continue;
                } catch (Exception e) {
                    completedTransaction.isConfirmedBroadcastSuccessfully = false;
                }

                if (!didAlreadyFail)
                    continue;

                Logger.log(Logger.SeveritySeriousError, "Transaction Not Found " + completedTransaction.getTransaction().getHash() + ". Proposal Age " + age + "ms completedTransaction.getPushCount() " + completedTransaction.getPushCount());

                if (age > ProposalExpiryTimeFailedToBroadcast) {
                    removeRecentlyCompletedAndChildren(completedTransaction);
                } else if (completedTransaction.getPushCount() < 5) {
                    try {
                        completedTransaction.pushTransaction();
                    } catch (Exception e) {
                        Logger.log(Logger.SeveritySeriousError, e);
                    }
                }
            }
        }
    }

    public static void cleanExpiredProposals() {
        long now = System.currentTimeMillis();


        final List<Proposal> proposals = new ArrayList<>(activeProposals.values());

        for (Proposal proposal : proposals) {
            if (proposal.getCreatedTime() > 0
                    && ((proposal.getNSigned() < proposal.getNSignaturesNeeded() && proposal.getCreatedTime() < now - ProposalExpiryTimeUnsigned)
                    || (proposal.getNSigned() == proposal.getNSignaturesNeeded() && proposal.getCreatedTime() < now - ProposalExpiryTimeSigned))) {

                Logger.log(Logger.SeverityINFO, "Clean Expired Proposal " + proposal);

                synchronized (proposal) {
                    DOSManager.failedToSignProposal(proposal);

                    activeProposals.remove(proposal.getProposalID());
                }
            }
        }
    }


    public static void cleanRecentlyCompletedProposals() {
        long now = System.currentTimeMillis();

        final List<CompletedTransaction> completedTransactions = new ArrayList<>(recentlyCompletedTransactions.values());

        for (CompletedTransaction completedTransaction : completedTransactions) {
            if (completedTransaction.getCompletedTime() > 0 && completedTransaction.getCompletedTime() < now - ProposalExpiryTimeAfterCompletion) {
                removeRecentlyCompleted(completedTransaction);
            }
        }
    }

    public static void cleanExpiredOffers() {
        long now = System.currentTimeMillis();

        final List<Offer> offers = new ArrayList<>(pendingOffers.values());

        for (Offer offer : offers) {
            if (offer.getReceivedTime() > 0 && offer.getReceivedTime() < now - OfferExpiryTime) {
                pendingOffers.remove(offer.getOfferID());
            }
        }
    }


    public static void createProposalsIfNeeded() throws Exception {
        long now = System.currentTimeMillis();

        final List<Offer> offers = new ArrayList<>(pendingOffers.values());


        for (Offer offer : offers) {
            //If the oldest offer has reached a certain age force creation
            if (offer.getReceivedTime() < now - offer.forceProposalMaxAge) {
                runCreateProposals();
                break;
            }
        }
    }


    public static boolean isTransactionCreatedByUs(Hash hash) {
        if (findCompletedTransaction(hash) != null)
            return true;

        final Sha256Hash _hash = new Sha256Hash(hash.getBytes());

        final List<Proposal> proposals = new ArrayList<>(activeProposals.values());

        for (Proposal proposal : proposals) {
            if (proposal.getTransaction() != null && proposal.getTransaction().getHash().equals(_hash)) {
                return true;
            }
        }

        return false;
    }


    public synchronized static void runCreateProposals() throws Exception {
        Proposal proposal = new Proposal();

        {
            int nInputs = 0;
            int nOutputs = 0;
            Set<String> allDestinationAddresses = new HashSet<>();

            //Set used to make sure no two offers are combined which contain inputs from the same transaction.
            Set<Hash> inputTransactionHashes = new HashSet<>();

            final List<Offer> offers = new ArrayList<>(pendingOffers.values());

            for (Offer offer : offers) {

                nInputs += offer.getOfferedOutpoints().size();
                nOutputs += offer.getRequestedOutputs().size();

                if (nInputs >= Proposal.getTargets().get("number_of_inputs_after_mix").longValue()) {
                    break;
                }

                if (nOutputs >= Proposal.getTargets().get("number_of_outputs_after_mix").longValue()) {
                    break;
                }

                if (proposal.getOffers().size() >= Proposal.getTargets().get("number_of_offers").longValue()) {
                    break;
                }

                //Encure All Output addresses are unique
                Set<String> thisOfferDestinationAddresses = offer.getRequestedOutputAddresses();
                if (!Collections.disjoint(allDestinationAddresses, offer.getRequestedOutputAddresses())) {
                    //All output addresses must be unique
                    //If there are any duplicates don't put them in the same proposal
                    continue;
                } else {
                    allDestinationAddresses.addAll(thisOfferDestinationAddresses);
                }

                Set<Hash> offerInputTransactionHashes = new HashSet<>();
                for (OutpointWithValue outpointWithValue : offer.getOfferedOutpoints()) {
                    offerInputTransactionHashes.add(outpointWithValue.getHash());
                }

                //Ensure all input transactions are unique
                if (!Collections.disjoint(inputTransactionHashes, offerInputTransactionHashes)) {
                    //All output addresses must be unique
                    //If there are any duplicates don't put them in the same proposal
                    continue;
                } else {
                    //If none are contained add them to the set
                    inputTransactionHashes.addAll(offerInputTransactionHashes);
                }

                boolean hasFailedToSign = DOSManager.hasHashedIPFailedToSign(offer.getHashedUserIP());

                if (!hasFailedToSign) {
                    if (!proposal.addOffer(offer)) {
                        throw new Exception("Error Adding Offer To Proposal");
                    }
                } else if (proposal.getOffers().size() == 0) {
                    //We only allow IPs that have failed to sign to join a proposal on their own
                    //That way it doesn't affect other users

                    if (!proposal.addOffer(offer)) {
                        throw new Exception("Error Adding Offer To Proposal");
                    }

                    break;
                } else {
                    continue;
                }
            }

            if (proposal.getOffers().size() == 0) {
                return;
            }

            if (activeProposals.containsKey(proposal.getProposalID()))
                throw new Exception("Duplicate Proposal ID");

            //Finalize the user offers
            proposal.offers = Collections.unmodifiableList(proposal.offers);

            Lock walletLock = OurWallet.getInstance().updateLock.readLock();

            walletLock.lock();
            try {
                final List<MyTransactionOutPoint> allUnspentPreFilter = OurWallet.getInstance().getUnspentOutputs(1000);

                Logger.log(Logger.SeverityINFO, "Put Active Proposal " + proposal.getProposalID());

                //Promote the proposal to active
                activeProposals.put(proposal.getProposalID(), proposal);

                //Remove the offer from pending
                pendingOffers.values().removeAll(proposal.getOffers());

                proposal.mixWithOurWallet(allUnspentPreFilter);

                if (proposal.getRequestedOutputCount() < MinNumberOfOutputs) {
                    throw new Exception("proposal.getRequestedOutputCount() ( " + proposal.getRequestedOutputCount() + ") < MinNumberOfOutputs (" + MinNumberOfOutputs + ")");
                }

                //TODO recover if these fail
                proposal.constructTransaction(allUnspentPreFilter);

                //Finalize our offers
                proposal.ourOffers = Collections.unmodifiableList(proposal.ourOffers);

            } catch (Exception e) {
                activeProposals.keySet().remove(proposal.getProposalID());

                pendingOffers.values().removeAll(proposal.getOffers());

                throw e;
            } finally {
                walletLock.unlock();
            }

            //Wake up the long pollers
            for (Offer offer : proposal.getOffers()) {
                synchronized (offer) {
                    offer.notifyAll();
                }
            }
        }
    }

    public static Address getRandomAddressNotInUse(List<MyTransactionOutPoint> allUnspent) throws Exception {
        int ii = 0;
        while (true) {
            String selectedAddress = OurWallet.getInstance().getRandomAddress();

            if ((!isAddressTargetOfAnActiveOutput(selectedAddress)
                    && findCompletedTransactionTargetingAddress(selectedAddress) == null)
                    || ii > 250) {

                for (MyTransactionOutPoint outPoint : allUnspent) {
                    final String address = outPoint.getAddress();
                    if (address != null && address.equals(selectedAddress))
                        continue;
                }

                return new Address(NetworkParameters.prodNet(), selectedAddress);
            }

            ++ii;
        }
    }


    public static long randomLong(long x, long y) {
        Random r = new Random();
        return x + ((long) (r.nextDouble() * (y - x)));
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
        private volatile Transaction transaction;
        private volatile boolean isFinalized = false;
        private volatile boolean isBroadcast = false;

        private AtomicBoolean isPushing = new AtomicBoolean();
        private ReadWriteLock finalizingLock = new ReentrantReadWriteLock();

        public static Map<String, Number> getTargets() {
            return (Map) Settings.instance().getMap("proposal_targets");
        }

        public Transaction getTransaction() {
            return transaction;
        }

        public Map<Integer, Script> getInput_scripts() {
            return input_scripts;
        }

        public Offer findOffer(long offerID) {
            for (Offer offer : offers) {
                if (offer.getOfferID() == offerID)
                    return offer;
            }

            return null;
        }

        public boolean sanityCheckBeforePush() throws Exception {

            final Transaction tx = getTransaction();

            if (tx == null) {
                throw new Exception("Sanity Check Failed. Tx Null");
            }

            long transactionFee = getTransactionFee();

            int nKB = (int) Math.ceil(tx.bitcoinSerialize().length / 1000d);

            boolean feeOk = transactionFee >= (nKB) * TransactionFeePer1000Bytes.longValue()
                    && transactionFee < (nKB + 4) * TransactionFeePer1000Bytes.longValue();

            if (!feeOk) {
                throw new Exception("Sanity Check Failed. Unexpected Network Fee " + transactionFee + " != " + nKB + " * " + TransactionFeePer1000Bytes);
            }

            if (nKB > MaximumHardTransactionSize) {
                throw new Exception("Sanity Check Failed. Transaction too large");
            }

            final Set<TransactionOutPoint> outpoints = new HashSet<>();

            for (TransactionInput input : tx.getInputs()) {
                if (!outpoints.add(input.getOutpoint()))
                    throw new Exception("Sanity Check Failed. Spent Same outpoint twice");
            }

            for (TransactionOutput output : tx.getOutputs()) {
                if (output.getValue().longValue() < MinimumNoneStandardOutputValue) {
                    throw new Exception("Sanity Check Failed. Transaction contains output smaller than none standard");
                }
            }

            final Map<Long, Long> offerIDToValueOutput = new HashMap<>();
            for (TransactionOutput output : tx.getOutputs()) {
                final String destinationAddress = output.getScriptPubKey().getToAddress(MainNetParams.get()).toString();

                if (OurWallet.getInstance().isOurAddress(output.getScriptPubKey().getToAddress(MainNetParams.get()).toString())) {
                    continue; //One of our addresses, looks good
                }

                boolean found = false;
                for (Offer offer : offers) {
                    for (Output requestedOutput : offer.getRequestedOutputs()) {
                        if (requestedOutput.getAddress().toString().equals(destinationAddress)) {

                            //Multiple offers with same output address will confuse this
                            if (offerIDToValueOutput.containsKey(offer.getOfferID())) {
                                offerIDToValueOutput.put(offer.getOfferID(), offerIDToValueOutput.get(offer.getOfferID()) + output.getValue().longValue());
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
                final Long valueOutput = offerIDToValueOutput.get(offer.getOfferID());

                final long amountInput = offer.getValueOffered();

                if (amountInput < valueOutput) {
                    throw new Exception("Sanity Check Failed. Greater value being sent to offer than was input");
                }

                for (OutpointWithValue outpointWithValue : offer.getOfferedOutpoints()) {
                    final CompletedTransaction completedTransaction = findCompletedTransactionOutputWasSpentIn(outpointWithValue.getHash(), outpointWithValue.getIndex());

                    if (completedTransaction != null) {
                        //Help Debug
                        Logger.printLogStack();

                        throw new Exception("Sanity Check Failed. User Offer Outpoint already Spent in Completed Transaction OutPoint: " + outpointWithValue + " Completed Transaction: " + completedTransaction + " (Current Time: " + System.currentTimeMillis() + ")");
                    }

                    final Offer conflictingOffer = findOfferConsumingOutpoint(outpointWithValue.getHash(), outpointWithValue.getIndex());
                    if (conflictingOffer != null && !conflictingOffer.equals(offer)) {
                        throw new Exception("Sanity Check Failed. User Offer Outpoint already Spent in Conflicting Offer " + conflictingOffer);
                    }
                }
            }

            for (Offer offer : ourOffers) {
                for (OutpointWithValue outpointWithValue : offer.getOfferedOutpoints()) {
                    final CompletedTransaction completedTransaction = findCompletedTransactionOutputWasSpentIn(outpointWithValue.getHash(), outpointWithValue.getIndex());


                    if (completedTransaction != null) {
                        Logger.log(Logger.SeverityINFO, tx);

                        //Help Debug
                        Logger.printLogStack();

                        throw new Exception("Sanity Check Failed. Our Offer Outpoint already Spent in Completed Transaction " + outpointWithValue + " Completed Transaction: " + completedTransaction + " (Current Time: " + System.currentTimeMillis() + ")");
                    }

                    final Offer conflictingOffer = findOfferConsumingOutpoint(outpointWithValue.getHash(), outpointWithValue.getIndex());
                    if (conflictingOffer != null && !conflictingOffer.equals(offer)) {
                        throw new Exception("Sanity Check Failed. Our Offer Outpoint already Spent in Conflicting Offer " + conflictingOffer);
                    }
                }
            }

            return true;
        }

        ;


        public boolean pushTransaction() throws Exception {
            if (isPushing.compareAndSet(false, true)) {
                try {
                    CompletedTransaction completedTransaction;

                    if (!isFinalized) {
                        throw new Exception("Cannot push transaction, not finalized");
                    }

                    final Transaction tx = getTransaction();

                    if (tx == null) {
                        throw new Exception("pushTransaction() tx null");
                    }

                    if (findCompletedTransaction(new Hash(tx.getHash().getBytes())) != null) {
                        throw new Exception("Proposal Already Pushed");
                    }

                    if (!sanityCheckBeforePush()) {
                        Logger.log(Logger.SeverityINFO, "!sanityCheckBeforePush() Remove Active Proposal " + getProposalID());

                        activeProposals.remove(getProposalID());

                        throw new Exception("Sanity Check Returned False");
                    }

                    completedTransaction = new CompletedTransaction();

                    completedTransaction.isConfirmedBroadcastSuccessfully = false;
                    completedTransaction.transaction = tx;
                    completedTransaction.completedTime = System.currentTimeMillis();
                    completedTransaction.pushCount = 0;
                    completedTransaction.lastCheckedConfirmed = 0;
                    completedTransaction.proposalID = getProposalID();
                    completedTransaction.nParticipants = getOffers().size();
                    completedTransaction.fee = getTransactionFee();

                    Logger.log(Logger.SeverityINFO, "pushTransaction() Remove Active Proposal " + getProposalID());

                    putRecentlyCompleted(completedTransaction);

                    multiThreadExec.submit(new Runnable() {
                        @Override
                        public void run() {
                            saveRecentlyCompleted();
                        }
                    });

                    activeProposals.remove(getProposalID());

                    boolean pushed = completedTransaction.pushTransaction();

                    isBroadcast = pushed;

                    synchronized (this) {
                        this.notifyAll();
                    }

                    return pushed;
                } finally {
                    isPushing.set(false);
                }
            }

            return false;
        }

        public void finalizeTransaction() throws Exception {
            Lock writeLock = finalizingLock.writeLock();

            writeLock.lock();
            try {
                if (isFinalized) {
                    return;
                }

                try {
                    if (getNSigned() < getNSignaturesNeeded()) {
                        throw new Exception("Cannot finalize transaction as not all inputs are signed");
                    }

                    int ii = 0;
                    for (TransactionInput input : transaction.getInputs()) {
                        Script inputScript = input_scripts.get(ii);

                        if (inputScript != null) {
                            input.setScriptSig(inputScript);
                        }

                        ++ii;
                    }

                    KeyChainGroup wallet = new KeyChainGroup(NetworkParameters.prodNet());

                    //Sign our inputs
                    try {
                        Lock lock = OurWallet.getInstance().updateLock.readLock();

                        lock.lock();
                        try {
                            MyWallet myWallet = OurWallet.getInstance().getWalletNoLock();

                            for (TransactionInput input : transaction.getInputs()) {
                                if (input.getScriptBytes() == null || input.getScriptBytes().length == 0) {
                                    if (input.getOutpoint() == null) {
                                        throw new Exception("Input hash null outpoint " + input + " " + transaction);
                                    }

                                    Script scriptPubKey = input.getConnectedOutput().getScriptPubKey();

                                    if (scriptPubKey == null) {
                                        throw new Exception("scriptPubKey is null");
                                    }

                                    String address = input.getOutpoint().getConnectedOutput().getScriptPubKey().getToAddress(MainNetParams.get()).toString();

                                    ECKey key = myWallet.getECKey(address);
                                    if (key == null) {
                                        throw new Exception("Unable to find ECKey for scriptPubKey " + scriptPubKey);
                                    }

                                    input.setScriptSig(scriptPubKey.createEmptyInputScript(key, null));

                                    wallet.importKeys(key);
                                }
                            }
                        } finally {
                            lock.unlock();
                        }

                        TransactionSigner.ProposedTransaction proposal = new TransactionSigner.ProposedTransaction(transaction);

                        LocalTransactionSigner signer = new LocalTransactionSigner();

                        if (!signer.signInputs(proposal, wallet))
                            throw new Exception("signInputs() returned false for the tx " + signer.getClass().getName());
                    } catch (Exception e) {
                        Logger.log(Logger.SeveritySeriousError, e);

                        throw new Exception("Error signing our inputs");
                    }


                    isFinalized = true;
                } catch (Exception e) {
                    isFinalized = false;
                    throw e;
                }
            } finally {
                writeLock.unlock();
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

            final Transaction tx = getTransaction();

            if (tx == null) {
                return requests;
            }

            int ii = 0;
            for (TransactionInput input : tx.getInputs()) {
                Hash hash = new Hash(input.getOutpoint().getHash().getBytes());
                int index = (int) input.getOutpoint().getIndex();

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

            final Transaction tx = getTransaction();

            if (tx == null)
                return null;

            List<OutpointWithValue> outpoints = new ArrayList<>();

            for (TransactionInput input : tx.getInputs()) {
                OutpointWithValue outpoint = new OutpointWithValue();

                outpoint.value = input.getOutpoint().getConnectedOutput().getValue().longValue();
                outpoint.script = input.getOutpoint().getConnectedPubKeyScript();
                outpoint.index = (int) input.getOutpoint().getIndex();
                outpoint.hash = new Hash(input.getOutpoint().getHash().getBytes());

                outpoints.add(outpoint);
            }

            return outpoints;
        }

        public List<Output> getTransactionOutputs() throws Exception {

            final Transaction tx = getTransaction();

            if (tx == null)
                return null;

            List<Output> outputs = new ArrayList<>();

            for (TransactionOutput _output : tx.getOutputs()) {
                Output output = new Output();

                output.value = _output.getValue().longValue();
                output.script = _output.getScriptBytes();

                outputs.add(output);
            }

            return outputs;
        }

        public long getTransactionFee() {

            final Transaction tx = getTransaction();

            if (tx == null)
                return 0;

            long totalValueOutput = 0;
            for (TransactionOutput output : tx.getOutputs()) {
                totalValueOutput += output.getValue().longValue();
            }

            long totalValueInput = 0;
            for (TransactionInput input : tx.getInputs()) {
                totalValueInput += input.getOutpoint().getConnectedOutput().getValue().longValue();
            }

            return totalValueInput - totalValueOutput;
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

        private static MyTransactionOutPoint closestUnspentToValueNotInList(long value, List<MyTransactionOutPoint> unspent, Set<String> alreadySelected, boolean allowUnconfirmed) {

            long closestDifference = Long.MAX_VALUE;
            MyTransactionOutPoint output = null;

            for (MyTransactionOutPoint unspentOutPoint : unspent) {

                //Allow unconfirmed outpoints only when specified
                if (allowUnconfirmed == false && unspentOutPoint.getConfirmations() == 0) {
                    continue;
                }

                long outPointValue = unspentOutPoint.getValue().longValue();

                //Ignore very small unconfirmed
                if (unspentOutPoint.getConfirmations() == 0 && outPointValue < MinimumNoneStandardOutputValue) {
                    continue;
                }

                long difference = value - outPointValue;

                if (difference < 0) {
                    difference = -difference;
                }

                if (difference < closestDifference) {
                    boolean alreadyExists = alreadySelected.contains(unspentOutPoint.toString());

                    if (!alreadyExists) {
                        closestDifference = difference;
                        output = unspentOutPoint;
                    }
                }
            }

            return output;
        }

        private int scaleForInputValue(long value) {
            int nDecimals = numberOfDecimalPlaces(value / (double) COIN);

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
            for (int i = 0; i < n; i++) {
                long rand = random.nextInt((int) upperbound) + offset;
                if (cursum + rand > sum || i == n - 1) {
                    rand = sum - cursum;
                }
                cursum += rand;
                nums[i] = rand;
                if (cursum == sum) {
                    break;
                }
            }
            return nums;
        }

        private boolean addInputsForValue(final List<MyTransactionOutPoint> unspent, final Offer offer, final long totalValueNeeded) throws Exception {

            //Pick the unspent outputs we will use
            long totalSelected = 0;
            List<MyTransactionOutPoint> selectedBeans = new ArrayList<>();

            for (int ii = 0; ii < 2; ++ii) {
                Set<String> alreadyTested = new HashSet<>();

                boolean allowUnconfirmed = false;

                if (ii == 1) {
                    allowUnconfirmed = true;
                }

                while (true) {
                    final MyTransactionOutPoint outpoint = closestUnspentToValueNotInList(totalValueNeeded - totalSelected, unspent, alreadyTested, allowUnconfirmed);

                    if (outpoint == null) {
                        //Logger.log(Logger.SeverityWARN, "Null outpoint unspent size " + unspent.size());
                        break;
                    }

                    alreadyTested.add(outpoint.toString());

                    final Hash hash = new Hash(outpoint.getTxHash().getBytes());

                    if (selectedBeans.contains(outpoint)
                            || findCompletedTransactionOutputWasSpentIn(hash, outpoint.getTxOutputN()) != null
                            || isOutpointInUse(hash, outpoint.getTxOutputN())
                            || offer.spendsOutpoint(hash, outpoint.getTxOutputN())) {
                        continue;
                    }

                    //If the fee is less than expected don't spend the outputs
                    final CompletedTransaction createdIn = findCompletedTransaction(new Hash(outpoint.getTxHash().getBytes()));
                    if (createdIn != null && !createdIn.isOkToSpend()) {
                        continue;
                    }

                    final long maxChange = allowUnconfirmed ? MaxChangeSingleUnconfirmedInput : MaxChangeSingleConfirmedInput;

                    if ((totalSelected + outpoint.getValue().longValue()) - totalValueNeeded > maxChange) {
                        continue;
                    }

                    selectedBeans.add(outpoint);

                    if (selectedBeans.size() > Proposal.getTargets().get("number_of_inputs_after_mix").longValue() && !allowUnconfirmed) {
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
                    final OutpointWithValue outpoint = new OutpointWithValue();

                    outpoint.script = myOutpoint.getScriptBytes();

                    if (outpoint.script == null) {
                        throw new Exception("Null output script");
                    }

                    outpoint.hash = new Hash(myOutpoint.getTxHash().getBytes());
                    outpoint.index = myOutpoint.getTxOutputN();
                    outpoint.value = myOutpoint.getValue().longValue();

                    if (!offer.addOfferedOutpoint(outpoint)) {
                        return false;
                    }

                    if (offer.getOfferedOutpoints().size() > MaxNumberOfInputs) {
                        System.out.println("offer.getOfferedOutpoints().size() > MaxNumberOfInputs");
                        return false;
                    }
                }
            }

            return true;
        }

        private boolean addOutputsWhichMimicsOffer(List<MyTransactionOutPoint> unspent, final Offer offer) throws Exception {

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

            final List<Long> splits = new ArrayList<>();

            long average = feePayingOutputValue / nSplits;

            long maxVariance = (long) ((average / 100d) * (double) VarianceWhenMimicingOutputValue);

            if (nSplits == 1) {
                long variance = (long) ((average / 100d) * (VarianceWhenMimicingOutputValue * Math.random()));

                long remainderRounded = BigDecimal.valueOf(feePayingOutputValue + variance).divide(BigDecimal.valueOf(COIN)).setScale(scaleForInputValue(noneFeePayingOutputValue), BigDecimal.ROUND_HALF_UP).multiply(BigDecimal.valueOf(COIN)).longValue();

                remainderRounded = Math.max(MinimumOutputValue, remainderRounded);

                splits.add(remainderRounded);
            } else {
                while (true) {
                    final long[] vSplits = genNumbers(feePayingOutputValue, nSplits);

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
                final long remainder = offerTotalValueOutput - splits.get(0);

                long remainderRounded = BigDecimal.valueOf(remainder).divide(BigDecimal.valueOf(COIN)).setScale(scaleForInputValue(noneFeePayingOutputValue), BigDecimal.ROUND_HALF_UP).multiply(BigDecimal.valueOf(COIN)).longValue();

                remainderRounded = Math.max(MinimumOutputChangeSplitValue, remainderRounded);

                splits.add(remainderRounded);
            }

            final Offer newOffer = new Offer();

            long totalValueNeeded = 0;

            newOffer.feePercent = 0;

            for (Long splitValue : splits) {
                final Output outOne = new Output();

                outOne.excludeFromFee = false;
                outOne.script = ScriptBuilder.createOutputScript(getRandomAddressNotInUse(unspent)).getProgram();
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
                        final Output outOne = new Output();

                        outOne.excludeFromFee = false;
                        outOne.script = ScriptBuilder.createOutputScript(getRandomAddressNotInUse(unspent)).getProgram();
                        outOne.value = splitValue;

                        newOffer.addRequestedOutput(outOne);
                    }

                    remainder -= totalValueNeeded;

                    ++ii;
                }
            }

            Logger.log(Logger.SeverityINFO, "addOutputsWhichMimicsOffer() Add Our Offer " + newOffer + " activeProposals " + activeProposals.keySet());

            if (!addOurOffer(newOffer)) {
                Logger.log(Logger.SeverityWARN, "Error Adding Our Offer");
                return false;
            }

            return true;
        }

        public long getRequestedOutputCount() {
            long count = 0;
            for (final Offer offer : offers) {
                count += offer.getRequestedOutputs().size();
            }

            for (final Offer offer : ourOffers) {
                count += offer.getRequestedOutputs().size();
            }

            return count;
        }

        public long getOfferedInputCount() {
            long count = 0;
            for (final Offer offer : offers) {
                count += offer.getOfferedOutpoints().size();
            }

            for (final Offer offer : ourOffers) {
                count += offer.getOfferedOutpoints().size();
            }

            return count;
        }

        public synchronized void mixWithOurWallet(List<MyTransactionOutPoint> allUnspentPreFilter) throws Exception {

            final List<MyTransactionOutPoint> allUnspent = new ArrayList<>();

            //Remove any unspent outpoints from transactions which user offers used
            int verySmallNoneStandardCount = 0;
            for (MyTransactionOutPoint outPoint : allUnspentPreFilter) {
                final Hash hash = new Hash(outPoint.getHash().getBytes());

                boolean suitableToUse = true;
                for (Offer offer : offers) {
                    for (OutpointWithValue outpointWithValue : offer.getOfferedOutpoints()) {
                        if (hash.equals(outpointWithValue.getHash())) {
                            suitableToUse = false;
                            break;
                        }
                    }
                }

                if (outPoint.getValue().longValue() < MinimumNoneStandardOutputValue) {
                    ++verySmallNoneStandardCount;

                    if (verySmallNoneStandardCount > 5) {
                        suitableToUse = false;
                    }
                }

                if (suitableToUse) {
                    allUnspent.add(outPoint);
                }
            }

            int allFailedCount = 0;
            while (allFailedCount < 10) {
                boolean allFailed = true;
                boolean fullBreak = false;
                for (Offer offer : offers) {
                    final List<MyTransactionOutPoint> unspent = new ArrayList<>(allUnspent);

                    try {
                        if (addOutputsWhichMimicsOffer(unspent, offer)) {
                            allFailed = false;
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }

                    if (getRequestedOutputCount() >= Proposal.getTargets().get("number_of_outputs_after_mix").longValue()
                            || getOfferedInputCount() >= Proposal.getTargets().get("number_of_inputs_after_mix").longValue()) {
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
        }

        public List<MyTransactionOutPoint> findSuitableOutpoints(List<MyTransactionOutPoint> allUnspent, long totalTargetValue, int maxN) {
            for (int ii = maxN; ii > 0; --ii) {
                long splitValue = totalTargetValue / ii;

                //So we add a new input to pay the fee
                final List<MyTransactionOutPoint> suitableOutPoints = new ArrayList<>();

                long valueSelected = 0;

                final Set<String> tested = new HashSet<>();

                while (true) {
                    MyTransactionOutPoint outpoint = closestUnspentToValueNotInList(splitValue, allUnspent, tested, true);

                    if (outpoint == null) {
                        break;
                    }

                    tested.add(outpoint.toString());

                    if (outpoint.getValue().longValue() < splitValue) {
                        continue;
                    }

                    final Hash hash = new Hash(outpoint.getTxHash().getBytes());

                    //Make sure it is not in use
                    if (findCompletedTransactionOutputWasSpentIn(hash, outpoint.getTxOutputN()) != null || isOutpointInUse(hash, outpoint.getTxOutputN())) {
                        continue;
                    }

                    //Make sure the parent transactions are ok to spend
                    CompletedTransaction createdIn = findCompletedTransaction(new Hash(outpoint.getTxHash().getBytes()));
                    if (createdIn != null && !createdIn.isOkToSpend()) {
                        continue;
                    }

                    suitableOutPoints.add(outpoint);

                    valueSelected += outpoint.getValue().longValue();

                    if (suitableOutPoints.size() < ii) {
                        continue;
                    }

                    if (suitableOutPoints.size() > ii) {
                        break;
                    }

                    if (valueSelected < totalTargetValue) {
                        continue;
                    }

                    //Check the outpoint value is not much larger than target so would leave a lot of change
                    if (valueSelected - totalTargetValue > MaxChangeSingleConfirmedInput) {
                        Logger.log(Logger.SeverityINFO, "findSuitableOutpoints() valueSelected - totalTargetValue > MaxChangeSingleConfirmedInput");
                        break;
                    }

                    return suitableOutPoints;
                }
            }

            return null;
        }

        public synchronized void constructTransaction(List<MyTransactionOutPoint> allUnspent) throws Exception {

            final Transaction transaction = new Transaction(NetworkParameters.prodNet());

            try {
                constructingTransactions.put(getProposalID(), transaction);

                final List<Output> allRequestedOutputs = new ArrayList<>();
                final List<OutpointWithValue> allOfferedOutpoints = new ArrayList<>();

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
                    TransactionOutput out = new TransactionOutput(NetworkParameters.prodNet(), transaction, Coin.valueOf(outputRequest.value), outputRequest.script);

                    synchronized (transaction) {
                        transaction.addOutput(out);
                    }
                }

                for (OutpointWithValue outpoint : allOfferedOutpoints) {
                    TransactionOutPoint outPoint = new MyTransactionOutPointWrapper(outpoint);

                    TransactionInput input = new TransactionInput(NetworkParameters.prodNet(), null, new byte[0], outPoint);

                    synchronized (transaction) {
                        transaction.addInput(input);
                    }
                }


                BigInteger totalValueOutput = BigInteger.ZERO;
                for (TransactionOutput output : transaction.getOutputs()) {
                    totalValueOutput = totalValueOutput.add(BigInteger.valueOf(output.getValue().longValue()));
                }

                BigInteger totalValueInput = BigInteger.ZERO;
                for (TransactionInput input : transaction.getInputs()) {
                    totalValueInput = totalValueInput.add(BigInteger.valueOf(input.getOutpoint().getConnectedOutput().getValue().longValue()));
                }

                if (totalValueInput.compareTo(totalValueOutput) < 0) {
                    throw new Exception("totalValueInput < totalValueOutput");
                }

                BigInteger change = totalValueInput.subtract(totalValueOutput);

                BigInteger feedPaid = BigInteger.ZERO;

                //Check fee
                int nKB = (int) Math.ceil((transaction.bitcoinSerialize().length + (transaction.getInputs().size() * scriptSigSize)) / 1000d);

                BigInteger extraFeeNeeded = BigInteger.valueOf(nKB).multiply(TransactionFeePer1000Bytes).subtract(feedPaid);
                if (extraFeeNeeded.compareTo(BigInteger.ZERO) > 0) {
                    change = change.subtract(extraFeeNeeded);
                    feedPaid = feedPaid.add(extraFeeNeeded);
                }

                final List<Offer> allOffers = new ArrayList<>(this.offers);

                allOffers.addAll(this.ourOffers);

                final LinkedHashSet<Long> potentialDifferenceValues = new LinkedHashSet<>();

                int max = 0;
                for (Offer offer : allOffers) {
                    max = Math.max(max, offer.getRequestedOutputs().size());
                }

                //Build a list of output values which force offers to SUM to the same value in many combinations
                //e.g. if offer 1 has a value of 5 BTC and offer 2 has a value of 6 BTC we add a 1 BTC random output
                for (int skipLastN = 0; skipLastN < max; ++skipLastN) {
                    for (Offer firstOffer : allOffers) {
                        final long firstOfferTotalOutputValue = firstOffer.getValueOutputRequested();

                        for (Offer secondOffer : allOffers) {
                            //Skip ourselves
                            if (secondOffer.getOfferID() == firstOffer.getOfferID()) {
                                continue;
                            }

                            long secondOfferOutputValue = 0;

                            final List<Output> outputs = secondOffer.getRequestedOutputs();
                            for (int ii = 0; ii < outputs.size() - skipLastN; ++ii) {
                                secondOfferOutputValue += outputs.get(ii).value;
                            }

                            if (secondOfferOutputValue == 0) {
                                continue;
                            }

                            final long difference = Math.abs(firstOfferTotalOutputValue - secondOfferOutputValue);

                            //Ignore the difference if it is less that the standard output size
                            if (difference <= MinimumNoneStandardOutputValue) {
                                continue;
                            }

                            if (!potentialDifferenceValues.contains(difference)) {
                                potentialDifferenceValues.add(difference);
                            }
                        }
                    }
                }

                final long targetNumberOfInputs = Proposal.getTargets().get("number_of_inputs_after_construction").longValue();
                final long targetNumberOfOutputs = Proposal.getTargets().get("number_of_outputs_after_construction").longValue();

                //Add new outputs using the value difference between offers
                for (long difference : potentialDifferenceValues) {
                    Logger.log(Logger.SeverityINFO, "constructTransaction()  difference phase difference " + difference);

                    if (transaction.getInputs().size() >= targetNumberOfInputs) {
                        Logger.log(Logger.SeverityINFO, "constructTransaction()  transaction.getInputs().size() >= number_of_inputs_after_construction breaking here");
                        break;
                    }

                    if (transaction.getOutputs().size() >= targetNumberOfOutputs) {
                        Logger.log(Logger.SeverityINFO, "constructTransaction()  transaction.getOutputs().size() >= number_of_outputs_after_construction breaking here");
                        break;
                    }

                    if (nKB >= MaximumSoftTransactionSize) {
                        break;
                    }

                    final BigInteger differenceBN = BigInteger.valueOf(difference);

                    Logger.log(Logger.SeverityINFO, "constructTransaction()  difference phase change.subtract(BigInteger.valueOf(MinimumOutputValue)) " + change.subtract(BigInteger.valueOf(MinimumOutputValue)));

                    //If we don't have enough change select a new input to pay for it
                    if (change.longValue() <= difference) {
                        final BigInteger valueNeeded = differenceBN.subtract(change);

                        int numberOfInputs = transaction.getInputs().size();
                        int numberOfOutputs = transaction.getInputs().size();

                        //maxN is the maximum number of inputs to select
                        //We do this to combine inputs so the wallet doesn't always become fragmented
                        int maxN = 1;
                        if (numberOfInputs < targetNumberOfInputs - 3
                                && numberOfInputs < numberOfOutputs + 3
                                && OurWallet.getInstance().walletIsFragmented()) {
                            maxN = 2;
                        }

                        final List<MyTransactionOutPoint> suitableOutPoints = findSuitableOutpoints(allUnspent, valueNeeded.longValue(), maxN);

                        Logger.log(Logger.SeverityINFO, "constructTransaction()  difference phase suitableOutPoints " + suitableOutPoints + " valueNeeded " + valueNeeded);

                        if (suitableOutPoints == null) {
                            continue;
                        }

                        BigInteger totalSuitableValue = BigInteger.ZERO;
                        for (MyTransactionOutPoint suitableOutPoint : suitableOutPoints) {
                            totalSuitableValue = totalSuitableValue.add(BigInteger.valueOf(suitableOutPoint.getValue().longValue()));
                        }

                        //Make sure the difference is less than the change value (i.e. we have enough change to spend)
                        if (change.add(totalSuitableValue).compareTo(differenceBN) < 0) {
                            Logger.log(Logger.SeverityINFO, "constructTransaction() difference phase still not suitable change");
                            continue;
                        }

                        for (MyTransactionOutPoint suitableOutPoint : suitableOutPoints) {
                            TransactionInput input = new TransactionInput(NetworkParameters.prodNet(), null, new byte[0], suitableOutPoint);

                            synchronized (transaction) {
                                transaction.addInput(input);
                            }

                            change = change.add(BigInteger.valueOf(suitableOutPoint.getValue().longValue()));
                        }
                    }

                    Logger.log(Logger.SeverityINFO, "constructTransaction() Adding difference output " + differenceBN);

                    //If it is add an output with the difference value
                    synchronized (transaction) {
                        transaction.addOutput(Coin.valueOf(differenceBN.longValue()), getRandomAddressNotInUse(allUnspent));
                    }
                    change = change.subtract(differenceBN);

                    //Check fee
                    nKB = (int) Math.ceil((transaction.bitcoinSerialize().length + (transaction.getInputs().size() * scriptSigSize)) / 1000d);
                    extraFeeNeeded = BigInteger.valueOf(nKB).multiply(TransactionFeePer1000Bytes).subtract(feedPaid);

                    if (extraFeeNeeded.compareTo(BigInteger.ZERO) > 0) {
                        change = change.subtract(extraFeeNeeded);
                        feedPaid = feedPaid.add(extraFeeNeeded);
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
                            if (!output.isExcludeFromFee() && output.value <= change.longValue() - MinimumNoneStandardOutputValue) {
                                double rand = (Math.random() - 0.5) * 2; //-1 to 1

                                long randomVariance = (long) ((output.getValue() / 100d) * (VarianceWhenMimicingOutputValue * rand));

                                BigInteger rounded = BigDecimal.valueOf(output.value + randomVariance).divide(BigDecimal.valueOf(COIN)).setScale(scaleForInputValue(output.getValue()), BigDecimal.ROUND_HALF_UP).multiply(BigDecimal.valueOf(COIN)).toBigInteger();

                                if (rounded.compareTo(change.subtract(BigInteger.valueOf(MinimumOutputValue))) <= 0 && rounded.compareTo(BigInteger.valueOf(MinimumNoneStandardOutputValue)) > 0) {

                                    synchronized (transaction) {
                                        transaction.addOutput(Coin.valueOf(rounded.longValue()), getRandomAddressNotInUse(allUnspent));
                                    }
                                    change = change.subtract(rounded);

                                    //Check fee
                                    nKB = (int) Math.ceil((transaction.bitcoinSerialize().length + (transaction.getInputs().size() * scriptSigSize)) / 1000d);
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
                nKB = (int) Math.ceil((transaction.bitcoinSerialize().length + (transaction.getInputs().size() * scriptSigSize)) / 1000d);
                extraFeeNeeded = BigInteger.valueOf(nKB).multiply(TransactionFeePer1000Bytes).subtract(feedPaid);

                if (extraFeeNeeded.compareTo(BigInteger.ZERO) > 0) {
                    change = change.subtract(extraFeeNeeded);
                    feedPaid = feedPaid.add(extraFeeNeeded);
                }

                if (change.compareTo(BigInteger.ZERO) > 0) {
                    //Check fee
                    nKB = (int) Math.ceil((transaction.bitcoinSerialize().length + ((transaction.getInputs().size() + 1) * scriptSigSize)) / 1000d);
                    extraFeeNeeded = BigInteger.valueOf(nKB).multiply(TransactionFeePer1000Bytes).subtract(feedPaid);

                    change = change.subtract(extraFeeNeeded);
                    feedPaid = feedPaid.add(extraFeeNeeded);
                }

                if (change.compareTo(BigInteger.valueOf(MinimumNoneStandardOutputValue)) > 0) {
                    synchronized (transaction) {
                        transaction.addOutput(Coin.valueOf(change.longValue()), getRandomAddressNotInUse(allUnspent));
                    }
                }

                {
                    //Final fee check
                    nKB = (int) Math.ceil((transaction.bitcoinSerialize().length + ((transaction.getInputs().size() + 1) * scriptSigSize)) / 1000d);
                    extraFeeNeeded = BigInteger.valueOf(nKB).multiply(TransactionFeePer1000Bytes).subtract(feedPaid);

                    if (extraFeeNeeded.compareTo(BigInteger.ZERO) > 0) {
                        Logger.log(Logger.SeverityINFO, "Proposal " + getProposalID() + " extraFeeNeeded + (" + extraFeeNeeded + ") > 0");

                        //So we add a new input to pay the fee
                        List<MyTransactionOutPoint> suitableOutPoints = findSuitableOutpoints(allUnspent, extraFeeNeeded.longValue(), 1);

                        if (suitableOutPoints != null) {
                            final MyTransactionOutPoint suitableOutPoint = suitableOutPoints.get(0);

                            long changeOutpoint = suitableOutPoint.getValue().longValue() - extraFeeNeeded.longValue();

                            //If the change is less than MinimumNoneStandardOutputValue just leave it as miners fee
                            if (changeOutpoint > MinimumNoneStandardOutputValue) {
                                TransactionOutput out = new TransactionOutput(NetworkParameters.prodNet(), transaction, Coin.valueOf(changeOutpoint), ScriptBuilder.createOutputScript(getRandomAddressNotInUse(allUnspent)).getProgram());

                                synchronized (transaction) {
                                    transaction.addOutput(out);
                                }
                            }

                            //Add the input
                            TransactionInput input = new TransactionInput(NetworkParameters.prodNet(), null, new byte[0], suitableOutPoint);

                            synchronized (transaction) {
                                transaction.addInput(input);
                            }
                        }
                    }
                }

                Collections.shuffle(transaction.getInputs());

                Collections.shuffle(transaction.getOutputs());

                transaction.unCache();

                this.transaction = transaction;

                this.notifyAll();
            } finally {
                constructingTransactions.keySet().remove(getProposalID());
            }
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

    public static CompletedTransaction findCompletedTransaction(Hash hash) {
        return recentlyCompletedTransactions.get(hash);
    }


    public static Offer findOffer(long offerID) {
        final Offer offer = pendingOffers.get(offerID);

        if (offer != null)
            return offer;

        final List<Proposal> proposals = new ArrayList<>(activeProposals.values());

        for (Proposal proposal : proposals) {
            for (Offer _offer : proposal.getOffers()) {
                if (_offer.getOfferID() == offerID)
                    return _offer;
            }
        }

        return null;
    }

    //Returns true if the address is the target of a transaction we are creating now
    public static boolean isAddressTargetOfAnActiveOutput(String address) {
        return findActiveOfferTargetingAddress(address) != null ||
                findActiveProposalTargetingAddress(address) != null ||
                findConstructingTransactionTargetingAddress(address) != null;
    }

    //Returns true if the address is in use for spending
    public static boolean isAddressInUse(String address) throws ScriptException {
        return findOfferConsumingAddress(address) != null
                || findConstructingTransactionConsumingAddress(address) != null
                || findActiveProposalConsumingAddress(address) != null;
    }

    //Returns true if an Outpoint is being spent in a transaction we are creating now
    public static boolean isOutpointInUse(Hash hash, int index) {
        return findOfferConsumingOutpoint(hash, index) != null
                || findConstructingTransactionUsingOutpoint(hash, index) != null
                || findActiveProposalsUsingOutpoint(hash, index) != null;
    }

    public static Offer findActiveOfferTargetingAddress(String address) {
        final List<Offer> offers = new ArrayList<>(pendingOffers.values());

        for (Offer offer : offers) {
            for (Output output : offer.getRequestedOutputs())
                if (output.getAddress().toString().equals(address))
                    return offer;
        }

        return null;
    }

    public static Proposal findActiveProposalTargetingAddress(String address) {
        final List<Proposal> proposals = new ArrayList<>(activeProposals.values());

        for (Proposal proposal : proposals) {
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

    public static Offer findOfferConsumingAddress(String address) throws ScriptException {
        final List<Offer> offers = new ArrayList<>(pendingOffers.values());

        for (Offer offer : offers) {
            for (OutpointWithValue outpointWithValue : offer.getOfferedOutpoints())
                if (outpointWithValue.getAddress().equals(address))
                    return offer;
        }

        final List<Proposal> proposals = new ArrayList<>(activeProposals.values());

        for (Proposal proposal : proposals) {
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


    public static boolean doesTransactionUseOutpoint(final Transaction transaction, final Hash hash, final int index) {
        final List<TransactionInput> inputs = transaction.getInputs();

        final byte[] hashBytes = hash.getBytes();

        for (TransactionInput input : inputs) {
            final TransactionOutPoint outPoint = input.getOutpoint();

            if (outPoint.getIndex() == index && Arrays.equals(outPoint.getHash().getBytes(), hashBytes)) {
                return true;
            }
        }

        return false;
    }

    public static boolean doesTransactionSpendAddress(Transaction transaction, String address) throws ScriptException {
        final List<TransactionInput> inputs = transaction.getInputs();

        for (TransactionInput input : inputs) {
            try {
                TransactionOutPoint outPoint = input.getOutpoint();

                final Address fromAddress = newScript(outPoint.getConnectedPubKeyScript()).getToAddress(MainNetParams.get());

                if (fromAddress.toString().equals(address)) {
                    return true;
                }
            } catch (Exception e) {
                Logger.log(Logger.SeveritySeriousError, e);
                return false;
            }
        }

        return false;
    }


    public static Proposal findActiveProposalConsumingAddress(String address) throws ScriptException {
        for (final Proposal proposal : activeProposals.values()) {
            if (proposal.transaction != null) {
                if (doesTransactionSpendAddress(proposal.transaction, address))
                    return proposal;
            }
        }

        return null;
    }

    public static Transaction findCompletedTransactionConsumingAddress(String address, long maxAge) throws ScriptException {
        long now = System.currentTimeMillis();

        for (final CompletedTransaction completedTransaction : recentlyCompletedTransactions.values()) {
            if (completedTransaction.getCompletedTime() < now - maxAge) {
                continue;
            }

            final Transaction transaction = completedTransaction.getTransaction();

            synchronized (transaction) {
                if (doesTransactionSpendAddress(transaction, address))
                    return transaction;
            }
        }
        return null;
    }

    public static Transaction findConstructingTransactionConsumingAddress(String address) throws ScriptException {
        for (final Transaction transaction : constructingTransactions.values()) {
            synchronized (transaction) {
                if (doesTransactionSpendAddress(transaction, address))
                    return transaction;
            }
        }
        return null;
    }

    public static Transaction findConstructingTransactionUsingOutpoint(Hash hash, int index) {
        for (final Transaction transaction : constructingTransactions.values()) {
            synchronized (transaction) {
                if (doesTransactionUseOutpoint(transaction, hash, index))
                    return transaction;
            }
        }
        return null;
    }

    public static Transaction findConstructingTransactionTargetingAddress(String address) {
        for (final Transaction transaction : constructingTransactions.values()) {
            synchronized (transaction) {
                for (TransactionOutput output : transaction.getOutputs()) {
                    try {
                        Address toAddress = output.getScriptPubKey().getToAddress(MainNetParams.get());

                        if (toAddress.toString().equals(address))
                            return transaction;
                    } catch (Exception e) {
                        Logger.log(Logger.SeveritySeriousError, e);
                    }
                }
            }
        }
        return null;
    }

    public static CompletedTransaction findCompletedTransactionTargetingAddress(String address) {
        return _outputAddressToRecentlyCompletedCache.get(address);
    }

    public static Transaction findActiveProposalsUsingOutpoint(Hash hash, int index) {
        for (final Proposal proposal : activeProposals.values()) {
            if (proposal.transaction != null) {
                if (doesTransactionUseOutpoint(proposal.transaction, hash, index))
                    return proposal.transaction;
            }
        }

        return null;
    }

    public static CompletedTransaction findCompletedTransactionOutputWasSpentIn(Hash hash, int index) {
        return _inputToRecentlyCompletedCache.get(hash.toString() + ":" + index);
    }

    public static List<CompletedTransaction> findCompletedTransactionsSpendingTransactionHash(Hash hash) {
        List<CompletedTransaction> results = new ArrayList<>();

        for (CompletedTransaction completedTransaction : recentlyCompletedTransactions.values()) {
            Transaction transaction = completedTransaction.getTransaction();
            synchronized (transaction) {
                final List<TransactionInput> inputs = transaction.getInputs();

                for (TransactionInput input : inputs) {
                    final TransactionOutPoint outPoint = input.getOutpoint();

                    if (new Hash(outPoint.getHash().getBytes()).equals(hash))
                        results.add(completedTransaction);
                }
            }
        }

        return results;
    }


    public static Offer findOfferConsumingOutpoint(Hash hash, int index) {
        final List<Offer> offers = new ArrayList<>(pendingOffers.values());

        for (Offer offer : offers) {
            if (offer.spendsOutpoint(hash, index)) {
                return offer;
            }
        }

        final List<Proposal> proposals = new ArrayList<>(activeProposals.values());

        for (Proposal proposal : proposals) {
            for (Offer offer : proposal.getOffers()) {
                if (offer.spendsOutpoint(hash, index)) {
                    return offer;
                }
            }

            for (Offer offer : proposal.ourOffers) {
                if (offer.spendsOutpoint(hash, index)) {
                    return offer;
                }
            }
        }

        return null;
    }

    public static Proposal findActiveProposalByTransaction(Hash hash) {
        final List<Proposal> proposals = new ArrayList<>(activeProposals.values());

        for (Proposal proposal : proposals) {
            if (proposal.isFinalized && proposal.transaction != null)
                if (new Hash(proposal.transaction.getHash().getBytes()).equals(hash))
                    return proposal;
        }

        return null;
    }

    public static Proposal findActiveProposalFromOffer(Offer offer) {
        final List<Proposal> proposals = new ArrayList<>(activeProposals.values());

        for (Proposal proposal : proposals) {
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
            return new TransactionOutput(params, null, Coin.valueOf(value.longValue()), script.getProgram());
        }

        @Override
        public byte[] getConnectedPubKeyScript() {
            return script.getProgram();
        }
    }

    public static class Output implements Serializable {
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
                return getScript().getToAddress(MainNetParams.get());
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

    public static class OutpointWithValue implements Serializable {
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
            return getScript().getToAddress(MainNetParams.get()).toString();
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

    public static class Offer implements Serializable {
        static final long serialVersionUID = 1L;

        private long receivedTime;
        private long offerID;
        private List<OutpointWithValue> offeredOutpoints = new CopyOnWriteArrayList<>();
        private List<Output> requestedOutputs = new CopyOnWriteArrayList<>();
        private double feePercent;
        private transient Token token;
        private transient long forceProposalMaxAge;
        private transient String hashedUserIP;

        public Offer() {
            offerID = randomID();
            receivedTime = System.currentTimeMillis();
        }

        public Token getToken() {
            return token;
        }

        public String getHashedUserIP() {
            return hashedUserIP;
        }

        private double getFeePercent() {
            return feePercent;
        }

        public long calculateFee() {
            return getValueOffered() - getValueOutputRequested();
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

                return totalFeePayingOutputValue / (long) Math.ceil(100 / getFeePercent());
            }
        }

        public boolean addOfferedOutpoint(OutpointWithValue outpointWithValue) {
            return offeredOutpoints.add(outpointWithValue);
        }

        public Set<String> getRequestedOutputAddresses() {
            Set<String> set = new HashSet<>();
            for (Output output : requestedOutputs) {
                set.add(output.getAddress().toString());
            }
            return set;
        }

        public boolean addRequestedOutput(Output pair) throws Exception {

            if (pair.getValue() < MinimumNoneStandardOutputValue)
                throw new Exception("addRequestedOutput().value < MinimumNoneStandardOutputValue (" + pair.getValue() + ")");

            return requestedOutputs.add(pair);
        }

        public long getReceivedTime() {
            return receivedTime;
        }

        public long getOfferID() {
            return offerID;
        }

        public boolean spendsOutpoint(final Hash hash, int index) {
            for (OutpointWithValue outpointWithValue : getOfferedOutpoints())
                if (outpointWithValue.getHash().equals(hash) && outpointWithValue.getIndex() == index)
                    return true;

            return false;
        }

        public List<OutpointWithValue> getOfferedOutpoints() {
            return Collections.unmodifiableList(offeredOutpoints);
        }

        public List<Output> getRequestedOutputs() {
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

        final List<Offer> offers = new ArrayList<>(pendingOffers.values());


        req.setAttribute("pending_offers", offers);

        final List<Proposal> proposals = new ArrayList<>(activeProposals.values());

        req.setAttribute("active_proposals", proposals);


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
        req.setAttribute("average_participants", ((double) totalParticipants / (double) recentlyCompleted.size()));
        req.setAttribute("recently_completed_transactions", recentlyCompleted);
        req.setAttribute("total_output_value", (totalOutputValue / (double) COIN));

        getServletContext().getRequestDispatcher("/WEB-INF/sharedcoin-status.jsp").forward(req, res);
    }

    @Override
    public void doOptions(HttpServletRequest req, HttpServletResponse res) throws IOException, ServletException {
        setCORS(req, res);

        res.setHeader("Access-Control-Allow-Methods", "GET, POST");
        res.setHeader("Access-Control-Allow-Headers", "X-Requested-With, Content-Type, Accept, Origin, If-Modified-Since, Cache-Control, User-Agent");
        res.setHeader("Access-Control-Max-Age", "86400");
        res.setHeader("Allow", "GET, POST, OPTIONS");
    }

    public void setCORS(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String origin = req.getHeader("Origin");

        List<String> allowedDomains = (List) Settings.instance().getList("cors_domains");

        if (origin == null || allowedDomains.contains("*")) {
            res.setHeader("Access-Control-Allow-Origin", "*");
            return;
        } else {

            boolean found = false;
            for (String allowedDomain : allowedDomains) {
                if (origin.startsWith(allowedDomain)) {
                    found = true;
                    break;
                }
            }

            if (found) {
                res.setHeader("Access-Control-Allow-Origin", origin);
                return;
            }
        }
        Logger.log(Logger.SeverityWARN, "Unknown CORS Origin " + origin);

        throw new IOException("CORS Denied");

    }

    @Override
    protected void doPost(HttpServletRequest req, final HttpServletResponse res) throws ServletException, IOException {

        DOSManager.RequestContainer container = null;
        try {
            container = DOSManager.registerRequestStart(req);

            try {
                setCORS(req, res);

                if (Settings.instance().getBoolean("disabled") && !AdminServlet.isAuthorized(req)) {
                    res.setStatus(500);
                    res.getWriter().print(Settings.instance().getString("disabled_message"));
                    return;
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

                final String userIP = AdminServlet.getRealIP(req);

                Logger.log(Logger.SeverityINFO, "Received Request Method " + method + " (IP : " + userIP + ")");

                if (method != null) {
                    if (method.equals("submit_offer")) {
                        Offer existingConflictingOffer = null;
                        MyTransactionOutput outputAlreadySpent = null;

                        Offer offer = new Offer();

                        Logger.log(Logger.SeverityINFO, "Submit Offer Received From " + userIP);

                        offer.hashedUserIP = Util.SHA256Hex(userIP);

                        JSONObject jsonObject = (JSONObject) new JSONParser().parse(req.getParameter("offer"));

                        if (jsonObject == null) {
                            throw new Exception("Invalid offer json");
                        }

                        Logger.log(Logger.SeverityINFO, "Submit Offer Object " + jsonObject);

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

                            //Only enforce when a fee is set
                            if (DefaultFeePercent > 0) {
                                if (token.created < System.currentTimeMillis() - TokenExpiryTime) {
                                    throw new Exception("Token has expired");
                                }

                                if (!token.created_ip.equals(userIP)) {
                                    throw new Exception("Token Requester Changed");
                                }
                            }

                            double tokenFeePercent = token.fee_percent;

                            String userFeePercentString = req.getParameter("fee_percent");

                            if (userFeePercentString != null) {
                                try {
                                    double userFeePercent = Double.valueOf(userFeePercentString);

                                    if (userFeePercent < tokenFeePercent) {
                                        throw new Exception("Fee Percentage Less Than Minimum");
                                    }

                                    offer.feePercent = userFeePercent;
                                } catch (Exception e) {
                                    throw new Exception("Invalid Numerical Value");
                                }
                            } else {
                                offer.feePercent = tokenFeePercent;
                            }

                            offer.token = token;
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
                            JSONObject input = (JSONObject) _input;

                            final String hashString = (String) input.get("hash");

                            if (hashString == null || hashString.length() != 64) {
                                throw new Exception("Invalid Input Hash");
                            }

                            Hash hash = new Hash(hashString);

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
                                        if (findCompletedTransaction(hash) != null || findActiveProposalByTransaction(hash) != null) {
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
                                    Logger.log(Logger.SeveritySeriousError, _e);

                                    throw new Exception("Input Tx is null " + hash);
                                }

                                _transactionCache.put(hash, transaction);
                            }

                            if (transaction.getHeight() == 0) {
                                //Allow unconfirmed inputs from transaction we created
                                if (!isTransactionCreatedByUs(hash)) {
                                    throw new Exception("Only confirmed inputs accepted " + hash);
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
                                throw new Exception("The Minimum Input Value is " + (HardErrorMinimumInputValue / (double) COIN) + " BTC");
                            }

                            if (outpointWithValue.value > MaximumInputValue) {
                                throw new Exception("The Maximum Input Value is " + (MaximumInputValue / (double) COIN) + " BTC");
                            }

                            MyTransactionOutput output = (MyTransactionOutput) transaction.getOutputs().get(index);

                            if (output.isSpent()) {
                                outputAlreadySpent = output;
                            }

                            outpointWithValue.script = output.getScriptBytes();

                            if (outpointWithValue.script == null) {
                                throw new Exception("Output Script is null");
                            }

                            if (!outpointWithValue.getScript().isSentToAddress()) {
                                throw new Exception("Invalid output script. Only Address Outputs currently supported.");
                            }

                            if (!offer.addOfferedOutpoint(outpointWithValue)) {
                                throw new Exception("Error Adding Outpoint");
                            }
                        }

                        for (Object _output : outputs) {
                            JSONObject output = (JSONObject) _output;

                            Script script = newScript(Hex.decode((String) output.get("script")));
                            long value;
                            try {
                                value = Long.valueOf(output.get("value").toString());
                            } catch (Exception e) {
                                throw new Exception("Invalid Integer");
                            }

                            if (!script.isSentToAddress()) {
                                throw new Exception("Strange script output " + script.toString());
                            }

                            //The client can cheat here by requesting the largest output be excluded even if it isn't the change address
                            //Can be detected next repetition
                            //Or enforced by checking the available inputs and determining if the client was able to use smaller inputs (Also possible to predict change address this method)
                            boolean excludeFromFee = false;

                            if (output.get("exclude_from_fee") != null) {
                                excludeFromFee = Boolean.valueOf(output.get("exclude_from_fee").toString());
                            }

                            if (value < MinimumOutputValue && !excludeFromFee) {
                                throw new Exception("The Minimum Output Value Size is " + (MinimumOutputValue / (double) COIN) + " BTC  (Actual: " + (value / (double) COIN) + ")");
                            } else if (value < MinimumOutputValueExcludeFee && excludeFromFee) {
                                throw new Exception("The Minimum Output Value Excluding Fee is " + (MinimumOutputValueExcludeFee / (double) COIN) + " BTC  (Actual: " + (value / (double) COIN) + ")");
                            }

                            if (value > HardErrorMaximumOutputValue && !excludeFromFee) {
                                throw new Exception("The Maximum Output Value Size is " + (HardErrorMaximumOutputValue / (double) COIN) + " BTC (Actual: " + (value / (double) COIN) + ")");
                            }

                            Output outputContainer = new Output();

                            outputContainer.script = script.getProgram();
                            outputContainer.value = value;
                            outputContainer.excludeFromFee = excludeFromFee;

                            if (offer.getRequestedOutputAddresses().contains(script.getToAddress(MainNetParams.get()).toString())) {
                                throw new Exception("Each Output Address must be unique");
                            }

                            if (!offer.addRequestedOutput(outputContainer)) {
                                throw new Exception("Error Adding Requested Output");
                            }
                        }

                        long totalInputValue = offer.getValueOffered();
                        long totalOutputValue = offer.getValueOutputRequested();

                        if (totalInputValue < totalOutputValue) {
                            throw new Exception("Input Value Less Than Output Value");
                        }

                        long expectedFee = offer.calculateFeeExpected();
                        if (version >= 2) {
                            expectedFee = Math.max(expectedFee, MinimumFee);
                        }

                        final long feePaid = totalInputValue - totalOutputValue;

                        if (feePaid < (expectedFee - MinimumNoneStandardOutputValue)) {
                            throw new Exception("Insufficient Fee " + (totalInputValue - totalOutputValue) + " expected " + expectedFee);
                        }

                        if (feePaid > (expectedFee + MinimumNoneStandardOutputValue)) {
                            throw new Exception("Paid too much fee. Possibly a client error. (Expected: " + expectedFee + " Paid: " + (totalInputValue - totalOutputValue) + ")");
                        }


                        //Everything looks good so far
                        //Check for any conflicting inputs
                        //Then add to pending

                        JSONObject obj = new JSONObject();

                        Lock lock = insertPendingOffersLock.writeLock();

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
                                Logger.log(Logger.SeverityINFO, "Offer " + offer + " has conflicting offer " + existingConflictingOffer);

                                if (offer.isTheSameAsOffer(existingConflictingOffer)) {
                                    Logger.log(Logger.SeverityINFO, "Conflicting Offer Is Equal");

                                    obj.put("offer_id", existingConflictingOffer.getOfferID());
                                } else {
                                    throw new Exception("Conflicting Offer");
                                }
                            } else {
                                //Check we didn't recently spend any outputs
                                for (OutpointWithValue outpointWithValue : offer.getOfferedOutpoints()) {
                                    CompletedTransaction completedTransaction = findCompletedTransactionOutputWasSpentIn(outpointWithValue.getHash(), outpointWithValue.getIndex());
                                    if (completedTransaction != null) {
                                        Logger.log(Logger.SeverityWARN, "User tried to submit outpoint spent in completed transaction " + AdminServlet.getRealIP(req));
                                        Logger.log(Logger.SeverityWARN, "   This is their offer " + offer);
                                        Logger.log(Logger.SeverityWARN, "   This is the conflicting transaction " + completedTransaction);
                                        Logger.log(Logger.SeverityWARN, "   Current Timestamp : " + System.currentTimeMillis() + " Completed Transaction Timestamp " + completedTransaction.completedTime);

                                        throw new Exception("Outpoint (" + outpointWithValue + ") already Spent in Completed Transaction " + completedTransaction);
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

                        Logger.log(Logger.SeverityINFO, "Responding to Submit Offer " + obj.toJSONString());

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
                                synchronized (offer) {
                                    offer.wait(MaxPollTime);
                                }

                                proposal = findActiveProposalFromOffer(offer);
                            } else if (proposal.getTransaction() == null) {
                                synchronized (proposal) {
                                    proposal.wait(MaxPollTime);
                                }
                            }

                            if (proposal == null || proposal.getTransaction() == null) {
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

                                byte[] serialized = completedTransaction.getTransaction().bitcoinSerialize();

                                obj.put("tx", new String(Hex.encode(serialized), "UTF-8"));
                            } else {
                                obj.put("status", "not_found");
                            }
                        } else if (proposal.isFinalized) {
                            final Transaction tx = proposal.getTransaction();

                            assert (tx != null);

                            obj.put("status", "complete");
                            obj.put("tx_hash", tx.getHash().toString());

                            byte[] serialized = tx.bitcoinSerialize();

                            obj.put("tx", new String(Hex.encode(serialized), "UTF-8"));
                        } else {
                            obj.put("proposal_id", proposal.getProposalID());

                            Offer offer = proposal.findOffer(offerID);

                            if (offer == null) {
                                obj.put("status", "not_found");
                            } else {
                                final Transaction tx = proposal.getTransaction();

                                if (tx == null) {
                                    synchronized (proposal) {
                                        proposal.wait(MaxPollTime);
                                    }
                                }

                                assert (tx != null);

                                obj.put("status", "signatures_needed");

                                byte[] serialized = tx.bitcoinSerialize();

                                obj.put("tx", new String(Hex.encode(serialized), "UTF-8"));

                                JSONArray array = new JSONArray();
                                for (Proposal.SignatureRequest request : proposal.getSignatureRequests(offer)) {
                                    JSONObject pairObj = new JSONObject();

                                    pairObj.put("offer_outpoint_index", request.offer_outpoint_index);
                                    pairObj.put("tx_input_index", request.tx_input_index);
                                    pairObj.put("connected_script", new String(Hex.encode(request.connected_script.getProgram()), "UTF-8"));

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

                                if (completedTransaction.pushCount == 0) {
                                    synchronized (completedTransaction) {
                                        completedTransaction.wait(MaxPollTime);
                                    }
                                }

                                if (completedTransaction.pushCount == 0) {
                                    obj.put("status", "waiting");
                                    obj.put("signatures_required", 0);

                                    Transaction transaction = completedTransaction.getTransaction();
                                    synchronized (transaction) {
                                        obj.put("signatures_submitted", transaction.getInputs().size());
                                    }
                                } else {
                                    obj.put("status", "complete");
                                    obj.put("tx_hash", completedTransaction.getTransaction().getHash().toString());

                                    byte[] serialized = completedTransaction.getTransaction().bitcoinSerialize();
                                    obj.put("tx", new String(Hex.encode(serialized), "UTF-8"));
                                }
                            } else {
                                obj.put("status", "not_found");
                            }
                        } else {
                            synchronized (proposal) {
                                if (!proposal.isFinalized || !proposal.isBroadcast) {
                                    proposal.wait(MaxPollTime);
                                }
                            }

                            if (proposal.isFinalized && proposal.isBroadcast) {
                                final Transaction tx = proposal.getTransaction();

                                assert (tx != null);

                                obj.put("status", "complete");
                                obj.put("tx_hash", tx.getHash().toString());

                                byte[] serialized = tx.bitcoinSerialize();

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

                                byte[] serialized = completedTransaction.getTransaction().bitcoinSerialize();

                                obj.put("tx", new String(Hex.encode(serialized), "UTF-8"));
                            } else {
                                obj.put("status", "not_found");
                            }
                        } else {
                            Offer offer = proposal.findOffer(offerID);

                            if (offer == null) {
                                obj.put("status", "not_found");
                            } else if (proposal.isFinalized) {

                                final Transaction tx = proposal.getTransaction();

                                assert (tx != null);

                                obj.put("status", "complete");
                                obj.put("tx_hash", tx.getHash().toString());

                                byte[] serialized = tx.bitcoinSerialize();

                                obj.put("tx", new String(Hex.encode(serialized), "UTF-8"));
                            } else {
                                JSONArray jsonSignaturesArray = (JSONArray) new JSONParser().parse(req.getParameter("input_scripts"));

                                boolean allSigned = false;
                                for (Object _jsonSignatureObject : jsonSignaturesArray) {
                                    JSONObject jsonSignatureObject = (JSONObject) _jsonSignatureObject;

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

                                    byte[] inputScriptBytes = Hex.decode((String) jsonSignatureObject.get("input_script"));

                                    Script bitcoinJInputScript = newScript(inputScriptBytes);

                                    OutpointWithValue outpoint = offer.getOfferedOutpoints().get(offer_outpoint_index);

                                    Script connected_script = outpoint.getScript();

                                    try {
                                        final Transaction tx = proposal.getTransaction();

                                        assert (tx != null);

                                        bitcoinJInputScript.correctlySpends(tx, tx_input_index, connected_script, Script.ALL_VERIFY_FLAGS);

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
                                                proposal.finalizeTransaction();

                                                proposal.pushTransaction();
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
                        final List<Proposal> proposals = new ArrayList<>(activeProposals.values());

                        for (final Proposal proposal : proposals) {
                            if (proposal.getNSigned() == proposal.getNSignaturesNeeded()) {
                                multiThreadExec.execute(new Runnable() {
                                    @Override
                                    public void run() {
                                        try {
                                            proposal.finalizeTransaction();

                                            proposal.pushTransaction();
                                        } catch (Exception e) {
                                            Logger.log(Logger.SeveritySeriousError, e);
                                        }
                                    }
                                });
                            }
                        }

                        res.sendRedirect("/home");
                    } else {
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

                throw e;
            } finally {
                container.didFinishRequest(res);
            }
        } catch (Exception e) {
            List<DOSManager.RequestContainer> requests = DOSManager.getRequestList(req);

            if (requests != null) {
                for (DOSManager.RequestContainer requestContainer : requests) {
                    Logger.log(Logger.SeverityWARN, requestContainer);
                }
            }
        }
    }
}
