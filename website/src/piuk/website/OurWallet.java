package piuk.website;

import org.bitcoinj.core.*;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import org.apache.commons.lang3.ArrayUtils;
import piuk.*;

import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class OurWallet {
    private volatile MyRemoteWallet _cached = null;
    public ReadWriteLock updateLock = new ReentrantReadWriteLock(true);

    private static boolean _scheduleDivideOutputs = false;
    private static boolean _scheduleCombineOutputs = true;

    private static final int TargetNumberActiveNonZeroAddresses = 600;
    private static final int TargetNumberUnusedAddresses = 200;
    private static final int MaxActiveAddresses = 1000; //16KB

    private static final long ForceDivideLargeOutputSize = 50 * SharedCoin.COIN;


    private static final int TimerInterval = 10000; //10 seconds
    private static final int TidyWalletInterval = 60000; //1 minutes
    private static final int CleanOutConfirmedInterval = 120000; //2 minutes

    private static long lastTidyWalletTime = 0;
    private static long lastCleanOutConfirmedTime = 0;
    private static Set<Hash> lastTidyRecentlyCompletedKeySet = new ConcurrentSkipListSet<>();

    private static final long CombineDustMinimumOutputSize = SharedCoin.MinimumNoneStandardOutputValue;

    private static final OurWallet instance = new OurWallet();

    private static long lastCleanOutBlockHeight = 0;

    private static final ExecutorService tidyExec = Executors.newSingleThreadExecutor();

    public static OurWallet getInstance() {
        return instance;
    }

    private int _cachedNumberOfActiveNonZero = 0;

    public boolean walletIsFragmented() {
        return _cachedNumberOfActiveNonZero > (TargetNumberActiveNonZeroAddresses * 0.9d);
    }

    private static final Cache<String, Boolean> recentlyDividedOrCombinedAddressesMap = CacheBuilder.newBuilder()
            .expireAfterWrite(20, TimeUnit.MINUTES).build();

    //Should make this outpoints really
    private static final Set<String> addressesWeRecentlySpent = Collections.newSetFromMap(recentlyDividedOrCombinedAddressesMap.asMap());

    public static boolean isAddressWeRecentlySpent(String address) {
        return addressesWeRecentlySpent.contains(address);
    }

    public static void scheduleTidyTasks() {
        final Timer timer = new Timer();

        timer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {

                tidyExec.execute(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            if (_scheduleDivideOutputs) {
                                _scheduleDivideOutputs = false;
                                Logger.log(Logger.SeverityINFO, "OurWallet.scheduleTidyTasks() Run divideOutputs()");
                                instance.divideOutputs();
                            }

                            if (_scheduleCombineOutputs) {
                                _scheduleCombineOutputs = false;
                                Logger.log(Logger.SeverityINFO, "OurWallet.scheduleTidyTasks() Run combineOutputs()");
                                instance.combineOutputs();
                            }

                            if (lastCleanOutConfirmedTime < System.currentTimeMillis() - CleanOutConfirmedInterval) {
                                lastCleanOutConfirmedTime = System.currentTimeMillis();
                                Logger.log(Logger.SeverityINFO, "OurWallet.scheduleTidyTasks() Run cleanOutFullyConfirmedAddresses()");
                                instance.cleanOutFullyConfirmedAddresses();
                            }

                            if (lastTidyWalletTime < System.currentTimeMillis() - TidyWalletInterval) {
                                lastTidyWalletTime = System.currentTimeMillis();
                                Logger.log(Logger.SeverityINFO, "OurWallet.scheduleTidyTasks() Run tidyTheWallet()");
                                instance.tidyTheWallet();
                            }
                        } catch (Exception e) {
                            Logger.log(Logger.SeveritySeriousError, e);
                        }
                    }
                });
            }
        }, TimerInterval, TimerInterval);
    }

    protected MyRemoteWallet getWalletNoLock() throws Exception {
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

    public static ECKey makeECKey(int counter) throws Exception {
        byte[] bytes = Util.SHA256(AdminServlet.PKSeed + counter).getBytes();

        //Prppend a zero byte to make the biginteger unsigned
        byte[] appendZeroByte = ArrayUtils.addAll(new byte[1], bytes);

        ECKey ecKey = ECKey.fromPrivate(new BigInteger(appendZeroByte));

        return ecKey;
    }

    public ECKey makeECKey() throws Exception {
        ++SharedCoin.PKSeedCounter;

        AdminServlet.writePKSeedCounter(SharedCoin.PKSeedCounter);

        return makeECKey(SharedCoin.PKSeedCounter);
    }


    public boolean isOurAddress(String address) throws Exception {
        Lock lock = updateLock.readLock();

        lock.lock();
        try {
            MyWallet wallet = getWalletNoLock();

            return wallet.isMine(address);
        } finally {
            lock.unlock();
        }
    }

    public List<MyTransactionOutPoint> getUnspentOutputs(int limit) throws Exception {
        Lock lock = updateLock.readLock();

        lock.lock();
        try {
            MyWallet wallet = getWalletNoLock();

            final List<MyTransactionOutPoint> unspent = MyRemoteWallet.getUnspentOutputPoints(wallet.getActiveAddresses(), 0, limit);

            final List<MyTransactionOutPoint> filtered = new ArrayList<>();

            for (MyTransactionOutPoint outPoint : unspent) {
                final String address = outPoint.getAddress();

                if (address != null) {
                    //Dont return outpoints from addresses we spent recently
                    //Otherwise the OurWallet use could double spend
                    if (!isAddressWeRecentlySpent(address)) {
                        filtered.add(outPoint);
                    }
                } else {
                    filtered.add(outPoint);
                }
            }

            return filtered;
        } finally {
            lock.unlock();
        }
    }

    private String getRandomAddressNoLock() throws Exception {
        MyWallet wallet = getWalletNoLock();

        int ii = 0;
        while (true) {
            String selectedAddress = wallet.getRandomActiveAddress();

            if (!isAddressWeRecentlySpent(selectedAddress) || ii > 100)
                return selectedAddress;

            ++ii;
        }
    }

    public String getRandomAddress() throws Exception {
        Lock lock = updateLock.readLock();

        lock.lock();
        try {
            return getRandomAddressNoLock();
        } finally {
            lock.unlock();
        }
    }

    public synchronized void cleanOutFullyConfirmedAddresses() throws Exception {
        long currentBlockHeight = MyRemoteWallet.getLatestBlockHeightFromQueryAPI();

        if (currentBlockHeight == 0 || currentBlockHeight == lastCleanOutBlockHeight) {
            Logger.log(Logger.SeverityINFO, "OurWallet.cleanOutFullyConfirmedAddresses() currentBlockHeight equals lastCheckedBlockHeight returning here");
            return;
        }

        lastCleanOutBlockHeight = currentBlockHeight;

        Logger.log(Logger.SeverityINFO, "OurWallet.cleanOutFullyConfirmedAddresses() Running Block Height " + lastCleanOutBlockHeight);

        final WalletOperationsQueue pendingOperations = new WalletOperationsQueue();

        {
            //Delete after 6 confirmations
            long maxDeletionBlockHeight = currentBlockHeight - 3;

            final MyRemoteWallet wallet = getWalletNoLock();

            final List<String> archived = Arrays.asList(wallet.getArchivedAddresses());

            final List<List<String>> batches = Util.divideListInSublistsOfNSize(archived, 1000);

            for (List<String> batch : batches) {
                Logger.log(Logger.SeverityINFO, "OurWallet.cleanOutFullyConfirmedAddresses() batch " + batch);

                final Map<String, Long> extraBalances = MyRemoteWallet.getMultiAddrBalances(batch);

                for (String address : batch) {
                    if (address == null)
                        continue;

                    final Long balance = extraBalances.get(address);

                    if (balance != null) {
                        //Un-archive any addresses with a none zero balance
                        if (balance > 0) {
                            Logger.log(Logger.SeverityINFO, "OurWallet.cleanOutFullyConfirmedAddresses() Unarchive " + address);

                            pendingOperations.add(new UnarchiveArchiveWalletOperation(address));
                        } else if (balance == 0) {
                            long blockHeight = MyRemoteWallet.getMaxConfirmingBlockHeightForTransactionConfirmations(address);

                            if (blockHeight > 0 && blockHeight <= maxDeletionBlockHeight) {
                                Logger.log(Logger.SeverityINFO, "OurWallet.cleanOutFullyConfirmedAddresses() Delete blockHeight " + address + " blockHeight " + blockHeight);

                                pendingOperations.add(new DeleteAddressWalletOperation(address));
                            }
                        }
                    }
                }
            }
        }

        if (pendingOperations.size() > 0) {
            Lock lock = updateLock.writeLock();

            lock.lock();
            try {
                MyRemoteWallet wallet = getWalletNoLock();

                for (WalletOperation operation : pendingOperations) {
                    operation.run(wallet);
                }

                if (!wallet.remoteSave(null)) {
                    throw new Exception("Error Saving Wallet");
                }
                _cached = null;
            } finally {
                lock.unlock();
            }
        }
    }


    public synchronized void combineOutputs() throws Exception {
        Lock lock = updateLock.writeLock();

        lock.lock();
        try {
            //Do multiaddr
            //Archive ZERO balance addresses with more than one transaction
            //Delete archived addresses with transactions > 6 confirmations

            MyRemoteWallet wallet = getWalletNoLock();

            wallet.doMultiAddr();

            final Set<String> toCombineAddresses = new HashSet<>();

            BigInteger value = BigInteger.ZERO;

            final List<String> allActive = Arrays.asList(wallet.getActiveAddresses());

            Collections.shuffle(allActive);

            int numberOfActiveNonZero = 0;
            for (String address : allActive) {
                final int n_tx = wallet.getNtx(address);
                final BigInteger balance = wallet.getBalance(address);

                if (n_tx > 0 && balance.compareTo(BigInteger.ZERO) > 0) {
                    ++numberOfActiveNonZero;
                }
            }

            Logger.log(Logger.SeverityINFO, "combineOutputs() numberOfActiveNonZero " + numberOfActiveNonZero);

            //Allow 10% leeway
            boolean shouldCombineUsed = (numberOfActiveNonZero > (TargetNumberActiveNonZeroAddresses * 1.1d));

            final List<String> unusedAddresses = new ArrayList<>();

            boolean addedAddressForFee = false;
            for (String address : allActive) {
                final BigInteger balance = wallet.getBalance(address);
                final int n_tx = wallet.getNtx(address);

                boolean isUsed = n_tx > 0;

                if (SharedCoin.isAddressInUse(address)
                        || SharedCoin.isAddressTargetOfAnActiveOutput(address)
                        || isAddressWeRecentlySpent(address)
                        || SharedCoin.findCompletedTransactionConsumingAddress(address, 600000) != null) {
                    continue;
                }

                if (!isUsed) {
                    unusedAddresses.add(address);
                }

                if (!addedAddressForFee && balance.compareTo(BigInteger.valueOf(SharedCoin.COIN)) >= 0) {

                    toCombineAddresses.add(address);

                    addedAddressForFee = true;

                    value = value.add(balance);

                } else if (isUsed && shouldCombineUsed && balance.compareTo(BigInteger.valueOf(SharedCoin.MaximumOutputValue)) < 0 && toCombineAddresses.size() < 4) {
                    Logger.log(Logger.SeverityINFO, "combineOutputs() Address " + address + " " + balance);

                    toCombineAddresses.add(address);

                    value = value.add(balance);
                } else if (balance.compareTo(BigInteger.ZERO) > 0 && balance.compareTo(BigInteger.valueOf(CombineDustMinimumOutputSize)) <= 0 && toCombineAddresses.size() <= 10) {
                    Logger.log(Logger.SeverityINFO, "combineOutputs() Dust Address " + address + " " + balance);

                    toCombineAddresses.add(address);

                    value = value.add(balance);
                }
            }

            if (toCombineAddresses.size() < 2) {
                return;
            }

            _scheduleCombineOutputs = true;

            final String destinationAddress;
            if (unusedAddresses.size() > 0) {
                destinationAddress = unusedAddresses.get(0);
                unusedAddresses.remove(destinationAddress);
            } else {
                destinationAddress = getRandomAddressNoLock();
            }

            final String changeAddress;
            if (unusedAddresses.size() > 0) {
                changeAddress = unusedAddresses.get(0);
                unusedAddresses.remove(changeAddress);
            } else {
                changeAddress = getRandomAddressNoLock();
            }

            Logger.log(Logger.SeverityINFO, "combineOutputs() Send From [" + toCombineAddresses + "] to destination " + destinationAddress + " changeAddress " + changeAddress);

            addressesWeRecentlySpent.addAll(toCombineAddresses);

            BigInteger unRoundedSplit = BigInteger.valueOf((long) ((value.longValue() / 2) * (Math.random() + 0.5)));

            //Round the split based on number of significant digits
            long digitCount = Util.getDigitCount(unRoundedSplit);

            BigInteger finalSplit = unRoundedSplit;
            for (int ii = 0; ii < 2; ++ii) {
                BigInteger modifier = BigInteger.valueOf((long) Math.pow(10L, Util.randomLong(1, digitCount - 1)));

                BigInteger rounded = unRoundedSplit.divide(modifier).multiply(modifier);

                BigInteger roundedSplitRemainder = value.subtract(rounded);

                if (rounded.compareTo(BigInteger.valueOf(SharedCoin.MinimumOutputChangeSplitValue)) >= 0 &&
                        roundedSplitRemainder.compareTo(BigInteger.valueOf(SharedCoin.MinimumOutputChangeSplitValue)) >= 0) {
                    finalSplit = rounded;
                    break;
                }
            }

            if (wallet.send(toCombineAddresses.toArray(new String[]{}), destinationAddress, changeAddress, finalSplit, SharedCoin.TransactionFeePer1000Bytes, true)) {
                Logger.log(Logger.SeverityINFO, "combineOutputs() wallet.send returned true");
            } else {
                Logger.log(Logger.SeverityINFO, "combineOutputs() wallet.send returned false");
            }
        } finally {
            lock.unlock();
        }
    }

    public synchronized void divideOutputs() throws Exception {
        Lock lock = updateLock.writeLock();

        lock.lock();
        try {
            //Do multiaddr
            //Archive ZERO balance addresses with more than one transaction
            //Delete archived addresses with transactions > 6 confirmations
            final MyRemoteWallet wallet = getWalletNoLock();

            wallet.doMultiAddr();

            final List<String> unusedAddresses = new ArrayList<>();

            int numberOfActiveNonZero = 0;

            final List<String> allActive = Arrays.asList(wallet.getActiveAddresses());

            Collections.shuffle(allActive);

            for (String address : allActive) {
                final int n_tx = wallet.getNtx(address);
                final BigInteger balance = wallet.getBalance(address);

                if (n_tx == 0) {
                    if (!SharedCoin.isAddressInUse(address)
                            && !SharedCoin.isAddressTargetOfAnActiveOutput(address)
                            && !isAddressWeRecentlySpent(address)
                            && SharedCoin.findCompletedTransactionConsumingAddress(address, 600000) == null) {
                        unusedAddresses.add(address);
                    }
                }

                if (n_tx > 0 && balance.compareTo(BigInteger.ZERO) > 0) {
                    ++numberOfActiveNonZero;
                }
            }

            Logger.log(Logger.SeverityINFO, "divideOutputs() numberOfActiveNonZero " + numberOfActiveNonZero);

            //Allow 10% leeway
            boolean splitUsed = (numberOfActiveNonZero < (TargetNumberActiveNonZeroAddresses * 0.9d));

            String divideAddress = null;
            BigInteger divideBalance = null;

            for (String address : allActive) {
                final BigInteger balance = wallet.getBalance(address);

                if (balance.compareTo(BigInteger.valueOf(SharedCoin.MinimumOutputChangeSplitValue * 2)) <= 0) {
                    continue;
                }

                if (SharedCoin.isAddressInUse(address)
                        || SharedCoin.isAddressTargetOfAnActiveOutput(address)
                        || isAddressWeRecentlySpent(address)
                        || SharedCoin.findCompletedTransactionConsumingAddress(address, 600000) != null) {
                    continue;
                }

                if (balance.longValue() >= ForceDivideLargeOutputSize) {
                    divideAddress = address;
                    divideBalance = balance;
                    break;
                }

                if (splitUsed && divideAddress == null) {
                    divideAddress = address;
                    divideBalance = balance;
                }
            }

            if (divideAddress != null) {
                BigInteger unRoundedSplit = BigInteger.valueOf((long) ((divideBalance.longValue() / 2) * (Math.random() + 0.5)));

                //Round the split based on number of significant digits
                long digitCount = Util.getDigitCount(unRoundedSplit);

                BigInteger finalSplit = unRoundedSplit;
                for (int ii = 0; ii < 2; ++ii) {
                    BigInteger modifier = BigInteger.valueOf((long) Math.pow(10L, Util.randomLong(1, digitCount - 1)));

                    BigInteger rounded = unRoundedSplit.divide(modifier).multiply(modifier);

                    BigInteger roundedSplitRemainder = divideBalance.subtract(rounded);

                    if (rounded.compareTo(BigInteger.valueOf(SharedCoin.MinimumOutputChangeSplitValue)) >= 0 &&
                            roundedSplitRemainder.compareTo(BigInteger.valueOf(SharedCoin.MinimumOutputChangeSplitValue)) >= 0) {
                        finalSplit = rounded;
                        break;
                    }
                }

                Logger.log(Logger.SeverityINFO, "divideOutputs() divideBalance "  + divideBalance + " rounded split " + finalSplit + " un-rounded " + unRoundedSplit + " digitCount " + digitCount);

                final String destinationAddress;
                if (unusedAddresses.size() > 0) {
                    destinationAddress = unusedAddresses.get(0);
                    unusedAddresses.remove(destinationAddress);
                } else {
                    destinationAddress = getRandomAddressNoLock();
                }

                final String changeAddress;
                if (unusedAddresses.size() > 0) {
                    changeAddress = unusedAddresses.get(0);
                    unusedAddresses.remove(changeAddress);
                } else {
                    changeAddress = getRandomAddressNoLock();
                }

                Logger.log(Logger.SeverityINFO, "divideOutputs() Send From [" + divideAddress + "] to destination " + destinationAddress + " value " + finalSplit + " changeAddress " + changeAddress);

                addressesWeRecentlySpent.add(divideAddress);

                wallet.send(new String[]{divideAddress}, destinationAddress, changeAddress, finalSplit, SharedCoin.TransactionFeePer1000Bytes, true);

                Logger.log(Logger.SeverityINFO, "divideOutputs() Schedule Divide Again");

                _scheduleDivideOutputs = true;
            }
        } finally {
            lock.unlock();
        }
    }

    public static interface WalletOperation {
        public void run(MyRemoteWallet wallet) throws Exception;
    }


    public static class WalletOperationsQueue extends HashSet<WalletOperation> {

        public int calculateNArchived() {
            int archived = 0;
            for (WalletOperation operation : this) {
                if (operation instanceof ArchiveWalletOperation)
                    ++archived;
                else if (operation instanceof UnarchiveArchiveWalletOperation)
                    --archived;
            }

            return archived;
        }
    }

    public static class ArchiveWalletOperation implements WalletOperation {
        private final String address;

        public ArchiveWalletOperation(String address) {
            this.address = address;
        }

        @Override
        public void run(MyRemoteWallet wallet) throws Exception {
            if (!SharedCoin.isAddressInUse(address) && !SharedCoin.isAddressTargetOfAnActiveOutput(address))
                wallet.setTag(address, 2);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            ArchiveWalletOperation that = (ArchiveWalletOperation) o;

            if (!address.equals(that.address)) return false;

            return true;
        }

        @Override
        public int hashCode() {
            return address.hashCode();
        }
    }

    public static class UnarchiveArchiveWalletOperation implements WalletOperation {
        private final String address;

        public UnarchiveArchiveWalletOperation(String address) {
            this.address = address;
        }

        @Override
        public void run(MyRemoteWallet wallet) throws Exception {
            wallet.setTag(address, 0);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            ArchiveWalletOperation that = (ArchiveWalletOperation) o;

            if (!address.equals(that.address)) return false;

            return true;
        }

        @Override
        public int hashCode() {
            return address.hashCode();
        }
    }

    public static class GenerateAddressWalletOperation implements WalletOperation {
        private final ECKey key;

        public GenerateAddressWalletOperation(ECKey key) {
            this.key = key;
        }

        @Override
        public void run(MyRemoteWallet wallet) throws Exception {
            wallet.addKey(key, null, "sharedcoin", "" + SharedCoin.ProtocolVersion);
        }
    }

    public static class DeleteAddressWalletOperation implements WalletOperation {
        private final String address;

        public DeleteAddressWalletOperation(String address) {
            this.address = address;
        }

        @Override
        public void run(MyRemoteWallet wallet) throws Exception {
            //Log before deleting
            AdminServlet.logDeletedPrivateKey(address, wallet.getECKey(address));

            //And remove it
            wallet.removeAddressAndKey(address);
        }
    }

    public boolean addECKey(String address, ECKey key) throws Exception {
        Lock lock = updateLock.writeLock();

        lock.lock();
        try {
            MyRemoteWallet wallet = getWalletNoLock();


            String returnVal = wallet.addKey(key, null, "sharedcoin", "" + SharedCoin.ProtocolVersion);

            if (returnVal.equals(address)) {
                if (wallet.remoteSave(null)) {
                    _cached = null;
                    return true;
                } else {
                    throw new Exception("Error Saving Wallet");
                }
            }
        } finally {
            lock.unlock();
        }

        return false;
    }

    public synchronized void tidyTheWallet() throws Exception {

        //Check if the recently completed transactions set changed
        final Set<Hash> recentlyCompletedHashes = new HashSet<>(SharedCoin.getRecentlyCompletedTransactionHashes());
        if (recentlyCompletedHashes.equals(lastTidyRecentlyCompletedKeySet)) {
            Logger.log(Logger.SeverityINFO, "OurWallet.tidyTheWallet() recentlyCompletedHashes equals lastTidyRecentlyCompletedKeySet returning here");
            return;
        }
        lastTidyRecentlyCompletedKeySet = recentlyCompletedHashes;

        Logger.log(Logger.SeverityINFO, "OurWallet.tidyTheWallet() Running");

        final MyRemoteWallet multiAddrWallet;

        //Fetch a snapshot of the wallet balances at this point
        //We dont lock the wallet because the operations are not performed atomically at this point and we don't mind if it changes
        multiAddrWallet = getWalletNoLock();

        multiAddrWallet.doMultiAddr();

        final WalletOperationsQueue pendingOperations = new WalletOperationsQueue();

        if (multiAddrWallet.getBalance().compareTo(BigInteger.ZERO) == 0) {
            throw new Exception("OurWallet.tidyTheWallet() Wallet Balance Zero");
        }

        final String[] allActiveAddresses = multiAddrWallet.getActiveAddresses();
        final String[] allArchivedAddresses = multiAddrWallet.getArchivedAddresses();

        Logger.log(Logger.SeverityINFO, "OurWallet.tidyTheWallet() Number Of Active Addresses " + allActiveAddresses.length + " Number of Archived " + allArchivedAddresses.length);

        int numberOfUnusedAddresses = 0;
        int numberOfActiveNonZero = 0;

        //Archive any 0 balance addreses
        for (String address : allActiveAddresses) {
            final BigInteger balance = multiAddrWallet.getBalance(address);
            final int n_tx = multiAddrWallet.getNtx(address);

            if (balance.compareTo(BigInteger.valueOf(ForceDivideLargeOutputSize)) >= 0) {
                Logger.log(Logger.SeverityINFO, "tidyTheWallet() Schedule Divide Large Output");
                _scheduleDivideOutputs = true;
            }

            if (balance.compareTo(BigInteger.ZERO) > 0 && balance.compareTo(BigInteger.valueOf(CombineDustMinimumOutputSize)) <= 0) {
                Logger.log(Logger.SeverityINFO, "tidyTheWallet() Schedule Combine Dust Output");
                _scheduleCombineOutputs = true;
            }

            if (n_tx == 0) {
                ++numberOfUnusedAddresses;
            }

            if (n_tx > 0 && balance.compareTo(BigInteger.ZERO) > 0) {
                ++numberOfActiveNonZero;
            }

            if (n_tx > 0 && balance.compareTo(BigInteger.ZERO) == 0) {
                if (SharedCoin.isAddressInUse(address) || SharedCoin.isAddressTargetOfAnActiveOutput(address)) {
                    continue;
                }

                //Archive the address after it has been used for at least one transaction and the balance is zero
                pendingOperations.add(new ArchiveWalletOperation(address));
            }

        }

        if (allActiveAddresses.length - pendingOperations.calculateNArchived() > MaxActiveAddresses) {
            Logger.log(Logger.SeverityWARN, "OurWallet.tidyTheWallet() Too Many Active Addresses " + allActiveAddresses.length + " new addresses");

            //We have too many active address
            {
                //Archive those wil zero balance first
                int nToArchive = allActiveAddresses.length - MaxActiveAddresses;
                for (String address : allActiveAddresses) {
                    final BigInteger balance = multiAddrWallet.getBalance(address);

                    if (balance.compareTo(BigInteger.ZERO) == 0) {
                        if (pendingOperations.add(new ArchiveWalletOperation(address))) {
                            --nToArchive;

                            if (nToArchive <= 0)
                                break;
                        }
                    }
                }
            }

            if (allActiveAddresses.length - pendingOperations.calculateNArchived() > MaxActiveAddresses) {
                //Still too many active
                //Archive some at random
                Logger.log(Logger.SeverityWARN, "OurWallet.tidyTheWallet() Still Too Many Active Addresses " + allActiveAddresses.length + " new addresses");

                int nToArchive = allActiveAddresses.length - MaxActiveAddresses;

                for (String address : allActiveAddresses) {
                    if (pendingOperations.add(new ArchiveWalletOperation(address))) {
                        --nToArchive;

                        if (nToArchive <= 0)
                            break;
                    }
                }
            }
        }

        _cachedNumberOfActiveNonZero = numberOfActiveNonZero;

        if (numberOfActiveNonZero > (TargetNumberActiveNonZeroAddresses * 1.1d)) {
            Logger.log(Logger.SeverityINFO, "tidyTheWallet() schedule combine. numberOfActiveNonZero > TargetNumberActiveNonZeroAddresses * 1.1");
            _scheduleCombineOutputs = true;
        } else if (numberOfActiveNonZero < (TargetNumberActiveNonZeroAddresses * 0.9d)) {
            Logger.log(Logger.SeverityINFO, "tidyTheWallet() schedule divide. numberOfActiveNonZero < TargetNumberActiveNonZeroAddresses * 0.9");
            _scheduleDivideOutputs = true;
        }

        if (numberOfUnusedAddresses < TargetNumberUnusedAddresses) {
            int nAddressToCreate = Math.min(TargetNumberUnusedAddresses - numberOfUnusedAddresses, MaxActiveAddresses - (allActiveAddresses.length - pendingOperations.calculateNArchived()));


            //Generate New Addresses To Fill the wallet
            Logger.log(Logger.SeverityINFO, "Tidy Wallet: Generate " + nAddressToCreate + " new addresses numberOfUnusedAddresses " + numberOfUnusedAddresses);

            for (int ii = 0; ii < nAddressToCreate; ++ii) {
                ECKey key = makeECKey();

                pendingOperations.add(new GenerateAddressWalletOperation(key));
            }
        }

        Logger.log(Logger.SeverityINFO, "OurWallet.tidyTheWallet() pendingOperations size " + pendingOperations.size());

        if (pendingOperations.size() > 0) {
            Lock lock = updateLock.writeLock();

            //Now we execute all the operations atomically
            lock.lock();
            try {
                MyRemoteWallet wallet = getWalletNoLock();

                for (WalletOperation operation : pendingOperations) {
                    operation.run(wallet);
                }

                if (!wallet.remoteSave(null)) {
                    throw new Exception("Error Saving Wallet");
                }

                _cached = null;
            } finally {
                lock.unlock();
            }
        }
    }
}
