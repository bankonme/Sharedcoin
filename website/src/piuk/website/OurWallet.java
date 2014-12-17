package piuk.website;

import com.google.bitcoin.core.*;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import org.apache.commons.lang3.ArrayUtils;
import piuk.*;
import sun.rmi.runtime.Log;

import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class OurWallet {
    private volatile MyRemoteWallet _cached = null;
    public ReadWriteLock updateLock = new ReentrantReadWriteLock();

    private static boolean _scheduleDivideLargeOutputs = false;
    private static boolean _scheduleCombineDust = true;

    private static final int TargetNumberActiveAddresses = 800;
    private static final int MaxActiveAddresses = 1000; //16KB

    private static final long ForceDivideLargeOutputSize = 50 * SharedCoin.COIN;
    private static final long RandomDivideLargeOutputSize = 25 * SharedCoin.COIN;

    private static final int TimerInterval = 10000; //10 seconds
    private static final int TidyWalletInterval = 120000; //2 minutes
    private static final int CleanOutConfirmedInterval = 120000; //2 minutes

    private static long lastTidyWalletTime = 0;
    private static long lastCleanOutConfirmedTime = 0;
    private static Set<Hash> lastTidyRecentlyCompletedKeySet = new HashSet<>();

    private static final long CombineDustMinimumOutputSize = SharedCoin.MinimumNoneStandardOutputValue;

    private static final OurWallet instance = new OurWallet();

    private static long lastCleanOutBlockHeight = 0;

    private static final ExecutorService tidyExec = Executors.newSingleThreadExecutor();

    public static OurWallet getInstance() {
        return instance;
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
                            final long now = System.currentTimeMillis();

                            if (_scheduleDivideLargeOutputs) {
                                _scheduleDivideLargeOutputs = false;
                                Logger.log(Logger.SeverityINFO, "OurWallet.scheduleTidyTasks() Run divideLargeOutputs()");
                                instance.divideLargeOutputs();
                            } else if (_scheduleCombineDust) {
                                _scheduleCombineDust = false;
                                Logger.log(Logger.SeverityINFO, "OurWallet.scheduleTidyTasks() Run combineDust()");
                                instance.combineDust();
                            } else if (lastCleanOutConfirmedTime < now - CleanOutConfirmedInterval) {
                                lastCleanOutConfirmedTime = now;
                                Logger.log(Logger.SeverityINFO, "OurWallet.scheduleTidyTasks() Run cleanOutFullyConfirmedAddresses()");
                                instance.cleanOutFullyConfirmedAddresses();
                            } else if (lastTidyWalletTime < now - TidyWalletInterval) {
                                lastTidyWalletTime = now;
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

        ECKey ecKey = new ECKey(new BigInteger(appendZeroByte));

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
                try {
                    final Script script = SharedCoin.newScript(outPoint.getScriptBytes());

                    final Address address = script.getToAddress();

                    //Dont return outpoints from addresses we spent recently
                    //Otherwise the OurWallet use could double spend
                    if (!isAddressWeRecentlySpent(address.toString())) {
                        filtered.add(outPoint);
                    }
                } catch (Exception e) {
                    Logger.log(Logger.SeveritySeriousError, e);

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
            long minDeletionBlockHeight = currentBlockHeight - 6;

            final MyRemoteWallet wallet = getWalletNoLock();

            final List<String> archived = Arrays.asList(wallet.getArchivedAddresses());

            final List<List<String>> batches = Util.divideListInSublistsOfNSize(archived, 500);

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
                            long blockHeight = MyRemoteWallet.getMinConfirmingBlockHeightForTransactionConfirmations(address);

                            if (blockHeight > 0 && blockHeight <= minDeletionBlockHeight) {
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


    public synchronized void combineDust() throws Exception {
        Lock lock = updateLock.writeLock();

        lock.lock();
        try {
            //Do multiaddr
            //Archive ZERO balance addresses with more than one transaction
            //Delete archived addresses with transactions > 6 confirmations

            MyRemoteWallet wallet = getWalletNoLock();

            for (int ii = 0; ii < 2; ++ii) {
                try {
                    wallet.doMultiAddr();

                    break;
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

            final List<String> toCombineAddresses = new ArrayList<>();

            BigInteger value = BigInteger.ZERO;


            boolean addedAddressForFee = false;
            for (String address : wallet.getActiveAddresses()) {
                final BigInteger balance = wallet.getBalance(address);

                if (!addedAddressForFee && balance.compareTo(BigInteger.valueOf(SharedCoin.COIN)) >= 0) {

                    if (SharedCoin.isAddressInUse(address) || SharedCoin.isAddressTargetOfAnActiveOutput(address) || isAddressWeRecentlySpent(address)) {
                        continue;
                    }

                    toCombineAddresses.add(address);

                    addedAddressForFee = true;

                    value = value.add(balance);

                } else if (balance.compareTo(BigInteger.ZERO) > 0 && balance.compareTo(BigInteger.valueOf(CombineDustMinimumOutputSize)) <= 0 && toCombineAddresses.size() < 10) {

                    Logger.log(Logger.SeverityINFO, "Dust Address " + address + " " + balance);

                    if (SharedCoin.isAddressInUse(address) || SharedCoin.isAddressTargetOfAnActiveOutput(address) || isAddressWeRecentlySpent(address)) {
                        continue;
                    }

                    toCombineAddresses.add(address);

                    value = value.add(balance);
                }
            }

            if (toCombineAddresses.size() <= 2) {
                return;
            }

            if (toCombineAddresses.size() >= 10) {
                _scheduleCombineDust = true;
            }

            final BigInteger fee = SharedCoin.TransactionFeePer1000Bytes.multiply(BigInteger.valueOf(Math.round(toCombineAddresses.size() / 1.5)));


            final String destination = getRandomAddressNoLock().toString();

            Logger.log(Logger.SeverityWARN, "combineDust() Send From [" + toCombineAddresses + "] to destination " + destination);

            addressesWeRecentlySpent.addAll(toCombineAddresses);

            if (wallet.send(toCombineAddresses.toArray(new String[]{}), destination, value.divide(BigInteger.valueOf(2)), fee)) {
                Logger.log(Logger.SeverityINFO, "Combine Dust wallet.send returned true");
            } else {
                Logger.log(Logger.SeverityError, "Combine Dust wallet.send returned false");
            }
        } finally {
            lock.unlock();
        }
    }

    public synchronized void divideLargeOutputs() throws Exception {
        Lock lock = updateLock.writeLock();

        lock.lock();
        try {
            //Do multiaddr
            //Archive ZERO balance addresses with more than one transaction
            //Delete archived addresses with transactions > 6 confirmations
            final MyRemoteWallet wallet = getWalletNoLock();

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

                    long split = (long) ((balance.longValue() / 2) * (Math.random() + 0.5));

                    String destination = getRandomAddressNoLock().toString();

                    Logger.log(Logger.SeverityWARN, "divideLargeOutputs() Send From [" + address + "] to destination " + destination + " value " + split);

                    if (SharedCoin.isAddressInUse(address) || SharedCoin.isAddressTargetOfAnActiveOutput(address) || isAddressWeRecentlySpent(address)) {
                        continue;
                    }

                    addressesWeRecentlySpent.add(address);

                    wallet.send(new String[]{address}, destination, BigInteger.valueOf(split), SharedCoin.TransactionFeePer1000Bytes);

                    break;
                }
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
            wallet.addKey(key, null, Math.random() >= 0.5, "sharedcoin", "" + SharedCoin.ProtocolVersion);
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

            String compressed = key.toAddressCompressed(NetworkParameters.prodNet()).toString();

            String returnVal = wallet.addKey(key, null, !address.equals(compressed), "sharedcoin", "" + SharedCoin.ProtocolVersion);

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

        //Archive any 0 balance addreses
        for (String address : allActiveAddresses) {
            final BigInteger balance = multiAddrWallet.getBalance(address);
            final int n_tx = multiAddrWallet.getNtx(address);

            if (balance.compareTo(BigInteger.valueOf(ForceDivideLargeOutputSize)) >= 0) {
                _scheduleDivideLargeOutputs = true;
            }

            if (balance.compareTo(BigInteger.valueOf(CombineDustMinimumOutputSize)) <= 0) {
                _scheduleCombineDust = true;
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
        } else {
            //Generate New Addresses To Fill the wallet
            int nAddressToCreate = TargetNumberActiveAddresses - (allActiveAddresses.length - pendingOperations.calculateNArchived());

            //Logger.log(Logger.SeverityWARN, "Tidy Wallet: Generate " + nAddressToCreate + " new addresses");

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
