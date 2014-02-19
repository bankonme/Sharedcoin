package piuk;


import com.google.bitcoin.core.Transaction;
import com.google.bitcoin.core.TransactionInput;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import piuk.website.AdminServlet;
import piuk.website.SharedCoin;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

//TODO much room for improvement
public class DOSManager {
    public static class RequestContainer {
        public String method;
        public long start_time;
        public long end_time;
        public int http_status_code;

        public long getRequestDuration() {
            if (end_time == 0)
                return 0;

            return end_time-start_time;
        }

        public boolean hasFinished() {
            return end_time != 0;
        }

        public void didFinishRequest(HttpServletResponse res) {
            http_status_code = res.getStatus();
            end_time = System.currentTimeMillis();
        }

        @Override
        public String toString() {
            return "RequestContainer{" +
                    "method='" + method + '\'' +
                    ", start_time=" + start_time +
                    ", end_time=" + end_time +
                    ", duration=" + getRequestDuration() +
                    ", finished=" + hasFinished() +
                    ", http_status_code=" + http_status_code +
                    '}';
        }
    }

    private static final Cache<String, String> _ipAddressesWhichRefusedToSign = CacheBuilder.newBuilder()
            .maximumSize(10000)
            .expireAfterWrite(4, TimeUnit.HOURS).build();

    private static final Cache<String, List<RequestContainer>> _latestRequests = CacheBuilder.newBuilder()
            .maximumSize(10000)
            .expireAfterWrite(10, TimeUnit.MINUTES).build();

    public static List<RequestContainer> getRequestList(HttpServletRequest req) {
        String hashedIP = null;
        try {
            hashedIP = Util.SHA256Hex(AdminServlet.getRealIP(req));
        } catch (Exception e) {
            e.printStackTrace();
        }

        return _latestRequests.asMap().get(hashedIP);
    }

    public synchronized static RequestContainer registerRequestStart(HttpServletRequest req) throws Exception {
        final String hashedIP = Util.SHA256Hex(AdminServlet.getRealIP(req));

        List<RequestContainer> requestList = _latestRequests.asMap().putIfAbsent(hashedIP, new CopyOnWriteArrayList<RequestContainer>());

        int pendingRequests = 0;
        for (RequestContainer requestContainer : requestList) {
            if (!requestContainer.hasFinished()) {
                ++pendingRequests;
            }
        }

        if (pendingRequests >= 2) {
            throw new Exception("Maximum Simultaneous Requests Reached");
        }

        RequestContainer container = new RequestContainer();

        String method = req.getParameter("method");

        container.start_time = System.currentTimeMillis();

        if (method != null && method.length() < 255)
            container.method = method;
        else
            container.method = "Unknown";

        if (requestList.size() >= 20) {
            requestList.remove(requestList.size()-1);
        }

        requestList.add(0, container);

        return container;
    }

    public static void failedToSignProposal(SharedCoin.Proposal proposal) {
        Transaction tx = proposal.getTransaction();

        if (tx == null) {
            return;
        }

        int index = 0;
        for (TransactionInput input : tx.getInputs()) {

            Hash outpointHash = new Hash(input.getOutpoint().getHash().getBytes());
            long outpointIndex = input.getOutpoint().getIndex();

            //If the index key is missing then no signature was submitted
            if (!proposal.getInput_scripts().containsKey(index)) {

                for (SharedCoin.Offer offer : proposal.getOffers()) {
                    for (SharedCoin.OutpointWithValue outpointWithValue : offer.getOfferedOutpoints()) {
                        if (outpointWithValue.getHash().equals(outpointHash) && outpointWithValue.getIndex() == outpointIndex) {
                            Logger.log(Logger.SeverityWARN, "IP Failed To Sign Proposal " + offer.getHashedUserIP());

                            //This is the offer which requested that outpoint but refused to sign
                            //Log it as the offender
                            _ipAddressesWhichRefusedToSign.put(offer.getHashedUserIP(), offer.getHashedUserIP());
                            break;
                        }
                    }
                }
            }

            ++index;
        }
    }

    public static boolean hasHashedIPFailedToSign(String hashedIP) {
        return _ipAddressesWhichRefusedToSign.asMap().containsKey(hashedIP);
    }
}
