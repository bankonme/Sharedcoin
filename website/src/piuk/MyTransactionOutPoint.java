package piuk;

import java.math.BigInteger;


import com.google.bitcoin.core.*;
import piuk.website.SharedCoin;

//Very messy
public class MyTransactionOutPoint extends TransactionOutPoint {
	private static final long serialVersionUID = 1L;
	private final byte[] scriptBytes;
	private final int txOutputN;
	private final Sha256Hash txHash;
	private final BigInteger value;
	int confirmations;

	String _stringCache = null;
	String _addressCache = null;

	public MyTransactionOutPoint(Sha256Hash txHash, int txOutputN, BigInteger value, byte[] scriptBytes) throws ProtocolException {
		super(NetworkParameters.prodNet(), txOutputN, new Sha256Hash(txHash.getBytes()));
		this.scriptBytes = scriptBytes;
		this.value = value;
		this.txOutputN = txOutputN;
		this.txHash = txHash;
	}

	public String getAddress() {
		if (_addressCache == null) {
			try {
				final Script script = SharedCoin.newScript(this.getScriptBytes());

				final Address address = script.getToAddress();

				_addressCache = address.toString();
			} catch (Exception e) {
				Logger.log(Logger.SeveritySeriousError, e);
			}
		}

		return _addressCache;
	}

	public int getConfirmations() {
		return confirmations;
	}

	public byte[] getScriptBytes() {
		return scriptBytes;
	}

	public int getTxOutputN() {
		return txOutputN;
	}

	public Sha256Hash getTxHash() {
		return txHash;
	}

	public BigInteger getValue() {
		return value;
	}

	public void setConfirmations(int confirmations) {
		this.confirmations = confirmations;
	}

	@Override
	public TransactionOutput getConnectedOutput() {		       
		return new TransactionOutput(params, null, value, scriptBytes);
	}

	@Override
	public byte[] getConnectedPubKeyScript() {
		return scriptBytes;
	}

	@Override
	public String toString() {
		if (_stringCache == null) {
			_stringCache = super.toString();
		}
		return _stringCache;
	}
}