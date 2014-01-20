package piuk;

import com.google.bitcoin.core.*;

import java.math.BigInteger;

public class MyTransactionOutput extends TransactionOutput {
	private static final long serialVersionUID = 1L;

	String address;
	NetworkParameters params;
    byte[] scriptBytes;
    boolean isSpent = false;

    MyTransactionOutput(NetworkParameters params, Transaction parent,
			BigInteger value, Address to, byte[] scriptBytes) {
		super(params, parent, value, to);

		this.params = params;
		this.address = to.toString();
        this.scriptBytes = scriptBytes;
	}

    public boolean isSpent() {
        return isSpent;
    }

    public Address getToAddress() {
		try {
			return new Address(params, address);
		} catch (AddressFormatException e) {
			e.printStackTrace();
		}

		return null;
	}

    @Override
    public com.google.bitcoin.core.Script getScriptPubKey() throws com.google.bitcoin.core.ScriptException {
        return new Script(NetworkParameters.prodNet(), scriptBytes, 0, scriptBytes.length);
    }

    @Override
    public byte[] getScriptBytes() {
       return scriptBytes;
    }


}