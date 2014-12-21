package piuk;

import org.bitcoinj.core.*;
import org.bitcoinj.script.Script;

import java.math.BigInteger;

public class MyTransactionOutput extends TransactionOutput {
	private static final long serialVersionUID = 1L;

	String address;
	NetworkParameters params;
    byte[] scriptBytes;
    boolean isSpent = false;

    MyTransactionOutput(NetworkParameters params, Transaction parent,
			Coin value, Address to, byte[] scriptBytes) {
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
    public Script getScriptPubKey() throws ScriptException {
        return new Script(scriptBytes);
    }

    @Override
    public byte[] getScriptBytes() {
       return scriptBytes;
    }


}