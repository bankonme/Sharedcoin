package piuk;

import org.bitcoinj.core.*;

public class MyTransactionInput extends TransactionInput {
	private static final long serialVersionUID = 1L;
	
	public String address;
	public Coin value;
	public NetworkParameters params;
	
	public MyTransactionInput(NetworkParameters params, Transaction parentTransaction, byte[] scriptBytes, TransactionOutPoint outpoint) {
		super(params, parentTransaction, scriptBytes, outpoint);
		
		this.params = params;
	}
 
	@Override
	public Address getFromAddress() {
		try {
			return new Address(params, address);
		} catch (AddressFormatException e) {
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public Coin getValue() {
		return value;
	}

	public void setValue(Coin value) {
		this.value = value;
	}
}