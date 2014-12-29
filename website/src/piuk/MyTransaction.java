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

import org.bitcoinj.core.*;
import org.spongycastle.util.encoders.Hex;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Date;
import java.util.List;
import java.util.Map;

public class MyTransaction extends Transaction implements Serializable {
	private static final long serialVersionUID = 1L;
	public Sha256Hash hash;
	public Date time;
	public String tag;
	public int height;
	public boolean double_spend;
	public int txIndex;
	public BigInteger result;
	public long version;

	public static long getSerialversionuid() {
		return serialVersionUID;
	}

	public Date getTime() {
		return time;
	}

	public int getHeight() {
		return height;
	}

	public boolean isDouble_spend() {
		return double_spend;
	}

	public int getTxIndex() {
		return txIndex;
	}

	public BigInteger getResult() {
		return result;
	}

	public String getTag() {
		return tag;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + txIndex;
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (!super.equals(obj))
			return false;
		if (getClass() != obj.getClass())
			return false;
		MyTransaction other = (MyTransaction) obj;
		if (txIndex != other.txIndex)
			return false;
		return true;
	}

	@Override
	public boolean hasConfidence() {
		return true;
	}

	public MyTransaction(NetworkParameters params, long version, Sha256Hash hash) {
		super(params);

		this.hash = hash;
		this.version = version;
	}

	public void setTxIndex(int txIndex) {
		this.txIndex = txIndex;
	}

	@Override
	public Date getUpdateTime() {
		return time;
	}

	@Override
	public long getVersion() {
		return version;
	}

	@Override
	public Sha256Hash getHash() {
		return hash;
	}

	@SuppressWarnings("unchecked")
	public static MyTransaction fromJSONDict(Map<String, Object> transactionDict)
			throws Exception {

		Sha256Hash hash = new Sha256Hash(Hex.decode((String) transactionDict
				.get("hash")));
		BigInteger result = BigInteger.ZERO;

		if (transactionDict.get("result") != null)
			result = BigInteger
					.valueOf(((Number) transactionDict.get("result"))
							.longValue());

		int height = 0;
		boolean double_spend = false;

		if (transactionDict.get("block_height") != null) {
			height = ((Number) transactionDict.get("block_height")).intValue();
		}

		if (transactionDict.get("double_spend") != null) {
			double_spend = ((Boolean) transactionDict.get("double_spend"))
					.booleanValue();
		}

		int txIndex = ((Number) transactionDict.get("tx_index")).intValue();

		MyTransaction tx = new MyTransaction(NetworkParameters.prodNet(), 1,
				hash);

		tx.height = height;

		tx.double_spend = double_spend;

		tx.txIndex = txIndex;

		tx.result = result;

		Number time = (Number) transactionDict.get("time");
		if (time != null) {
			tx.time = new Date(time.longValue() * 1000);
		} else {
			tx.time = new Date(0);
		}

		List<Map<String, Object>> inputs = (List<Map<String, Object>>) transactionDict
				.get("inputs");
		for (Map<String, Object> inputDict : inputs) {

			Map<String, Object> prev_out_dict = (Map<String, Object>) inputDict
					.get("prev_out");

			if (prev_out_dict == null)
				continue;

			int txOutputN = 0;
			if (prev_out_dict.get("n") != null)
				txOutputN = ((Number) prev_out_dict.get("n")).intValue();

			if (tx.tag == null)
				tx.tag = (String) prev_out_dict.get("addr_tag");

			TransactionOutPoint outpoint = new TransactionOutPoint(NetworkParameters.prodNet(), txOutputN, (Transaction) null);


            byte[] scriptBytes = null;
            String scriptHex = (String)inputDict.get("script");
            if (scriptHex != null) {
                scriptBytes = Hex.decode(scriptHex);
            }

			MyTransactionInput input = new MyTransactionInput(NetworkParameters.prodNet(), null, scriptBytes, outpoint);

			if ((String) prev_out_dict.get("addr") != null)
				input.address = new Address(NetworkParameters.prodNet(),
						(String) prev_out_dict.get("addr")).toString();

			if ((Number) prev_out_dict.get("value") != null)
				input.value = Coin.valueOf(((Number) prev_out_dict
						.get("value")).longValue());

			tx.addInput(input);
		}

		List<Map<String, Object>> outputs = (List<Map<String, Object>>) transactionDict
				.get("out");
		for (Map<String, Object> outDict : outputs) {

			if (tx.tag == null)
				tx.tag = (String) outDict.get("addr_tag");

			Coin value = Coin.valueOf(((Number) outDict
					.get("value")).longValue());

			Address addr = new Address(NetworkParameters.prodNet(),
					(String) outDict.get("addr"));

            byte[] scriptBytes = null;
            String scriptHex = (String)outDict.get("script");
            if (scriptHex != null) {
                scriptBytes = Hex.decode(scriptHex);
            }

            boolean spent = outDict.get("spent") != null && outDict.get("spent").equals("true");

			MyTransactionOutput output = new MyTransactionOutput(NetworkParameters.prodNet(), null, value, addr, scriptBytes);

            output.isSpent = spent;

			tx.addOutput(output);
		}

		return tx;
	}
}