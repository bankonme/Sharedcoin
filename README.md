# Sharedcoin

Sharedcoin is a implementation of coinjoin which in addition to mixing with other participants mixes with a server pool as well.

More information - http://sharedcoin.com/

Use Sharedcoin - https://blockchain.info/wallet

Javascript client - https://github.com/blockchain/My-Wallet/blob/master/sharedcoin.js

## Settings

Replace the values in settings_global_example.json as instructed. Rename the file to settings_global.json

## Running Your Own Server

You will need an installation of Apache Tomcat and Orcale JDK. For the sharedcoin wallet it is recommended you keep at minimum 10 * Max Output Value in the wallet pool (Default Max Output Value 50 BTC). 

Linux Recommended

## Client Flow

- Client calls get_info which returns information on fees and maximum send values used to populate the send form
- User enters send amount and value
- Client fetches the unspent outputs of the user's wallet
- Client constructs the first offer. An offer is a series of inputs and & requested outputs to be submitted to the sharedcoin server. The first offer consumes a number of unspent outputs from the users wallet sends the desired send amount to a newly generated address + fees and returns the change back to the wallet.
- Client constructs an additional offer for each repetition. Each offer splits outputs into a various N different sizes. Offers spend the outputs generated from executing the previous offer. The last repitition/offer sends the coins to the desired send address.
- Client creates an array of offers called a plan.
- Client executes the offers in sequential order. If any offer fails to execute it can be retried a number of times.
- After continual failures the client adds the temporary addresses generated in the previous offer back into the users wallet and displays an error. Server errors are always plain/text error 500.

## Server Parameters

Endpoint : https://api.sharedcoin.com

### All Requests

version = The client version number (current = 3)
method = The method or action to perform (see below)

### Methods

get_info
	No Parameters

submit_offer
		offer = a JSON encoded offer object
		token = A token from retrieved from get_info
		fee_percent = Requested fee percent. Can only be higher than fee percent retreived from get_info.
		offer_max_age = (Optional) Maximum time in milliseconds the client is willing to wait for an offer to be executed by the server.

	Returns
		 A JSON object containing an Offer ID

get_offer_id
		offer_id = An offer ID retreived from submit_offer

	Returns a status object 
		"waiting" = means to retry the request
		"not_found" = Offer ID was not recognised. Fatal error, resubmit the offer.
		"active_proposal" = An active proposal has been found. The object will also contain a proposal_id for the next stage.

get_proposal_id
		proposal_id = The proposal ID from get_offer_id
		offer_id = The Offer ID from submit_offer

	Returns a status object 
		"completed" = The Proposal has already been completed. A tx_hash & tx will be returned.
		"signatures_needed" = The client is required to submit a number of signatures by signing the attached tx data.

submit_signatures
		proposal_id = The proposal ID from get_offer_id
		offer_id = The Offer ID from submit_offer
		input_scripts = A number of JSON encoded signature scripts

	Returns a status object 
		"not_found" = Proposal ID was not recognised. Resubmit the current offer.
		"completed" = The proposal is complete. Client should submit the next offer.
		"verification_failed" = signature verification failed. Can retry but probably fatal.
		"signatures_accepted" = All good. Proceed to poll_for_proposal_completed.

poll_for_proposal_completed
		proposal_id = The proposal ID from get_offer_id 

	Returns a status object 
		"waiting" = means to retry the request
		"not_found" = Proposal ID was not recognised. Fatal error, resubmit the current offer.
		"completed" = The proposal is complete. Client should submit the next offer.






