<%@ page language="java" session="false" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>

<!DOCTYPE html><html>
<head>
    <title>Shared Coin Status.</title>

    <style type="text/css">
        table {
            width:100%;
            border-width:1px;
            border-style:solid;
            margin:20px;
            box-sizing:border-box;
        }

        .container {
            width:90%;
        }
    </style>
    <meta http-equiv="refresh" content="5" >
</head>
<body>
<div class="container">

    <c:if test="${initial_error != null}">
    <div class="alert alert-block alert-error" id="initial_error"><c:out escapeXml="true"
                                                                         value="${initial_error}"/></div>
    </c:if>

    <c:if test="${initial_success != null}">
    <div class="alert alert-block alert-success" id="initial_success"><c:out escapeXml="true"
                                                                             value="${initial_success}"/></div>
    </c:if>

    <h3 class="page-header">Pending Offers <small>(${pending_offers.size()})</small></h3>

    <table class="table table-striped">
        <tr>
            <th>ID</th>
            <th>Offered Inputs</th>
            <th>Requested Outputs</th>
            <th>Fee</th>
            <th>Received Time</th>
        </tr>
        <c:forEach var="offer" items="${pending_offers}">
            <tr>
                <td>
                        ${offer.offerID}
                </td>
                <td><ul>
                    <c:forEach var="outpoint" items="${offer.offeredOutpoints}">
                        <li><a href="https://blockchain.info/tx/${outpoint.hash}/${outpoint.index}" target="blank">${outpoint.hash.toString().substring(0, 10)}...</a> ${outpoint.value}</li>
                    </c:forEach>
                </ul></td>
                <td><ul>
                    <c:forEach var="output" items="${offer.requestedOutputs}">
                        <li><a href="https://blockchain.info/address/${output.address}" target="blank">${output.address}...</a> ${output.value}</li>
                    </c:forEach>
                </ul></td>
                <td>
                        ${offer.calculateFee()}
                </td>
                <td>
                        ${offer.receivedTime}
                </td>

            </tr>
        </c:forEach>
    </table>

    <div align="right">
        <form style="display:inline-block;margin:0px;" action="/" method="POST">
            <input type="hidden" value="create_proposals" name="method">
            <button class="btn btn-secondary" name="submit" value="true">Create Proposals Now</button>
        </form>
    </div>

    <h3 class="page-header">Active Proposals <small>(${active_proposals.size()})</small></h3>
    <table class="table table-striped">
        <tr>
            <th>ID</th>
            <th>Inputs</th>
            <th>Outputs</th>
            <th>Network Fee</th>
            <th>Signing Progress</th>
            <th>Created Time</th>
        </tr>
        <c:forEach var="proposal" items="${active_proposals}">
            <tr>
                <td>${proposal.proposalID}</td>
                <td><ul>
                    <c:forEach var="outpoint" items="${proposal.transactionOutpoints}">
                        <li><a href="https://blockchain.info/tx/${outpoint.hash}/${outpoint.index}">${outpoint.hash.toString().substring(0, 10)}...</a> ${outpoint.value}</li>
                    </c:forEach>
                </ul></td>
                <td><ul>
                    <c:forEach var="output" items="${proposal.transactionOutputs}">
                        <li><a href="https://blockchain.info/address/${output.address}">${output.address}...</a> ${output.value}</li>
                    </c:forEach>
                </ul></td>
                <td>
                        ${proposal.transactionFee}
                </td>
                <td>
                        ${proposal.getNSigned()} of ${proposal.getNSignaturesNeeded()}
                </td>
                <td>
                        ${proposal.createdTime}
                </td>
            </tr>
        </c:forEach>
    </table>

    <div align="right">
        <form style="display:inline-block;margin:0px;" action="/" method="POST">
            <input type="hidden" value="finalize_and_push_signed" name="method">
            <button class="btn btn-secondary" name="submit" value="true">Finalize and Push Signed</button>
        </form>
    </div>

    <h3 class="page-header">Recently Completed Transactions <small>(${recently_completed_transactions.size()})</small></h3>
    <table class="table table-striped">
        <tr>
            <th>ID</th>
            <th>Transaction Hash</th>
            <th>Status</th>
        </tr>
        <c:forEach var="completedTransaction" items="${recently_completed_transactions}">
            <tr>
                <td>${completedTransaction.proposalID}</td>
                <td><a href="https://blockchain.info/tx/${completedTransaction.transaction.hash}" target="blank">${completedTransaction.transaction.hash.toString().substring(0, 10)}...</a></td>
                <td><c:choose><c:when test="${completedTransaction.isConfirmed}"><font color="blue">(C)</font></c:when><c:otherwise><font color="red">(U)</font></c:otherwise></c:choose></td>
            </tr>
        </c:forEach>
    </table>

    <p>
        Total Participants : ${total_participants}<br />
        Average Participants : ${average_participants}<br />
        Total Output Value : ${total_output_value} BTC <br />
    </p>
</body>
</html>