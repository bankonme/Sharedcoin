<%@ page language="java" session="false" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>

<!DOCTYPE html><html>
<head>
    <title>Shared Coin Admin.</title>

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
</head>
<body>
<div class="container">

    <c:if test="${initial_error != null}">
    <div class="alert alert-block alert-error" id="initial_error"><c:out escapeXml="true" value="${initial_error}"/></div>
    </c:if>

    <c:if test="${initial_success != null}">
    <div class="alert alert-block alert-success" id="initial_success"><c:out escapeXml="true" value="${initial_success}"/></div>
    </c:if>

    <h3 class="page-header">Methods</h3>

    <form style="display:inline-block;margin:0px;" action="/sharedcoin-admin" method="POST">
        <input type="hidden" value="git_pull_and_restart" name="method">
        <button class="btn btn-secondary" name="submit" value="true">Git Pull And Restart</button>
    </form>

    <form style="display:inline-block;margin:0px;" action="/sharedcoin-admin" method="POST">
        <input type="hidden" value="tidy_wallet" name="method">
        <button class="btn btn-secondary" name="submit" value="true">Tidy The Wallet</button>
    </form>

    <form style="display:inline-block;margin:0px;" action="/sharedcoin-admin" method="POST">
        <input type="hidden" value="divide_large_outputs" name="method">
        <button class="btn btn-secondary" name="submit" value="true">Divide Large Outputs</button>
    </form>

    <form style="display:inline-block;margin:0px;" action="/sharedcoin-admin" method="POST">
        <input type="hidden" value="print_unspent" name="method">
        <button class="btn btn-secondary" name="submit" value="true">Print Unspent Outputs</button>
    </form>

    <form style="display:inline-block;margin:0px;" action="/sharedcoin-admin" method="POST">
        <input type="hidden" value="check_seeded_private_keys" name="method">
        <button class="btn btn-secondary" name="submit" value="true">Check Seeded Private Keys</button>
    </form>

    <form style="display:inline-block;margin:0px;" action="/sharedcoin-admin" method="POST">
        <input type="hidden" value="check_deleted_private_keys_log" name="method">
        <button class="btn btn-secondary" name="submit" value="true">Check Delete Private Keys Log</button>
    </form>

    <form style="display:inline-block;margin:0px;" action="/sharedcoin-admin" method="POST">
        <input type="hidden" value="toggle_info_log" name="method">
        <button class="btn btn-secondary" name="submit" value="true">Toggle Info Logger</button>
    </form>
    <p>
        <a href="/sharedcoin-admin?method=threads">View Threads</a>
    </p>

    <h3 class="page-header">Output</h3>

    <p>
        <a href="/sharedcoin-admin?method=clear">Clear Output</a>
    </p>

    <iframe name='output_frame' src="/sharedcoin-admin?method=show" frameborder="1" width='100%' height='800'></iframe>
</body>
</html>