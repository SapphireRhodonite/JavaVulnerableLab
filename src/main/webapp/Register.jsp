<%@ include file="header.jsp" %>
<%@page import="java.util.UUID"%>
<%@page import="org.owasp.encoder.Encode"%>

<%
    String csrfToken = (String) session.getAttribute("csrfToken");
    if (csrfToken == null) {
        csrfToken = UUID.randomUUID().toString();
        session.setAttribute("csrfToken", csrfToken);
    }
%>

<script type="text/javascript">
    $(document).ready(function(){
        $("#username").change(function(){
            $("#status").html("");
        });

        $("#email").change(function(){
            $("#emailStatus").html("");
        });
    });
</script>

<form action="AddUser" method="post" autocomplete="off">
    <input type="hidden" name="csrfToken" value="<%= Encode.forHtmlAttribute(csrfToken) %>" />
    <table>
        <tr>
            <td>UserName: </td>
            <td><input type="text" name="username" id="username" maxlength="50" /></td>
            <td><span id="status"></span></td>
        </tr>
        <tr>
            <td>Email:</td>
            <td><input type="email" name="email" id="email" maxlength="254" /></td>
            <td><span id="emailStatus"></span></td>
        </tr>
        <tr>
            <td>Describe Yourself:</td>
            <td><input type="text" name="About" maxlength="500" /></td>
        </tr>
        <tr>
            <td>What's Your Pet's name?:</td>
            <td><input type="text" name="secret" maxlength="100" /></td>
        </tr>
        <tr>
            <td>Password :</td>
            <td><input type="password" name="password" maxlength="128" /></td>
        </tr>
        <tr>
            <td><input type="submit" name="Register" value="Register"/></td>
        </tr>
    </table>
</form>

<%@ include file="footer.jsp" %>
