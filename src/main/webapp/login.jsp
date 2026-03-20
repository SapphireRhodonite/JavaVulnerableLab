<%@ include file="header.jsp" %>
<%@ page import="javax.servlet.http.Cookie" %>

<%!
    private String escapeHtml(String input) {
        if (input == null) return "";
        return input.replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                    .replace("\"", "&quot;")
                    .replace("'", "&#x27;");
    }
%>

<%
String username = "";
String err = "";

Cookie[] cookies = request.getCookies();
if (cookies != null) {
    for (Cookie c : cookies) {
        if ("username".equals(c.getName())) {
            username = c.getValue();
        }
    }
}

if (request.getParameter("err") != null) {
    err = request.getParameter("err");
}

String safeUsername = escapeHtml(username);
String safeErr = escapeHtml(err);
%>

<form action="LoginValidator" method="post">
<table>
    <tr>
        <td>UserName:</td>
        <td><input type="text" name="username" value="<%= safeUsername %>" /></td>
    </tr>
    <tr>
        <td>Password :</td>
        <td><input type="password" name="password" value="" /></td>
    </tr>
    <tr>
        <td>Remember me:</td>
        <td><input type="checkbox" name="RememberMe" checked /></td>
    </tr>
    <tr>
        <td><input type="submit" name="Login" value="Login" /></td>
    </tr>
    <tr>
        <td></td>
        <td class="fail"><%= safeErr %></td>
    </tr>
</table>
</form>

<br/>
<a href="ForgotPassword.jsp">Forgot Password?</a>

<%@ include file="footer.jsp" %>
