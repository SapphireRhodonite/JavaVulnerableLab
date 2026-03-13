<%@page import="org.cysecurity.cspf.jvl.model.DBConnect"%>
<%@page import="java.sql.PreparedStatement"%>
<%@page import="java.sql.ResultSet"%>
<%@page import="java.sql.Connection"%>
<%@page import="org.owasp.encoder.Encode"%>
<%@ include file="header.jsp" %>

<script type="text/javascript">
    $(document).ready(function(){
        $("#username").change(function(){
            $("#status").html("");
        });
    });
</script>

Password Recovery:
<form action="ForgotPassword.jsp" method="post" autocomplete="off">
<table>
<tr>
    <td>Username: </td>
    <td><input type="text" name="username" id="username"/></td>
    <td><span id="status"></span></td>
</tr>
<tr>
    <td>What's Your Pet's name?: </td>
    <td><input type="text" name="secret" /></td>
</tr>
<tr>
    <td><input type="submit" name="GetPassword" value="GetPassword"/></td>
</tr>
</table>
</form>
<br/>

<%
if (request.getParameter("secret") != null) {
    String username = request.getParameter("username");
    String secret = request.getParameter("secret");

    if (username == null) username = "";
    if (secret == null) secret = "";

    username = username.trim();
    secret = secret.trim();

    if (!username.isEmpty() && !secret.isEmpty()) {
        String sql = "SELECT username FROM users WHERE username = ? AND secret = ?";

        try (
            Connection con = new DBConnect().connect(getServletContext().getRealPath("/WEB-INF/config.properties"));
            PreparedStatement ps = con.prepareStatement(sql)
        ) {
            ps.setString(1, username);
            ps.setString(2, secret);

            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    out.print("<b class='success'>If the provided information is correct, your recovery request has been processed.</b>");
                } else {
                    out.print("<b class='fail'>Invalid recovery information.</b>");
                }
            }
        } catch (Exception e) {
            out.print("<b class='fail'>Something went wrong.</b>");
        }
    } else {
        out.print("<b class='fail'>Please provide the required information.</b>");
    }
}
%>

<%@ include file="footer.jsp" %>
