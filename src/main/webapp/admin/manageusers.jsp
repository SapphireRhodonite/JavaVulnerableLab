<%@ include file="/header.jsp" %>
<%@ page import="java.sql.Connection" %>
<%@ page import="java.sql.PreparedStatement" %>
<%@ page import="java.sql.ResultSet" %>
<%@ page import="java.sql.SQLException" %>
<%@ page import="org.cysecurity.cspf.jvl.model.DBConnect" %>

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
Connection con = null;
PreparedStatement deletePs = null;
PreparedStatement selectPs = null;
ResultSet rs = null;

try {
    con = new DBConnect().connect(getServletContext().getRealPath("/WEB-INF/config.properties"));

    if (con == null || con.isClosed()) {
        out.print("<b class='error'>Database connection error</b>");
    } else {

        if (request.getParameter("delete") != null) {
            String user = request.getParameter("user");
            user = (user == null) ? "" : user.trim();

            if (!user.matches("[A-Za-z0-9_\\-]{1,30}")) {
                out.print("<b class='error'>Invalid username</b><br/><br/>");
            } else {
                deletePs = con.prepareStatement("DELETE FROM users WHERE username = ?");
                deletePs.setString(1, user);
                deletePs.executeUpdate();
                out.print("<b class='success'>User deleted</b><br/><br/>");
            }
        }
%>

<form action="manageusers.jsp" method="POST">
<%
        selectPs = con.prepareStatement("SELECT username FROM users WHERE privilege = ?");
        selectPs.setString(1, "user");
        rs = selectPs.executeQuery();

        while (rs.next()) {
            String username = rs.getString("username");
            String safeUsernameHtml = escapeHtml(username);
%>
    <input type="radio" name="user" value="<%= safeUsernameHtml %>" />
    <%= safeUsernameHtml %><br/>
<%
        }
%>
    <br/>
    <input type="submit" value="Delete" name="delete"/>
</form>
<br/>
<a href="admin.jsp">Back to Admin Panel</a>

<%
    }
} catch (SQLException ex) {
    log("Database error in manageusers.jsp", ex);
    out.print("<b class='error'>A database error occurred</b>");
} catch (Exception ex) {
    log("Unexpected error in manageusers.jsp", ex);
    out.print("<b class='error'>Something went wrong</b>");
} finally {
    try { if (rs != null) rs.close(); } catch (SQLException ignore) {}
    try { if (selectPs != null) selectPs.close(); } catch (SQLException ignore) {}
    try { if (deletePs != null) deletePs.close(); } catch (SQLException ignore) {}
    try { if (con != null) con.close(); } catch (SQLException ignore) {}
}
%>

<%@ include file="/footer.jsp" %>
