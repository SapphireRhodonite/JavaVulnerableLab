<%@page import="org.cysecurity.cspf.jvl.model.HashMe"%>
<%@page import="java.sql.PreparedStatement"%>
<%@page import="java.sql.ResultSet"%>
<%@page import="java.sql.SQLException"%>
<%@page import="org.cysecurity.cspf.jvl.model.DBConnect"%>
<%@page import="java.sql.Connection"%>
<%@page import="javax.servlet.http.Cookie"%>
<%@page import="javax.servlet.http.HttpSession"%>
<%@page import="org.owasp.encoder.Encode"%>

<%!
    private String safeAvatar(String avatar) {
        if (avatar == null || avatar.trim().isEmpty()) {
            return "default.jpg";
        }

        String cleaned = avatar.trim();

        if (cleaned.matches("[A-Za-z0-9._\\-]{1,100}\\.(jpg|jpeg|png|gif)$")) {
            return cleaned;
        }

        return "default.jpg";
    }
%>

<%
String errorMessage = null;
boolean isPost = "POST".equalsIgnoreCase(request.getMethod());

if (isPost && request.getParameter("Login") != null) {
    String user = request.getParameter("username");
    String rawPassword = request.getParameter("password");

    if (user == null) user = "";
    if (rawPassword == null) rawPassword = "";

    user = user.trim();
    rawPassword = rawPassword.trim();

    if (!user.isEmpty() && !rawPassword.isEmpty()) {
        String pass = HashMe.hashMe(rawPassword);
        String sql = "SELECT id, username, avatar FROM users WHERE username = ? AND password = ? AND privilege = ?";

        try (
            Connection con = new DBConnect().connect(getServletContext().getRealPath("/WEB-INF/config.properties"));
            PreparedStatement ps = con.prepareStatement(sql)
        ) {
            ps.setString(1, user);
            ps.setString(2, pass);
            ps.setString(3, "admin");

            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    HttpSession oldSession = request.getSession(false);
                    if (oldSession != null) {
                        oldSession.invalidate();
                    }

                    String dbUserId = rs.getString("id");
                    String dbUsername = rs.getString("username");
                    String dbAvatar = rs.getString("avatar");

                    if (dbUserId == null) dbUserId = "";
                    if (dbUsername == null) dbUsername = "";

                    HttpSession newSession = request.getSession(true);
                    newSession.setAttribute("isLoggedIn", "1");
                    newSession.setAttribute("userid", dbUserId);
                    newSession.setAttribute("user", dbUsername);
                    newSession.setAttribute("avatar", safeAvatar(dbAvatar));
                    newSession.setAttribute("privilege", "admin");

                    Cookie privilege = new Cookie("privilege", "admin");
                    privilege.setHttpOnly(true);
                    privilege.setSecure(request.isSecure());
                    privilege.setPath(request.getContextPath().isEmpty() ? "/" : request.getContextPath());
                    response.addCookie(privilege);

                    response.sendRedirect("admin.jsp");
                    return;
                } else {
                    errorMessage = "Username or password is wrong";
                }
            }
        } catch (SQLException ex) {
            errorMessage = "Something went wrong";
        } catch (Exception e) {
            errorMessage = "Something went wrong";
        }
    } else {
        errorMessage = "Username and password are required";
    }
}
%>

<%@ include file="/header.jsp" %>
<b>Admin Login Page:</b><br/>
<form action="adminlogin.jsp" method="post" autocomplete="off">
<table>
<tr><td>UserName: </td><td><input type="text" name="username" /></td></tr>
<tr><td>Password :</td><td><input type="password" name="password"/></td></tr>
<tr><td><input type="submit" name="Login" value="Login"/></td></tr>
<tr>
    <td></td>
    <td class="fail"><%= errorMessage != null ? Encode.forHtml(errorMessage) : "" %></td>
</tr>
</table>
</form>

<%@ include file="/footer.jsp" %>
