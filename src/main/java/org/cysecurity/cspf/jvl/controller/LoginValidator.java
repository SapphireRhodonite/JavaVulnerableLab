package org.cysecurity.cspf.jvl.controller;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.cysecurity.cspf.jvl.model.DBConnect;

public class LoginValidator extends HttpServlet {

    private static final String AUTH_QUERY =
        "SELECT id, username, avatar FROM users WHERE username = ? AND password = ?";

    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String user = safeTrim(request.getParameter("username"));
        String pass = safeTrim(request.getParameter("password"));

        if (user.isEmpty() || pass.isEmpty()) {
            response.sendRedirect("ForwardMe?location=/login.jsp&err=Invalid credentials");
            return;
        }

        response.setContentType("text/html;charset=UTF-8");

        try (Connection con = new DBConnect().connect(
                getServletContext().getRealPath("/WEB-INF/config.properties"))) {

            if (con == null || con.isClosed()) {
                response.sendRedirect("login.jsp?err=something went wrong");
                return;
            }

            try (PreparedStatement ps = con.prepareStatement(AUTH_QUERY)) {
                ps.setString(1, user);
                ps.setString(2, pass);

                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {

                        HttpSession oldSession = request.getSession(false);
                        if (oldSession != null) {
                            oldSession.invalidate();
                        }

                        String dbUserId = safeTrim(rs.getString("id"));
                        String dbUsername = safeText(rs.getString("username"));
                        String dbAvatar = safeAvatar(rs.getString("avatar"));

                        HttpSession session = request.getSession(true);
                        session.setAttribute("isLoggedIn", "1");
                        session.setAttribute("userid", dbUserId);
                        session.setAttribute("user", dbUsername);
                        session.setAttribute("avatar", dbAvatar);
                        session.setAttribute("privilege", "user");

                        Cookie privilege = new Cookie("privilege", "user");
                        privilege.setHttpOnly(true);
                        privilege.setSecure(request.isSecure());
                        privilege.setPath("/");
                        response.addCookie(privilege);

                        if (request.getParameter("RememberMe") != null) {
                            Cookie usernameCookie = new Cookie("username", user);
                            usernameCookie.setHttpOnly(true);
                            usernameCookie.setSecure(request.isSecure());
                            usernameCookie.setPath("/");
                            usernameCookie.setMaxAge(7 * 24 * 60 * 60);
                            response.addCookie(usernameCookie);
                        }

                        response.sendRedirect(response.encodeRedirectURL("ForwardMe?location=/index.jsp"));
                    } else {
                        response.sendRedirect("ForwardMe?location=/login.jsp&err=Invalid credentials");
                    }
                }
            }

        } catch (SQLException ex) {
            response.sendRedirect("login.jsp?err=something went wrong");
        } catch (Exception ex) {
            response.sendRedirect("login.jsp?err=something went wrong");
        }
    }

    private String safeTrim(String value) {
        return value == null ? "" : value.trim();
    }

    private String safeText(String value) {
        if (value == null) {
            return "";
        }
        return value.trim();
    }

    private String safeAvatar(String avatar) {
        if (avatar == null || avatar.trim().isEmpty()) {
            return "default.jpg";
        }

        String cleaned = avatar.trim();

        // allowlist simple para nombres de archivo de avatar
        if (cleaned.matches("[A-Za-z0-9._\\-]{1,100}\\.(jpg|jpeg|png|gif)$")) {
            return cleaned;
        }

        return "default.jpg";
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    @Override
    public String getServletInfo() {
        return "Login validator";
    }
}
