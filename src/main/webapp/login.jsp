package org.cysecurity.cspf.jvl.controller;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
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

        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED, "POST is required");
            return;
        }

        HttpSession csrfSession = request.getSession(false);
        String sessionToken = csrfSession != null ? (String) csrfSession.getAttribute("csrfToken") : null;
        String requestToken = request.getParameter("csrfToken");

        if (sessionToken == null || requestToken == null || !sessionToken.equals(requestToken)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid CSRF token");
            return;
        }

        String user = safeTrim(request.getParameter("username"));
        String pass = safeTrim(request.getParameter("password"));

        if (user.isEmpty() || pass.isEmpty()) {
            redirectToLoginWithError(response, "Invalid credentials");
            return;
        }

        response.setContentType("text/html;charset=UTF-8");

        try (Connection con = new DBConnect().connect(
                getServletContext().getRealPath("/WEB-INF/config.properties"))) {

            if (con == null || con.isClosed()) {
                redirectToLoginWithError(response, "Something went wrong");
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

                        String dbUserId = requireNumericId(rs.getString("id"));
                        String dbUsername = safeUsername(rs.getString("username"));
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

                        response.sendRedirect(response.encodeRedirectURL("ForwardMe?location=home"));
                    } else {
                        redirectToLoginWithError(response, "Invalid credentials");
                    }
                }
            }

        } catch (SQLException ex) {
            redirectToLoginWithError(response, "Something went wrong");
        } catch (IllegalArgumentException ex) {
            redirectToLoginWithError(response, "Something went wrong");
        } catch (Exception ex) {
            redirectToLoginWithError(response, "Something went wrong");
        }
    }

    private void redirectToLoginWithError(HttpServletResponse response, String message)
            throws IOException {
        String encodedMessage = URLEncoder.encode(message, StandardCharsets.UTF_8.name());
        response.sendRedirect("ForwardMe?location=login&err=" + encodedMessage);
    }

    private String safeTrim(String value) {
        return value == null ? "" : value.trim();
    }

    private String requireNumericId(String value) {
        String normalized = safeTrim(value);
        if (!normalized.matches("\\d{1,20}")) {
            throw new IllegalArgumentException("Invalid user id");
        }
        return normalized;
    }

    private String safeUsername(String value) {
        String normalized = safeTrim(value);
        if (!normalized.matches("[A-Za-z0-9_\\-]{1,30}")) {
            return "user";
        }
        return normalized;
    }

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

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED, "GET is not supported for login");
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
