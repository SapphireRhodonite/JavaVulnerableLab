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

                        // Mitigación de session fixation
                        HttpSession oldSession = request.getSession(false);
                        if (oldSession != null) {
                            oldSession.invalidate();
                        }

                        HttpSession session = request.getSession(true);
                        session.setAttribute("isLoggedIn", "1");
                        session.setAttribute("userid", rs.getString("id"));

                        // Guardamos datos, pero OJO:
                        // si se renderizan en JSP deben escaparse al salir.
                        session.setAttribute("user", rs.getString("username"));
                        session.setAttribute("avatar", rs.getString("avatar"));

                        Cookie privilege = new Cookie("privilege", "user");
                        privilege.setHttpOnly(true);
                        privilege.setSecure(request.isSecure());
                        privilege.setPath("/");
                        response.addCookie(privilege);

                        // Mejor NO guardar password en cookies.
                        // Si necesitas "remember me", usa un token aleatorio del lado servidor.
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
