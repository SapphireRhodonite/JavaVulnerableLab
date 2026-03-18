package org.cysecurity.cspf.jvl.controller;

import java.io.IOException;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.cysecurity.cspf.jvl.model.DBConnect;
import org.cysecurity.cspf.jvl.model.HashMe;

public class Register extends HttpServlet {

    private static final String INSERT_USER_SQL =
            "INSERT INTO users(username, password, email, About, avatar, privilege, secretquestion, secret) " +
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

    private static final String INSERT_WELCOME_MESSAGE_SQL =
            "INSERT INTO UserMessages(recipient, sender, subject, msg) VALUES (?, ?, ?, ?)";

    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        response.setContentType("text/html;charset=UTF-8");

        String user = safeTrim(request.getParameter("username"));
        String pass = safeTrim(request.getParameter("password"));
        String email = safeTrim(request.getParameter("email"));
        String about = safeTrim(request.getParameter("About"));
        String secret = safeTrim(request.getParameter("secret"));

        if (secret.isEmpty()) {
            secret = "nosecret";
        }

        try (PrintWriter out = response.getWriter()) {

            try {
                validateRegistrationInput(user, pass, email, about, secret);
            } catch (IllegalArgumentException ex) {
                out.print(ex.getMessage());
                return;
            }

            String hashedPassword = HashMe.hashMe(pass);

            try (Connection con = new DBConnect().connect(
                    getServletContext().getRealPath("/WEB-INF/config.properties"))) {

                if (con == null || con.isClosed()) {
                    response.sendRedirect("Register.jsp?err=Database connection error");
                    return;
                }

                con.setAutoCommit(false);

                try (PreparedStatement userPs = con.prepareStatement(INSERT_USER_SQL);
                     PreparedStatement msgPs = con.prepareStatement(INSERT_WELCOME_MESSAGE_SQL)) {

                    userPs.setString(1, user);
                    userPs.setString(2, hashedPassword);
                    userPs.setString(3, email);
                    userPs.setString(4, about);
                    userPs.setString(5, "default.jpg");
                    userPs.setString(6, "user");
                    userPs.setInt(7, 1);
                    userPs.setString(8, secret);
                    userPs.executeUpdate();

                    msgPs.setString(1, user);
                    msgPs.setString(2, "admin");
                    msgPs.setString(3, "Hi");
                    msgPs.setString(4, "Hi<br/> This is admin of this page. <br/> Welcome to Our Forum");
                    msgPs.executeUpdate();

                    con.commit();

                    HttpSession oldSession = request.getSession(false);
                    if (oldSession != null) {
                        oldSession.invalidate();
                    }

                    HttpSession session = request.getSession(true);
                    session.setAttribute("user", user);
                    session.setAttribute("isLoggedIn", "1");
                    session.setAttribute("privilege", "user");

                    response.sendRedirect("index.jsp");
                    return;

                } catch (SQLException ex) {
                    con.rollback();
                    log("Registration failed", ex);
                    response.sendRedirect("Register.jsp?err=Registration failed");
                    return;
                }

            } catch (SQLException ex) {
                log("Database connection error", ex);
                response.sendRedirect("Register.jsp?err=Database error");
                return;
            } catch (Exception ex) {
                log("Unexpected registration error", ex);
                response.sendRedirect("Register.jsp?err=Unexpected error");
                return;
            }
        }
    }

    private void validateRegistrationInput(String user,
                                           String pass,
                                           String email,
                                           String about,
                                           String secret) {

        if (!user.matches("[A-Za-z0-9_\\-]{3,30}")) {
            throw new IllegalArgumentException("Invalid username");
        }

        if (pass.length() < 8 || pass.length() > 128) {
            throw new IllegalArgumentException("Password must be between 8 and 128 characters");
        }

        if (!email.matches("^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\\.[A-Za-z]{2,20}$")) {
            throw new IllegalArgumentException("Invalid email");
        }

        if (about.length() > 200) {
            throw new IllegalArgumentException("About section is too long");
        }

        if (!about.isEmpty() && !about.matches("[A-Za-z0-9 .,\\-_]{1,200}")) {
            throw new IllegalArgumentException("Invalid About text");
        }

        if (secret.length() > 50) {
            throw new IllegalArgumentException("Secret answer is too long");
        }

        if (!secret.matches("[A-Za-z0-9_\\-]{1,50}")) {
            throw new IllegalArgumentException("Invalid secret answer");
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
        return "Safe user registration controller";
    }
}
