package org.cysecurity.cspf.jvl.controller;

import java.io.IOException;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.cysecurity.cspf.jvl.model.DBConnect;
import org.json.JSONObject;

public class UsernameCheck extends HttpServlet {

    private static final String USERNAME_EXISTS_SQL =
            "SELECT 1 FROM users WHERE username = ?";

    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        response.setContentType("application/json;charset=UTF-8");

        JSONObject json = new JSONObject();
        String user = safeTrim(request.getParameter("username"));

        try (PrintWriter out = response.getWriter()) {

            if (!isValidUsername(user)) {
                json.put("available", 0);
                json.put("message", "Invalid username");
                out.print(json.toString());
                return;
            }

            try (Connection con = new DBConnect().connect(
                    getServletContext().getRealPath("/WEB-INF/config.properties"))) {

                if (con == null || con.isClosed()) {
                    response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                    json.put("available", 0);
                    json.put("message", "Database connection error");
                    out.print(json.toString());
                    return;
                }

                try (PreparedStatement ps = con.prepareStatement(USERNAME_EXISTS_SQL)) {
                    ps.setString(1, user);

                    try (ResultSet rs = ps.executeQuery()) {
                        if (rs.next()) {
                            json.put("available", 1);
                        } else {
                            json.put("available", 0);
                        }
                    }
                }
            } catch (SQLException ex) {
                log("UsernameCheck database error", ex);
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                json.put("available", 0);
                json.put("message", "Unable to process request");
            }

            out.print(json.toString());
        }
    }

    private String safeTrim(String value) {
        return value == null ? "" : value.trim();
    }

    private boolean isValidUsername(String value) {
        if (value.isEmpty() || value.length() > 30) {
            return false;
        }

        return value.matches("[A-Za-z0-9_\\-]{3,30}");
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
        return "Safe username availability check controller";
    }
}
