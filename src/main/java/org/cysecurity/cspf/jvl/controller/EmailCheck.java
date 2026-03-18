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

public class EmailCheck extends HttpServlet {

    private static final String EMAIL_EXISTS_SQL =
            "SELECT 1 FROM users WHERE email = ?";

    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        response.setContentType("application/json;charset=UTF-8");

        JSONObject json = new JSONObject();
        String email = safeTrim(request.getParameter("email"));

        try (PrintWriter out = response.getWriter()) {

            if (!isValidEmail(email)) {
                json.put("available", 0);
                json.put("message", "Invalid email");
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

                try (PreparedStatement ps = con.prepareStatement(EMAIL_EXISTS_SQL)) {
                    ps.setString(1, email);

                    try (ResultSet rs = ps.executeQuery()) {
                        if (rs.next()) {
                            json.put("available", 1);
                        } else {
                            json.put("available", 0);
                        }
                    }
                }
            } catch (SQLException ex) {
                log("EmailCheck database error", ex);
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

    private boolean isValidEmail(String value) {
        if (value.isEmpty() || value.length() > 254) {
            return false;
        }

        return value.matches("^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\\.[A-Za-z]{2,20}$");
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
        return "Safe email availability check controller";
    }
}
