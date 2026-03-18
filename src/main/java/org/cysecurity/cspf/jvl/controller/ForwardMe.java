package org.cysecurity.cspf.jvl.controller;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ForwardMe extends HttpServlet {

    private static final Map<String, String> ALLOWED_LOCATIONS = new HashMap<>();

    static {
        ALLOWED_LOCATIONS.put("home", "/index.jsp");
        ALLOWED_LOCATIONS.put("login", "/login.jsp");
        ALLOWED_LOCATIONS.put("register", "/register.jsp");
        ALLOWED_LOCATIONS.put("xpathLogin", "/vulnerability/Injection/xpath_login.jsp");
        ALLOWED_LOCATIONS.put("contact", "/contact.jsp");
    }

    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        response.setContentType("text/html;charset=UTF-8");

        try (PrintWriter out = response.getWriter()) {
            String locationKey = safeTrim(request.getParameter("location"));

            if (locationKey.isEmpty()) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing location parameter");
                return;
            }

            String safeLocation = ALLOWED_LOCATIONS.get(locationKey);

            if (safeLocation == null) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid forward target");
                return;
            }

            RequestDispatcher dispatcher = getServletContext().getRequestDispatcher(safeLocation);

            if (dispatcher == null) {
                response.sendError(HttpServletResponse.SC_NOT_FOUND, "Target resource not found");
                return;
            }

            dispatcher.forward(request, response);
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
        return "Safe internal forward controller";
    }
}
