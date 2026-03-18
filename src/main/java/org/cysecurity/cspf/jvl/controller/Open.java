package org.cysecurity.cspf.jvl.controller;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashSet;
import java.util.Set;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Open extends HttpServlet {

    private static final Set<String> ALLOWED_EXTERNAL_HOSTS = new HashSet<>();

    static {
        ALLOWED_EXTERNAL_HOSTS.add("example.com");
        ALLOWED_EXTERNAL_HOSTS.add("www.example.com");
        ALLOWED_EXTERNAL_HOSTS.add("docs.oracle.com");
    }

    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String url = safeTrim(request.getParameter("url"));

        if (url.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing url parameter");
            return;
        }

        if (isAllowedInternalPath(url)) {
            response.sendRedirect(response.encodeRedirectURL(request.getContextPath() + url));
            return;
        }

        if (isAllowedExternalUrl(url)) {
            response.sendRedirect(response.encodeRedirectURL(url));
            return;
        }

        response.sendError(HttpServletResponse.SC_FORBIDDEN, "Redirect target is not allowed");
    }

    private String safeTrim(String value) {
        return value == null ? "" : value.trim();
    }

    private boolean isAllowedInternalPath(String url) {
        if (!url.startsWith("/")) {
            return false;
        }

        if (url.startsWith("//")) {
            return false;
        }

        if (url.contains("..") || url.contains("\r") || url.contains("\n")) {
            return false;
        }

        return true;
    }

    private boolean isAllowedExternalUrl(String url) {
        try {
            URI uri = new URI(url);

            String scheme = uri.getScheme();
            String host = uri.getHost();

            if (scheme == null || host == null) {
                return false;
            }

            if (!("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme))) {
                return false;
            }

            return ALLOWED_EXTERNAL_HOSTS.contains(host.toLowerCase());
        } catch (URISyntaxException ex) {
            return false;
        }
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
        return "Safe redirect controller";
    }
}
