package org.cysecurity.cspf.jvl.controller;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class AddPage extends HttpServlet {

    private static final Map<String, String> ALLOWED_PAGE_FILES = new HashMap<>();

    static {
        ALLOWED_PAGE_FILES.put("help", "help.html");
        ALLOWED_PAGE_FILES.put("faq", "faq.html");
        ALLOWED_PAGE_FILES.put("notice", "notice.txt");
    }

    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED, "POST is required");
            return;
        }

        response.setContentType("text/html;charset=UTF-8");

        try (PrintWriter out = response.getWriter()) {

            HttpSession session = request.getSession(false);
            if (session == null || session.getAttribute("isLoggedIn") == null) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication required");
                return;
            }

            String privilege = safeTrim((String) session.getAttribute("privilege"));
            if (!"admin".equals(privilege)) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Admin access required");
                return;
            }

            String pageKey = safeTrim(request.getParameter("filename"));
            String content = request.getParameter("content");

            if (pageKey.isEmpty() || content == null) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "filename or content parameter is missing");
                return;
            }

            String allowedFileName = resolveAllowedFileName(pageKey);
            if (allowedFileName == null) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid page selection");
                return;
            }

            File pagesDir = new File(getServletContext().getRealPath("/pages"));
            File targetFile = new File(pagesDir, allowedFileName);

            String canonicalPagesDir = pagesDir.getCanonicalPath();
            String canonicalTargetFile = targetFile.getCanonicalPath();

            if (!canonicalTargetFile.startsWith(canonicalPagesDir + File.separator)) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid file path");
                return;
            }

            String safeContent = escapeHtml(content);

            if (!pagesDir.exists() && !pagesDir.mkdirs()) {
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Unable to prepare pages directory");
                return;
            }

            try (BufferedWriter bw = new BufferedWriter(
                    new FileWriter(targetFile, StandardCharsets.UTF_8))) {
                bw.write(safeContent);
            }

            String safeFileName = escapeHtml(allowedFileName);
            out.print("Successfully created the file: <a href='../pages/" + safeFileName + "'>" + safeFileName + "</a>");
        }
    }

    private String resolveAllowedFileName(String pageKey) {
        String normalized = safeTrim(pageKey).toLowerCase();
        return ALLOWED_PAGE_FILES.get(normalized);
    }

    private String safeTrim(String value) {
        return value == null ? "" : value.trim();
    }

    private String escapeHtml(String input) {
        if (input == null) return "";
        return input.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;");
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED, "GET is not supported");
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    @Override
    public String getServletInfo() {
        return "Safe page creation controller";
    }
}
