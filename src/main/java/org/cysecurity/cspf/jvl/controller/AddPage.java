package org.cysecurity.cspf.jvl.controller;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class AddPage extends HttpServlet {

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

            String fileName = safeTrim(request.getParameter("filename"));
            String content = request.getParameter("content");

            if (fileName.isEmpty() || content == null) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "filename or content parameter is missing");
                return;
            }

            if (!isValidFileName(fileName)) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid file name");
                return;
            }

            Path pagesDir = Paths.get(getServletContext().getRealPath("/pages"))
                    .toAbsolutePath()
                    .normalize();

            Path targetPath = pagesDir.resolve(fileName).normalize();

            if (!targetPath.startsWith(pagesDir)) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid file path");
                return;
            }

            String safeContent = escapeHtml(content);

            Files.createDirectories(pagesDir);

            try (BufferedWriter writer = Files.newBufferedWriter(
                    targetPath,
                    StandardCharsets.UTF_8)) {
                writer.write(safeContent);
            }

            String safeFileName = escapeHtml(fileName);
            out.print("Successfully created the file: <a href='../pages/" + safeFileName + "'>" + safeFileName + "</a>");
        }
    }

    private String safeTrim(String value) {
        return value == null ? "" : value.trim();
    }

    private boolean isValidFileName(String fileName) {
        return fileName.matches("[A-Za-z0-9_-]{1,50}\\.(html|txt)$");
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
