package org.cysecurity.cspf.jvl.controller;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class AddPage extends HttpServlet {

    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

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

            String pagesDirPath = getServletContext().getRealPath("/pages");
            File pagesDir = new File(pagesDirPath);
            File targetFile = new File(pagesDir, fileName);

            String canonicalPagesDir = pagesDir.getCanonicalPath();
            String canonicalTargetFile = targetFile.getCanonicalPath();

            if (!canonicalTargetFile.startsWith(canonicalPagesDir + File.separator)) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid file path");
                return;
            }

            String safeContent = escapeHtml(content);

            if (targetFile.exists() && !targetFile.delete()) {
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Unable to replace existing file");
                return;
            }

            if (!targetFile.createNewFile()) {
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Failed to create file");
                return;
            }

            try (BufferedWriter bw = new BufferedWriter(
                    new FileWriter(targetFile, StandardCharsets.UTF_8))) {
                bw.write(safeContent);
            }

            String safeFileName = escapeHtml(fileName);
            out.print("Successfully created the file: <a href='../pages/" + safeFileName + "'>" + safeFileName + "</a>");
        }
    }

    private String safeTrim(String value) {
        return value == null ? "" : value.trim();
    }

    private boolean isValidFileName(String fileName) {
        return fileName.matches("[A-Za-z0-9._-]{1,100}\\.(html|txt)$");
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
        processRequest(request, response);
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
