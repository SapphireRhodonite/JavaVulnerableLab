package org.cysecurity.cspf.jvl.controller;

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.xml.XMLConstants;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import javax.xml.xpath.XPathVariableResolver;
import org.w3c.dom.Document;

public class XPathQuery extends HttpServlet {

    private static final String AUTH_XPATH =
            "/users/user[username=$username and password=$password]/name/text()";

    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED, "POST is required");
            return;
        }

        response.setContentType("text/html;charset=UTF-8");

        String user = safeTrim(request.getParameter("username"));
        String pass = safeTrim(request.getParameter("password"));

        if (!isValidCredentialInput(user) || !isValidCredentialInput(pass)) {
            response.sendRedirect(response.encodeRedirectURL("ForwardMe?location=xpathLogin"));
            return;
        }

        try {
            String xmlSource = getServletContext().getRealPath("/WEB-INF/users.xml");

            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);

            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            factory.setXIncludeAware(false);
            factory.setExpandEntityReferences(false);

            DocumentBuilder builder = factory.newDocumentBuilder();
            Document xDoc = builder.parse(xmlSource);

            XPath xPath = XPathFactory.newInstance().newXPath();
            xPath.setXPathVariableResolver(new UserAuthVariableResolver(user, pass));

            String name = (String) xPath.evaluate(AUTH_XPATH, xDoc, XPathConstants.STRING);

            if (name == null || name.trim().isEmpty()) {
                response.sendRedirect(response.encodeRedirectURL("ForwardMe?location=xpathLogin"));
                return;
            }

            HttpSession oldSession = request.getSession(false);
            if (oldSession != null) {
                oldSession.invalidate();
            }

            HttpSession session = request.getSession(true);
            session.setAttribute("isLoggedIn", "1");
            session.setAttribute("user", safeDisplayName(name));

            response.sendRedirect(response.encodeRedirectURL("ForwardMe?location=home"));

        } catch (Exception ex) {
            log("XPath authentication failed", ex);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Authentication failed");
        }
    }

    private static class UserAuthVariableResolver implements XPathVariableResolver {
        private final String username;
        private final String password;

        UserAuthVariableResolver(String username, String password) {
            this.username = username;
            this.password = password;
        }

        @Override
        public Object resolveVariable(QName variableName) {
            if (variableName == null) {
                return null;
            }

            String localPart = variableName.getLocalPart();

            if ("username".equals(localPart)) {
                return username;
            }

            if ("password".equals(localPart)) {
                return password;
            }

            return null;
        }
    }

    private String safeTrim(String value) {
        return value == null ? "" : value.trim();
    }

    private boolean isValidCredentialInput(String value) {
        if (value == null) {
            return false;
        }

        if (value.length() < 1 || value.length() > 50) {
            return false;
        }

        return value.matches("[A-Za-z0-9_@.\\-]+");
    }

    private String safeDisplayName(String value) {
        String normalized = safeTrim(value);
        if (normalized.matches("[A-Za-z0-9 _\\-]{1,50}")) {
            return normalized;
        }
        return "user";
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED, "GET is not supported for XPath authentication");
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    @Override
    public String getServletInfo() {
        return "Safe XPath authentication controller";
    }
}
