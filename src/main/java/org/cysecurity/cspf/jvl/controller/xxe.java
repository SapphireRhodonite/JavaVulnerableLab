package org.cysecurity.cspf.jvl.controller;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.owasp.encoder.Encode;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

public class xxe extends HttpServlet {

    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED, "POST is required");
            return;
        }

        response.setContentType("text/html;charset=UTF-8");

        try (PrintWriter out = response.getWriter();
             InputStream xml = request.getInputStream()) {

            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);

            // Hardening against XXE
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);

            factory.setXIncludeAware(false);
            factory.setExpandEntityReferences(false);

            DocumentBuilder builder = factory.newDocumentBuilder();
            InputSource inputSource = new InputSource(xml);
            Document doc = builder.parse(inputSource);

            Element element = doc.getDocumentElement();
            NodeList nodes = element.getChildNodes();

            out.print("<br/>Result:<br/>");
            out.print("---------------------<br/>");

            for (int i = 0; i < nodes.getLength(); i++) {
                if (nodes.item(i) != null
                        && nodes.item(i).getNodeName() != null
                        && nodes.item(i).getFirstChild() != null
                        && nodes.item(i).getFirstChild().getNodeValue() != null) {

                    String nodeName = Encode.forHtml(nodes.item(i).getNodeName());
                    String nodeValue = Encode.forHtml(nodes.item(i).getFirstChild().getNodeValue());

                    out.print(nodeName + " : " + nodeValue);
                    out.print("<br/>");
                }
            }

        } catch (Exception ex) {
            log("Error processing XML request in xxe servlet", ex);
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid XML input");
        }
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
        return "Safe XML processing controller";
    }
}
