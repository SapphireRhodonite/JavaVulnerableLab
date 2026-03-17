package org.cysecurity.cspf.jvl.controller;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Properties;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.cysecurity.cspf.jvl.model.HashMe;

public class Install extends HttpServlet {

    @Override
    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String configPath = getServletContext().getRealPath("/WEB-INF/config.properties");

        String dburl = safeTrim(request.getParameter("dburl"));
        String jdbcdriver = safeTrim(request.getParameter("jdbcdriver"));
        String dbuser = safeTrim(request.getParameter("dbuser"));
        String dbpass = safeTrim(request.getParameter("dbpass"));
        String siteTitle = safeTrim(request.getParameter("siteTitle"));
        String adminuser = safeTrim(request.getParameter("adminuser"));
        String rawAdminPass = safeTrim(request.getParameter("adminpass"));
        String setup = safeTrim(request.getParameter("setup"));

        response.setContentType("text/html;charset=UTF-8");

        try (PrintWriter out = response.getWriter()) {
            out.println("<!DOCTYPE html>");
            out.println("<html>");
            out.println("<head>");
            out.println("<title>Servlet install</title>");
            out.println("</head>");
            out.println("<body>");

            if (!"1".equals(setup)) {
                out.print("Invalid setup request");
                out.println("</body>");
                out.println("</html>");
                return;
            }

            String dbname;
            try {
                dbname = requireValidDbName(request.getParameter("dbname"));
            } catch (IllegalArgumentException ex) {
                out.print("Invalid database name");
                out.println("</body>");
                out.println("</html>");
                return;
            }

            if (!isValidAdminUser(adminuser)) {
                out.print("Invalid admin username");
            } else if (rawAdminPass.isEmpty()) {
                out.print("Admin password is required");
            } else {
                String adminpass = HashMe.hashMe(rawAdminPass);

                storeConfig(configPath, dburl, jdbcdriver, dbuser, dbpass, dbname, siteTitle);

                if (setupDatabase(dburl, jdbcdriver, dbuser, dbpass, dbname, adminuser, adminpass)) {
                    out.print("successfully installed");
                } else {
                    out.print("Something went wrong. Unable to install");
                }
            }

            out.println("</body>");
            out.println("</html>");
        } catch (Exception e) {
            throw new ServletException("Installation failed", e);
        }
    }

    private boolean setupDatabase(String dburl,
                                  String jdbcdriver,
                                  String dbuser,
                                  String dbpass,
                                  String dbname,
                                  String adminuser,
                                  String adminpass) {

        try {
            Class.forName(jdbcdriver);

            // Database names are identifiers, not data values.
            // They cannot be parameterized with PreparedStatement,
            // so we strictly validate and then quote them safely.
            String safeDbIdentifier = quoteMySqlIdentifier(dbname);

            try (Connection con = DriverManager.getConnection(dburl, dbuser, dbpass);
                 Statement stmt = con.createStatement()) {

                stmt.executeUpdate("DROP DATABASE IF EXISTS " + safeDbIdentifier);
                stmt.executeUpdate("CREATE DATABASE " + safeDbIdentifier);
            }

            try (Connection con = DriverManager.getConnection(dburl + dbname, dbuser, dbpass);
                 Statement stmt = con.createStatement()) {

                stmt.executeUpdate("CREATE TABLE users(" +
                        "ID int NOT NULL AUTO_INCREMENT, " +
                        "username varchar(30), " +
                        "email varchar(60), " +
                        "password varchar(60), " +
                        "about varchar(50), " +
                        "privilege varchar(20), " +
                        "avatar TEXT, " +
                        "secretquestion int, " +
                        "secret varchar(30), " +
                        "PRIMARY KEY (id))");

                try (PreparedStatement ps = con.prepareStatement(
                        "INSERT INTO users(username, password, email, About, avatar, privilege, secretquestion, secret) " +
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)")) {

                    ps.setString(1, adminuser);
                    ps.setString(2, adminpass);
                    ps.setString(3, "admin@localhost");
                    ps.setString(4, "I am the admin of this application");
                    ps.setString(5, "default.jpg");
                    ps.setString(6, "admin");
                    ps.setInt(7, 1);
                    ps.setString(8, "rocky");
                    ps.executeUpdate();

                    ps.setString(1, "victim");
                    ps.setString(2, "victim");
                    ps.setString(3, "victim@localhost");
                    ps.setString(4, "I am the victim of this application");
                    ps.setString(5, "default.jpg");
                    ps.setString(6, "user");
                    ps.setInt(7, 1);
                    ps.setString(8, "max");
                    ps.executeUpdate();

                    ps.setString(1, "attacker");
                    ps.setString(2, "attacker");
                    ps.setString(3, "attacker@localhost");
                    ps.setString(4, "I am the attacker of this application");
                    ps.setString(5, "default.jpg");
                    ps.setString(6, "user");
                    ps.setInt(7, 1);
                    ps.setString(8, "bella");
                    ps.executeUpdate();

                    ps.setString(1, "NEO");
                    ps.setString(2, "trinity");
                    ps.setString(3, "neo@matrix");
                    ps.setString(4, "I am the NEO");
                    ps.setString(5, "default.jpg");
                    ps.setString(6, "user");
                    ps.setInt(7, 1);
                    ps.setString(8, "sentinel");
                    ps.executeUpdate();

                    ps.setString(1, "trinity");
                    ps.setString(2, "NEO");
                    ps.setString(3, "trinity@matrix");
                    ps.setString(4, "it is Trinity");
                    ps.setString(5, "default.jpg");
                    ps.setString(6, "user");
                    ps.setInt(7, 1);
                    ps.setString(8, "sentinel");
                    ps.executeUpdate();

                    ps.setString(1, "Anderson");
                    ps.setString(2, "java");
                    ps.setString(3, "anderson@1999");
                    ps.setString(4, "I am computer programmer");
                    ps.setString(5, "default.jpg");
                    ps.setString(6, "user");
                    ps.setInt(7, 1);
                    ps.setString(8, "C++");
                    ps.executeUpdate();
                }

                stmt.executeUpdate("CREATE TABLE posts(postid int NOT NULL AUTO_INCREMENT, content TEXT, title varchar(100), user varchar(30), PRIMARY KEY (postid))");
                stmt.executeUpdate("INSERT INTO posts(content,title,user) VALUES ('Feel free to ask any questions about Java Vulnerable Lab','First Post','admin')");
                stmt.executeUpdate("INSERT INTO posts(content,title,user) VALUES ('Hello Guys, this is victim','Second Post','victim')");
                stmt.executeUpdate("INSERT INTO posts(content,title,user) VALUES ('Hello This is attacker','Third Post','attacker')");
                stmt.executeUpdate("INSERT INTO posts(content,title,user) VALUES ('Trinity! Help!','Help','neo')");

                stmt.executeUpdate("CREATE TABLE tdata(id int, page varchar(30))");
                stmt.executeUpdate("INSERT INTO tdata VALUES(1,'ext1.html')");
                stmt.executeUpdate("INSERT INTO tdata VALUES(2,'ext2.html')");

                stmt.executeUpdate("CREATE TABLE Messages(msgid int NOT NULL AUTO_INCREMENT, name varchar(30), email varchar(60), msg varchar(500), PRIMARY KEY (msgid))");
                stmt.executeUpdate("INSERT INTO Messages(name,email,msg) VALUES ('TestUser','Test@localhost','Hi admin, how are you')");

                stmt.executeUpdate("CREATE TABLE UserMessages(msgid int NOT NULL AUTO_INCREMENT, recipient varchar(30), sender varchar(30), subject varchar(60), msg varchar(500), PRIMARY KEY (msgid))");
                stmt.executeUpdate("INSERT INTO UserMessages(recipient, sender, subject, msg) VALUES ('attacker','admin','Hi','Hi<br/> This is admin of this page. <br/> Welcome to Our Forum')");
                stmt.executeUpdate("INSERT INTO UserMessages(recipient, sender, subject, msg) VALUES ('victim','admin','Hi','Hi<br/> This is admin of this page. <br/> Welcome to Our Forum')");

                stmt.executeUpdate("CREATE TABLE cards(id int, cardno varchar(80), cvv varchar(6), expirydate varchar(15))");
                stmt.executeUpdate("INSERT INTO cards(id,cardno,cvv,expirydate) VALUES ('1','4000123456789010','123','12/2014')");
                stmt.executeUpdate("INSERT INTO cards(id,cardno,cvv,expirydate) VALUES ('2','4111111111111111','321','7/2015')");
                stmt.executeUpdate("INSERT INTO cards(id,cardno,cvv,expirydate) VALUES ('3','5111111111111118','111','1/2017')");

                stmt.executeUpdate("CREATE TABLE FilesList(fileid int NOT NULL AUTO_INCREMENT, path text, PRIMARY KEY (fileid))");
                stmt.executeUpdate("INSERT INTO FilesList(path) VALUES ('/docs/doc1.pdf')");
                stmt.executeUpdate("INSERT INTO FilesList(path) VALUES ('/docs/exampledoc.pdf')");
            }

            return true;

        } catch (SQLException ex) {
            log("SQLException during installation", ex);
            return false;
        } catch (ClassNotFoundException ex) {
            log("JDBC Driver Missing", ex);
            return false;
        }
    }

    private void storeConfig(String configPath,
                             String dburl,
                             String jdbcdriver,
                             String dbuser,
                             String dbpass,
                             String dbname,
                             String siteTitle) throws IOException {

        Properties config = new Properties();

        try (InputStream in = new FileInputStream(configPath)) {
            config.load(in);
        }

        config.setProperty("dburl", dburl);
        config.setProperty("jdbcdriver", jdbcdriver);
        config.setProperty("dbuser", dbuser);
        config.setProperty("dbpass", dbpass);
        config.setProperty("dbname", dbname);
        config.setProperty("siteTitle", siteTitle);

        try (OutputStream out = new FileOutputStream(configPath)) {
            config.store(out, null);
        }
    }

    private String safeTrim(String value) {
        return value == null ? "" : value.trim();
    }

    private String requireValidDbName(String value) {
        String normalized = safeTrim(value);
        if (!normalized.matches("[A-Za-z0-9_]{1,50}")) {
            throw new IllegalArgumentException("Invalid database name");
        }
        return normalized;
    }

    private String quoteMySqlIdentifier(String identifier) {
        return "`" + identifier + "`";
    }

    private boolean isValidAdminUser(String value) {
        return value != null && value.matches("[A-Za-z0-9_\\-]{3,30}");
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
        return "Install servlet";
    }
}
