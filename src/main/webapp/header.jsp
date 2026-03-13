<%@page import="java.io.FileInputStream"%>
<%@page import="java.io.InputStream"%>
<%@page import="java.util.Properties"%>
<%@page import="org.owasp.encoder.Encode"%>
<%
   String path = request.getContextPath();
   if (path == null) {
       path = "";
   }

   String configPath = getServletContext().getRealPath("/WEB-INF/config.properties");

   Properties properties = new Properties();
   try (InputStream in = new FileInputStream(configPath)) {
       properties.load(in);
   }

   String siteTitle = properties.getProperty("siteTitle");
   if (siteTitle == null) {
       siteTitle = "Application";
   }

   String safePath = Encode.forHtmlAttribute(path);
   String safeSiteTitleHtml = Encode.forHtml(siteTitle);
   String safeSiteTitleAttr = Encode.forHtmlContent(siteTitle);

   String sessionUserId = session.getAttribute("userid") != null
           ? String.valueOf(session.getAttribute("userid"))
           : "";
   String safeUserIdForUrl = Encode.forUriComponent(sessionUserId);

   boolean loggedIn = session.getAttribute("isLoggedIn") != null
           && "1".equals(String.valueOf(session.getAttribute("isLoggedIn")));

   boolean isAdmin = session.getAttribute("privilege") != null
           && "admin".equals(String.valueOf(session.getAttribute("privilege")));
%>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
    <title><%= safeSiteTitleHtml %></title>
    <link rel="stylesheet" href="<%= safePath %>/style.css" type="text/css" charset="utf-8" />
    <script src="<%= safePath %>/jquery.min.js" type="text/javascript"></script>
</head>

<body>
<div id="container" >

    <div id="Menu">
        <ul id="menu-bar" style="margin-left: auto ;  margin-right: auto ;" >
            <li class="current"><a href="<%= safePath %>">Home</a></li>

            <li><a href="#">Vulnerability</a>
                <ul><li><a href="#">A1- Injection</a>
                    <ul><li><a href="#">SQL Injection</a>
                        <ul>
                          <li><a href="<%= safePath %>/vulnerability/forumposts.jsp?postid=1">Sql Injection 1</a></li>
                          <li><a href="<%= safePath %>/login.jsp">Authentication Bypass</a></li>
                          <li><a href="<%= safePath %>/vulnerability/sqli/download.jsp">Blind SQLi 1</a></li>
                          <li><a href="<%= safePath %>/vulnerability/sqli/union2.jsp">Union 2</a></li>
                        </ul>
                    </li>
                    <li><a href="#">XPath Injection</a>
                        <ul>
                            <li><a href="<%= safePath %>/vulnerability/Injection/xpath_login.jsp">Login Bypass</a></li>
                        </ul>
                    </li>
                    <li><a href="#">XML Injection</a>
                        <ul>
                            <li><a href="<%= safePath %>/vulnerability/Injection/xxe.jsp">External Entity</a></li>
                            <li><a href="<%= safePath %>/vulnerability/Injection/xslt.jsp?style=1.xsl">XSLT Injection</a></li>
                        </ul>
                    </li>
                    <li><a href="<%= safePath %>/vulnerability/Injection/orm.jsp?id=1">ORM Injection</a></li>
                    </ul>
                </li>

                <li><a href="#">A2- Broken Authentication &amp; Session Management</a>
                   <ul>
                       <li><a href="<%= safePath %>/ForgotPassword.jsp">UserName Enumeration</a></li>
                       <li><a href="<%= safePath %>/login.jsp">Brute Foce Login Page</a></li>
                       <%-- Mitigación: no exponer session id en URL --%>
                       <li><a href="<%= safePath %>/vulnerability/baasm/URLRewriting.jsp">Session Handling</a></li>
                       <li><a href="<%= safePath %>/vulnerability/baasm/SiteTitle.jsp">Improper Authentication: Privilege Escalation</a></li>
                   </ul>
                 </li>

                <li><a href="#">A3- XSS</a>
                    <ul>
                        <li><a href="#">Reflected(GET)</a>
                            <ul>
                                <li><a href="<%= safePath %>/vulnerability/xss/search.jsp">Challenge 1</a></li>
                                <li><a href="<%= safePath %>/vulnerability/xss/xss2.jsp">Challenge 2</a></li>
                                <li><a href="<%= safePath %>/vulnerability/xss/xss3.jsp">Challenge 3</a></li>
                                <li><a href="<%= safePath %>/vulnerability/xss/xss4.jsp">Challenge 4</a></li>
                            </ul>
                        </li>

                        <li><a href="#">Flash Based</a>
                            <ul>
                                <li><a href="<%= safePath %>/vulnerability/xss/flash/xss1.swf?vuln=<%= Encode.forUriComponent(path) %>">Challenge 1</a></li>
                                <li><a href="<%= safePath %>/vulnerability/xss/flash/exss.jsp">Challenge 2</a></li>
                            </ul>
                        </li>
                        <li><a href="<%= safePath %>/vulnerability/forum.jsp">Stored XSS(Persistent)</a></li>
                    </ul>
                </li>

                <li><a href="#">A4-Insecure Direct Object References</a>
                    <ul>
                        <li><a href="<%= safePath %>/myprofile.jsp?id=<%= safeUserIdForUrl %>" title="Make sure you have logged in ">Viewing Details</a></li>
                        <li><a href="<%= safePath %>/vulnerability/idor/change-email.jsp" title="Make sure you have logged in ">Modifying email ID</a></li>
                        <li><a href="<%= safePath %>/vulnerability/idor/download.jsp">Download Document</a></li>
                    </ul>
                </li>

                <li><a href="#">A5-Security Misconfiguration</a>
                    <ul>
                        <li><a href="<%= safePath %>/install.jsp">Setup Page not removed</a></li>
                        <li><a href="<%= safePath %>/admin/">Default Admin Credentials not changed</a></li>
                        <li><a href="<%= safePath %>/vulnerability/securitymisconfig/pages.jsp?id=1">Error Handling</a></li>
                    </ul>
                </li>

                <li><a href="#">A6-Sensitive Data Exposure</a>
                    <ul>
                        <li><a href="<%= safePath %>/changeCardDetails.jsp">Cleartext Transmission of Sensitive Information</a></li>
                        <li><a href="<%= safePath %>/ForgotPassword.jsp">Storing Login Credentials in Plain Text</a></li>
                        <li><a href="<%= safePath %>/login.jsp">Storing Login Credentials in Plain Text in a cookie</a></li>
                        <li><a href="<%= safePath %>/vulnerability/sde/hash.jsp">Hashed Credentials</a></li>
                    </ul>
                </li>

                <li><a href="#">A7- Missing Function Level Access Control</a>
                    <ul>
                        <li><a href="<%= safePath %>/admin/" title="Hint: Forced Browsing">Challenge 1:Bypass Admin Login</a></li>
                        <li><a href="<%= safePath %>/admin/AddPage.jsp">Challenge 2: Add Page</a></li>
                        <li><a href="<%= safePath %>/admin/Configure.jsp">Configure</a></li>
                        <li><a href="<%= safePath %>/vulnerability/mfac/SearchEngines.jsp">Crawlers</a></li>
                    </ul>
                </li>

                <li><a href="#">A8- CSRF</a>
                    <ul>
                        <li><a href="<%= safePath %>/vulnerability/csrf/change-info.jsp">CSRF 1(GET): Change Info</a></li>
                        <li><a href="<%= safePath %>/vulnerability/csrf/changepassword.jsp">CSRF 2(POST): Change Password</a></li>
                    </ul>
                </li>

                <li><a href="#">A9- Using components with known vulnerabilities</a>
                    <ul>
                        <li><a href="/VulnerableSpring/error.htm?msg=error.c403">Web Application using Spring Framework</a></li>
                    </ul>
                </li>

                <li><a href="#">A10. Unvalidated Redirect &amp; Forward..</a>
                    <ul>
                        <li><a href="<%= safePath %>/vulnerability/unvalidated/OpenURL.jsp">Open Redirect</a></li>
                        <li><a href="<%= safePath %>/vulnerability/unvalidated/OpenForward.jsp">Open Forward</a></li>
                    </ul>
                </li>
            </ul>
            </li>

            <li><a href="<%= safePath %>/vulnerability/forum.jsp">Forum</a></li>
            <%
                if (loggedIn) {
                    if (isAdmin) {
            %>
                        <li><a href="<%= safePath %>/admin/admin.jsp">Admin Panel</a></li>
            <%
                    }
            %>
                    <li><a href="<%= safePath %>/myprofile.jsp?id=<%= safeUserIdForUrl %>">My Profile</a></li>
                    <li><a href="<%= safePath %>/Logout">Logout</a></li>
            <%
                } else {
            %>
                    <li><a href="<%= safePath %>/login.jsp">LogIn</a></li>
                    <li><a href="<%= safePath %>/Register.jsp">Register</a></li>
            <%
                }
            %>
            <li><a href="<%= safePath %>/contact.jsp">Contact</a></li>
        </ul>
    </div>

    <div id="Main-Container">
    <br/>
    <div id="logo">
        <h1><%= safeSiteTitleHtml %></h1>
    </div>
    <br/>

    <div id="Main">