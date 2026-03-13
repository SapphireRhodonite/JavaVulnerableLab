<%@page import="org.apache.commons.text.StringEscapeUtils"%>
 <%@ include file="header.jsp" %>
 <%
 if(session.getAttribute("user")!=null)
{
    out.print("Hello "+StringEscapeUtils.escapeHtml4(session.getAttribute("user").toString())+",");
}
 %>
 Welcome to Java Vulnerable Lab !<br/><br/>
 A Deliberately vulnerable Web Application built on JAVA designed to teach Web Application Security. 
  <%@ include file="footer.jsp" %>