<%@page import="org.apache.commons.text.StringEscapeUtils"%>
 <%@ include file="/header.jsp" %>
  <%@page import="java.sql.PreparedStatement"%>
<%@page import="java.sql.Statement"%>
<%@page import="java.sql.ResultSet"%>
<%@page import="java.sql.SQLException"%>
<%@page import="org.cysecurity.cspf.jvl.model.DBConnect"%>
<%@page import="java.sql.Connection"%>

 <%
   Connection con=new DBConnect().connect(getServletContext().getRealPath("/WEB-INF/config.properties"));
 if(request.getParameter("delete")!=null)
 {
     String user=request.getParameter("user");
     PreparedStatement deleteStmt = con.prepareStatement("Delete from users where username=?");
     deleteStmt.setString(1, user);
     deleteStmt.executeUpdate();
 }
 %>	
<form action="manageusers.jsp" method="POST">	
<%
 PreparedStatement stmt=con.prepareStatement("select * from users where privilege=?");
 stmt.setString(1, "user");
 ResultSet rs=stmt.executeQuery();
 while(rs.next())
 {
     String username = StringEscapeUtils.escapeHtml4(rs.getString("username"));
     out.print("<input type='radio' name='user' value='"+username+"'/> "+username+"<br/>");
 }
 %>
<br/>
<input type="submit" value="Delete" name="delete"/>

</form>
<br/>
<a href="admin.jsp"> Back to Admin Panel</a>
 <%@ include file="/footer.jsp" %>
