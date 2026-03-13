 <%@ include file="/header.jsp" %>
  <%@page import="java.sql.PreparedStatement"%>
<%@page import="java.sql.ResultSet"%>
<%@page import="java.sql.SQLException"%>
<%@page import="org.cysecurity.cspf.jvl.model.DBConnect"%>
<%@page import="java.sql.Connection"%>
<%@page import="org.apache.commons.text.StringEscapeUtils"%>

 <%
   Connection con=new DBConnect().connect(getServletContext().getRealPath("/WEB-INF/config.properties"));
    PreparedStatement pstmt = null; 
 if(request.getParameter("delete")!=null)
 {
     String user=request.getParameter("user");
     String deleteSql = "Delete from users where username=?";
     pstmt = con.prepareStatement(deleteSql);
     pstmt.setString(1, user);
     pstmt.executeUpdate();                      
 }
 %>	
<form action="manageusers.jsp" method="POST">	
<%
 String selectSql = "select * from users where privilege='user'";
 pstmt = con.prepareStatement(selectSql);
 ResultSet rs=pstmt.executeQuery();
 while(rs.next())
 {
     out.print("<input type='radio' name='user' value='"+StringEscapeUtils.escapeHtml4(rs.getString("username"))+"'/> "+StringEscapeUtils.escapeHtml4(rs.getString("username"))+"<br/>");
 }
 %>
<br/>
<input type="submit" value="Delete" name="delete"/>

</form>
<br/>
<a href="admin.jsp"> Back to Admin Panel</a>
 <%@ include file="/footer.jsp" %>