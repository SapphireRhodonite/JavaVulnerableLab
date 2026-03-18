<%@page import="org.apache.commons.text.StringEscapeUtils"%>
 <%@ include file="/header.jsp" %>
 <%@page import="java.sql.Connection"%>
<%@page import="java.sql.PreparedStatement"%>
<%@page import="java.sql.Statement"%>
<%@page import="java.sql.SQLException"%>

<%@page import="java.sql.ResultSetMetaData"%>
<%@page import="java.sql.ResultSet"%>
<%@ page import="java.util.*,java.io.*"%>
<%@ page import="org.cysecurity.cspf.jvl.model.DBConnect"%>

<%
if(session.getAttribute("isLoggedIn")!=null)
{
 Connection con=new DBConnect().connect(getServletContext().getRealPath("/WEB-INF/config.properties"));
         
   String id=request.getParameter("id");
   if(id!=null && !id.equals(""))
   {
        PreparedStatement stmt = con.prepareStatement("select * from users where id=?");
        stmt.setInt(1, Integer.parseInt(id));
        ResultSet rs = stmt.executeQuery();
        if(rs != null && rs.next())
        {
            out.print("UserName : "+StringEscapeUtils.escapeHtml4(rs.getString("username"))+"<br>"); 
            out.print("Email : "+StringEscapeUtils.escapeHtml4(rs.getString("email"))+"<br>"); 
            out.print("About : "+StringEscapeUtils.escapeHtml4(rs.getString("about"))+"<br>"); 
                 
            PreparedStatement stmtCards = con.prepareStatement("select * from cards where id=?");
            stmtCards.setInt(1, Integer.parseInt(id));
            ResultSet rs1 = stmtCards.executeQuery();
            if(rs1 != null && rs1.next())
            {
                out.print("<br/>-------------------<br/>Card Details:<br/>-------------------<br/>");
                out.print("Card Number: "+StringEscapeUtils.escapeHtml4(rs1.getString("cardno"))+"<br/>");
                out.print("CVV: "+StringEscapeUtils.escapeHtml4(rs1.getString("cvv"))+"<br/>");
                out.print("Expiry Date: "+StringEscapeUtils.escapeHtml4(rs1.getString("expirydate"))+"<br/>");
            }
            else
            {
                out.print("<br/>No Card Details Found: <a href='changeCardDetails.jsp'>Add Card</a><br/>");
            }
        }
   }
   else
   {
       out.print("ID Parameter is Missing");
   }
     
   out.print("<br/><ul type='square'>");
   out.print("<li><a href='"+path+"/vulnerability/csrf/change-info.jsp'>Change Description</a></li>");
   out.print("<li><a href='"+path+"/vulnerability/csrf/changepassword.jsp'>Change Password</a></li>");
   out.print("<li><a href='"+path+"/vulnerability/idor/change-email.jsp'>Change Email</a></li>");
   out.print("<li><a href='"+path+"/vulnerability/Messages.jsp'>Messages </a></li>"); 
   out.print("<li><a href='"+path+"/vulnerability/SendMessage.jsp'>Send Message </a></li>"); 
   out.print("</ul><br/>");
   out.print("<br/><a href='"+path+"/vulnerability/forum.jsp'>Return to Forum &gt;&gt;</a>");     
    
}
else
{
    out.print("Please login to see Your Profile");
}

  %>
  
 <%@ include file="/footer.jsp" %>
