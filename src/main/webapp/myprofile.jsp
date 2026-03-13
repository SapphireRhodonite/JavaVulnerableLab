<%@ include file="/header.jsp" %>
<%@page import="java.sql.Connection"%>
<%@page import="java.sql.PreparedStatement"%>
<%@page import="java.sql.ResultSet"%>
<%@page import="org.cysecurity.cspf.jvl.model.DBConnect"%>
<%@page import="org.owasp.encoder.Encode"%>

<%
if ("1".equals(String.valueOf(session.getAttribute("isLoggedIn")))) {

    String sessionUserId = String.valueOf(session.getAttribute("userid"));

    if (sessionUserId != null && !sessionUserId.trim().isEmpty()) {

        String userSql = "SELECT username, email, about FROM users WHERE id = ?";
        String cardSql = "SELECT cardno, expirydate FROM cards WHERE id = ?";

        try (
            Connection con = new DBConnect().connect(getServletContext().getRealPath("/WEB-INF/config.properties"));
            PreparedStatement userPs = con.prepareStatement(userSql);
            PreparedStatement cardPs = con.prepareStatement(cardSql)
        ) {
            userPs.setString(1, sessionUserId);

            try (ResultSet rs = userPs.executeQuery()) {
                if (rs.next()) {
                    out.print("UserName : " + Encode.forHtml(rs.getString("username")) + "<br>");
                    out.print("Email : " + Encode.forHtml(rs.getString("email")) + "<br>");
                    out.print("About : " + Encode.forHtml(rs.getString("about")) + "<br>");

                    cardPs.setString(1, sessionUserId);
                    try (ResultSet rs1 = cardPs.executeQuery()) {
                        if (rs1.next()) {
                            String cardNo = rs1.getString("cardno");
                            String expiryDate = rs1.getString("expirydate");

                            String maskedCard = "****";
                            if (cardNo != null) {
                                String digitsOnly = cardNo.replaceAll("\\s+", "");
                                if (digitsOnly.length() >= 4) {
                                    maskedCard = "**** **** **** " + digitsOnly.substring(digitsOnly.length() - 4);
                                }
                            }

                            out.print("<br/>-------------------<br/>Card Details:<br/>-------------------<br/>");
                            out.print("Card Number: " + Encode.forHtml(maskedCard) + "<br/>");
                            out.print("Expiry Date: " + Encode.forHtml(expiryDate == null ? "" : expiryDate) + "<br/>");
                        } else {
                            out.print("<br/>No Card Details Found: <a href='changeCardDetails.jsp'>Add Card</a><br/>");
                        }
                    }
                } else {
                    out.print("Profile not found");
                }
            }

            out.print("<br/><ul type='square'>");
            out.print("<li><a href='" + path + "/vulnerability/csrf/change-info.jsp'>Change Description</a></li>");
            out.print("<li><a href='" + path + "/vulnerability/csrf/changepassword.jsp'>Change Password</a></li>");
            out.print("<li><a href='" + path + "/vulnerability/idor/change-email.jsp'>Change Email</a></li>");
            out.print("<li><a href='" + path + "/vulnerability/Messages.jsp'>Messages </a></li>");
            out.print("<li><a href='" + path + "/vulnerability/SendMessage.jsp'>Send Message </a></li>");
            out.print("</ul><br/>");
            out.print("<br/><a href='" + path + "/vulnerability/forum.jsp'>Return to Forum &gt;&gt;</a>");

        } catch (Exception e) {
            out.print("Something went wrong");
        }
    } else {
        out.print("Invalid session");
    }

} else {
    out.print("Please login to see your profile");
}
%>

<%@ include file="/footer.jsp" %>
