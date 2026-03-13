<%@ include file="/header.jsp" %>
<%@page import="java.sql.Connection"%>
<%@page import="java.sql.PreparedStatement"%>
<%@page import="org.cysecurity.cspf.jvl.model.DBConnect"%>
<%@page import="java.util.UUID"%>
<%@page import="org.owasp.encoder.Encode"%>

<%
if ("1".equals(String.valueOf(session.getAttribute("isLoggedIn")))) {

    String id = String.valueOf(session.getAttribute("userid"));
    String action = request.getParameter("action");

    String csrfToken = (String) session.getAttribute("csrfToken");
    if (csrfToken == null) {
        csrfToken = UUID.randomUUID().toString();
        session.setAttribute("csrfToken", csrfToken);
    }
%>
    Change Credit Card Info:<br/><br/>
    <form action="changeCardDetails.jsp" method="POST" autocomplete="off">
        <input type="hidden" name="csrfToken" value="<%= Encode.forHtmlAttribute(csrfToken) %>" />
        <table>
            <tr>
                <td>Card Number:</td>
                <td><input type="text" name="cardno" value="" maxlength="19"/></td>
            </tr>
            <tr>
                <td>CVV:</td>
                <td><input type="password" name="cvv" value="" maxlength="4"/></td>
            </tr>
            <tr>
                <td>Expiry Date:</td>
                <td><input type="text" name="expirydate" value="" maxlength="7" placeholder="MM/YYYY"/></td>
            </tr>
            <tr>
                <td></td>
                <td><input type="submit" name="action" value="add"/></td>
            </tr>
        </table>
    </form>
    <br/>
<%
    try {
        if (action != null && action.equalsIgnoreCase("add")) {

            String requestToken = request.getParameter("csrfToken");
            if (requestToken == null || !requestToken.equals(session.getAttribute("csrfToken"))) {
                out.print("<b style='color:red'>* Invalid request *</b>");
            } else {
                String cardno = request.getParameter("cardno");
                String cvv = request.getParameter("cvv");
                String expirydate = request.getParameter("expirydate");

                if (cardno == null) cardno = "";
                if (cvv == null) cvv = "";
                if (expirydate == null) expirydate = "";

                cardno = cardno.trim();
                cvv = cvv.trim();
                expirydate = expirydate.trim();

                boolean validCard = cardno.matches("\\d{13,19}");
                boolean validCvv = cvv.matches("\\d{3,4}");
                boolean validExpiry = expirydate.matches("(0[1-9]|1[0-2])/\\d{4}");

                if (!cardno.isEmpty() && !cvv.isEmpty() && !expirydate.isEmpty()
                        && validCard && validCvv && validExpiry) {

                    try (
                        Connection con = new DBConnect().connect(
                            getServletContext().getRealPath("/WEB-INF/config.properties"));
                        PreparedStatement ps = con.prepareStatement(
                            "INSERT INTO cards (id, cardno, cvv, expirydate) VALUES (?, ?, ?, ?)")
                    ) {
                        ps.setString(1, id);
                        ps.setString(2, cardno);
                        ps.setString(3, cvv);
                        ps.setString(4, expirydate);
                        ps.executeUpdate();

                        session.setAttribute("csrfToken", UUID.randomUUID().toString());
                        out.print("<b style='color:green'>* Card details added *</b>");
                    }
                } else {
                    out.print("<b style='color:red'>* Invalid card details *</b>");
                }
            }
        }

        out.print("<br/><br/><a href='" + path + "/myprofile.jsp?id="
                + Encode.forUriComponent(id)
                + "'>Return to Profile Page &gt;&gt;</a>");

    } catch (Exception e) {
        out.print("<b style='color:red'>* Something went wrong *</b>");
    }

} else {
    out.print("Please login to view this page");
}
%>

<%@ include file="/footer.jsp" %>
