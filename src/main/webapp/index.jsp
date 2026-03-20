<%@ include file="header.jsp" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>

<c:if test="${not empty sessionScope.user}">
    Hello <c:out value="${sessionScope.user}" />,
</c:if>

Welcome to Java Vulnerable Lab !<br/><br/>
A Deliberately vulnerable Web Application built on JAVA designed to teach Web Application Security.

<%@ include file="footer.jsp" %>
