/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package org.cysecurity.cspf.jvl.controller;

import java.io.IOException;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.cysecurity.cspf.jvl.model.DBConnect;

/**
 *
 * @author breakthesec
 */
public class Register extends HttpServlet {

    /**
     * Processes requests for both HTTP <code>GET</code> and <code>POST</code>
     * methods.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
       try {
            PrintWriter out = response.getWriter();
            Connection con=new DBConnect().connect(getServletContext().getRealPath("/WEB-INF/config.properties"));
         String user=request.getParameter("username");
          String pass=request.getParameter("password");
          String email=request.getParameter("email");
          String about=request.getParameter("About");
          String secret=request.getParameter("secret");
          if(secret==null || secret.equals(""))
          {
              secret="nosecret";
          }
            try
             {
                    if(con!=null && !con.isClosed())
                               {
                                  
                                   PreparedStatement createUserStmt = con.prepareStatement("INSERT into users(username, password, email, About,avatar,privilege,secretquestion,secret) values (?,?,?,?,'default.jpg','user',1,?)");
                                   createUserStmt.setString(1, user);
                                   createUserStmt.setString(2, pass);
                                   createUserStmt.setString(3, email);
                                   createUserStmt.setString(4, about);
                                   createUserStmt.setString(5, secret);
                                   createUserStmt.executeUpdate();

                                   PreparedStatement createMessageStmt = con.prepareStatement("INSERT into UserMessages(recipient, sender, subject, msg) values (?,'admin','Hi','Hi<br/> This is admin of this page. <br/> Welcome to Our Forum')");
                                   createMessageStmt.setString(1, user);
                                   createMessageStmt.executeUpdate();
             
                                    response.sendRedirect("index.jsp");
                                    
                               }
                    else
                    {
                         response.sendRedirect("Register.jsp");
                    }
                }
               catch(SQLException ex)
                {
                          System.out.println("SQLException: " + ex.getMessage());
                         System.out.println("SQLState: " + ex.getSQLState());
                         System.out.println("VendorError: " + ex.getErrorCode());
                           
                       }
        
          }
        catch(Exception e)
        {
            
        }
    }

    // <editor-fold defaultstate="collapsed" desc="HttpServlet methods. Click on the + sign on the left to edit the code.">
    /**
     * Handles the HTTP <code>GET</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Handles the HTTP <code>POST</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Returns a short description of the servlet.
     *
     * @return a String containing servlet description
     */
    @Override
    public String getServletInfo() {
        return "Short description";
    }// </editor-fold>

}
