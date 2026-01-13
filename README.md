Vulnerable Flask Web Application (OWASP TOP 10)

Project Overview
This project demonstrates the real-world vulnerabilities in a web application aligned with OWASP TOP 10. This project runs in a localhost only

The goal of this project is:
1) Learn how vulnerabilities are present in a backend application
2) How attackers can exploit insecure login
3) Practice documenting a pentest report for the vulnerabilties present.

Technology Stack
Backend: Python (Flask)
Database: MSSQL Server
Database connection:pyodbc
Frontend: HTML
Authentication: Flask sessions
Environment: localhost only, windows

Application Features
1) User registration and login
2) search for user
3) admin endpoint to check user functionality
4) session based authentication
5) local database integration with MSSQL

The Vulnerabilities present in our application:
1) Broken access control/IDOR
2) SQL Injection
3) Cross site scripting