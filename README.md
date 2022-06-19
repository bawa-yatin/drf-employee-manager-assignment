# DRF Employee Manager Assignment. All the following points have been covered in this assignment

1. Create a Custom user model with 3 roles (superuser, manager, employee)
2. Email and mobile no. fields should be unique.
3. Superuser should be created only through API.
4. Manager can register himself through signup API.
5. Manager should create the employee, and upon successful registration, employee should get
system generated welcome mail with his credentials(email & randomly generated password).
6. Manager can perform crud operations for employee.
7. Employee cannot register himself.
8. Employee can use his credentials to login and get his profile details only, i.e. employee
should not be allowed to access any other part of API.
9. Functionality for forgot password, login
10. Jwt authentication, employee and manager custom permissions
11. Create a logout API to blacklist user.
12. Use class based views and Generic Views only
