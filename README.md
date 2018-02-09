# WebApiCoreSecurity
Using ASP.NET Core Web API Identity With JWT and TFA Authenticator

This is a work in progress project. 

This ASP.NET Core 2.0 Web API uses Identity Tables and JWT to authenticate and authorize users as well as
user, role and userRole management.

I have got the authenticator working as well but the timing doesn't seem to reflect what on the Authenticator app.

* Added middleware to check for IP addresses, invalid IP request get a 403.

This is being tested with Google Postman.

### Auth (Account)

POST http://localhost:65048/api/auth/token

POST http://localhost:65048/api/auth/2fa

POST http://localhost:65048/api/auth/register

GET  http://localhost:65048/api/auth/ConfirmEmail?Id=xxx&code=xxx

POST http://localhost:65048/api/auth/ForgotPassword

POST http://localhost:65048/api/auth/ResetPassword?code=xxx


### Manage

POST http://localhost:65048/api/manage/SendVerificationEmail

POST http://localhost:65048/api/manage/ChangePassword

GET  http://localhost:65048/api/manage/EnableAuthenticator

POST http://localhost:65048/api/manage/EnableAuthenticator

POST http://localhost:65048/api/manage/GenerateRecoveryCodes

POST http://localhost:65048/api/manage/ResetAuthenticator

POST http://localhost:65048/api/manage/Disable2fa

GET  http://localhost:65048/api/manage/TwoFactorAuthentication

POST http://localhost:65048/api/manage/SetPassword


### Role

GET  http://localhost:65048/api/role

POST http://localhost:65048/api/role/InsertUpdate

DELETE http://localhost:65048/api/role?id=xxx


### User

GET  http://localhost:65048/api/user

GET  http://localhost:65048/api/user?id=xxx

POST http://localhost:65048/api/user/InsertWithRole

PUT  http://localhost:65048/api/user/Update

DELETE http://localhost:65048/api/user?id=xxx


### UserRoles

GET  http://localhost:65048/api/UserRoles/GetUserRoles?id=xxx

DELETE http://localhost:65048/api/UserRoles/RemoveFromRole?id=352bf910-ea1a-455e-b4a0-f49e585c3eff

POST http://localhost:65048/api/UserRoles/AddToRole
