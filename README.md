# CoreIdentity
Using ASP.NET Core Identity Web API With JWT, TFA, Swagger, Sendgrid, EF Core and Azure Storage

This ASP.NET Core 3.1 Web API uses Identity Tables and JWT to authenticate and authorize users as well as
user, role and userRole management.

This project has everything you need to get started with ASP.NET Core Web API.

- ASP.NET Core Web API
- ASP.NET Core Identity (SQL Server)
- Entity Framework Core (SQL Server)
- JWT
- Two Factor Authentication
- Swagger (Documentation)
- SendGrid (Email) 
- Error Handling Middleware
- CORS Middleware

- Azure Storage
  - Blob
  - Queue

# Getting Started
To get started locate the `appsettings.Development.json` and supply your connectionString.

To activate emails in the API you can also enter SendGrid (free account through Azure Portal) account credentials.

Now run the API, register, confirm your email, login and receive JWT, add JWT to Authorize Header for every request after.


