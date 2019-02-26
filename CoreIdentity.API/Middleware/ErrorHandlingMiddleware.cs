using CoreIdentity.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using System.Threading.Tasks;

namespace CoreIdentity.Middleware
{
    public class ErrorHandlingMiddleware
    {
        private readonly RequestDelegate _next;

        public ErrorHandlingMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext httpContext, IEmailService _emailService)
        {
            try
            {
                await _next(httpContext);
            }
            catch (SqlException ex)
            {
                await _emailService.SendSqlException(ex);
                await HandleSqlExceptionAsync(httpContext, ex);
            }
            catch (Exception ex)
            {
                await _emailService.SendException(ex);
                await HandleExceptionAsync(httpContext, ex);
            }
        }

        private static Task HandleExceptionAsync(HttpContext context, Exception ex)
        {
            var result = JsonConvert.SerializeObject(new
            {
                Type = "General Exception",
                Exception = new
                {
                    Message = ex.Message,
                    Inner = ex.InnerException
                }
            });

            context.Response.ContentType = "application/json";
            context.Response.StatusCode = 500;
            return context.Response.WriteAsync(result);
        }

        private static Task HandleSqlExceptionAsync(HttpContext context, SqlException ex)
        {
            var errorList = new List<Object>();

            for (int i = 0; i < ex.Errors.Count; i++)
            {
                errorList.Add(new
                {
                    Message = ex.Errors[i].Message,
                    Procedure = ex.Errors[i].Procedure,
                    LineNumber = ex.Errors[i].LineNumber,
                    Source = ex.Errors[i].Source,
                    Server = ex.Errors[i].Server
                });
            }

            var result = JsonConvert.SerializeObject(new
            {
                Type = "SQL Exception",
                Exceptions = errorList
            });

            context.Response.ContentType = "application/json";
            context.Response.StatusCode = 500;
            return context.Response.WriteAsync(result);
        }
    }

    // Extension method used to add the middleware to the HTTP request pipeline.
    public static class ErrorHandlingMiddlewareExtensions
    {
        public static IApplicationBuilder UseErrorHandlingMiddleware(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<ErrorHandlingMiddleware>();
        }
    }
}
