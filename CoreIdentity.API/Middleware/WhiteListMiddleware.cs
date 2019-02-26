using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using CoreIdentity.API.Helpers;

namespace CoreIdentity.API.Middleware
{
    // You may need to install the Microsoft.AspNetCore.Http.Abstractions package into your project
    public class WhiteListMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly string _adminWhiteList;

        public WhiteListMiddleware(RequestDelegate next, string adminWhiteList)
        {
            _next = next;
            _adminWhiteList = adminWhiteList;
        }

        public async Task Invoke(HttpContext httpContext)
        {
            //if (httpContext.Request.Method != "GET")

            string ipAddress = IpHelper.GetIpAddress();

            //_logger.LogInformation($"Request from Remote IP address: {remoteIp}");

            string[] ips = _adminWhiteList.Split(';');

            if (!ips.Any(option => option == ipAddress))
            {
                //_logger.LogInformation($"Forbidden Request from Remote IP address: {remoteIp}");
                httpContext.Response.StatusCode = (int)HttpStatusCode.Forbidden;
                httpContext.Response.Headers.Add("x-ip-check", "IP not allowed");
                return;
            }
            
            await _next(httpContext);
        }
    }

    // Extension method used to add the middleware to the HTTP request pipeline.
    public static class WhiteListMiddlewareExtensions
    {
        public static IApplicationBuilder UseWhiteListMiddleware(this IApplicationBuilder builder, string WhiteList)
        {
            return builder.UseMiddleware<WhiteListMiddleware>(WhiteList);
        }
    }
}
