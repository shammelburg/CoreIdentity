using System;
using System.Data.SqlClient;
using System.Threading.Tasks;

namespace CoreIdentity.API.Services
{
    public interface IEmailService
    {
        Task SendAsync(string EmailDisplayName, string Subject, string Body, string From, string To);

        Task SendEmailConfirmationAsync(string Email, string CallbackUrl);

        Task SendPasswordResetAsync(string Email, string CallbackUrl);

        Task SendException(Exception ex);

        Task SendSqlException(SqlException ex);
    }
}
