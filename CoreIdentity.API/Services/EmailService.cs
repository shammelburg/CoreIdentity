using CoreIdentity.API.Settings;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Options;
using SendGrid;
using SendGrid.Helpers.Mail;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace CoreIdentity.API.Services
{
    public class EmailService : IEmailService
    {
        private readonly EmailSettings _email;
        private readonly IWebHostEnvironment _env;

        public EmailService(IOptions<EmailSettings> email, IWebHostEnvironment env)
        {
            _email = email.Value;
            _env = env;
        }


        public async Task SendAsync(string EmailDisplayName, string Subject, string Body, string From, string To)
        {
            await SendSendGridMessage(From, EmailDisplayName, new List<EmailAddress> { new EmailAddress(To) }, Subject, Body).ConfigureAwait(false);
        }

        public async Task SendEmailConfirmationAsync(string EmailAddress, string CallbackUrl)
        {
            var Subject = "Confirm your email";
            var HTMLContent = $"Please confirm your email by clicking here: <a href='{CallbackUrl}'>link</a>";

            await SendSendGridMessage(_email.From, _email.DisplayName, new List<EmailAddress> { new EmailAddress(EmailAddress) }, Subject, HTMLContent).ConfigureAwait(false);
        }

        public async Task SendPasswordResetAsync(string EmailAddress, string CallbackUrl)
        {
            var Subject = "Reset your password";
            var HTMLContent = $"Please reset your password by clicking here: <a href='{CallbackUrl}'>link</a>";

            await SendSendGridMessage(_email.From, _email.DisplayName, new List<EmailAddress> { new EmailAddress(EmailAddress) }, Subject, HTMLContent).ConfigureAwait(false);
        }

        public async Task SendException(Exception ex)
        {
            var Subject = $"[{_env.EnvironmentName}] INTERNAL SERVER ERROR";
            var HTMLContent = $"{ex.ToString()}";

            await SendSendGridMessage(_email.From, _email.DisplayName, new List<EmailAddress> { new EmailAddress(_email.To) }, Subject, HTMLContent).ConfigureAwait(false);
        }

        public async Task SendSqlException(SqlException ex)
        {
            var Subject = $"[{_env.EnvironmentName}] SQL ERROR";
            var HTMLContent = $"{ex.ToString()}";

            await SendSendGridMessage(_email.From, _email.DisplayName, new List<EmailAddress> { new EmailAddress(_email.To) }, Subject, HTMLContent).ConfigureAwait(false);
        }

        private async Task SendSendGridMessage(string From, string EmailDisplayName, List<EmailAddress> tos, string Subject, string HTMLContent)
        {
            var client = new SendGridClient(_email.SendGridApiKey);
            var from = new EmailAddress(From, EmailDisplayName);
            var msg = MailHelper.CreateSingleEmailToMultipleRecipients(from, tos, Subject, "", HTMLContent, false);
            var response = await client.SendEmailAsync(msg).ConfigureAwait(false);
        }
    }
}
