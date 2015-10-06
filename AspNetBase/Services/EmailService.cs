using System.Net.Mail;
using AspNetBase.DAL;
//using Nito.AsyncEx;
//using SendGrid;

namespace AspNetBase.Services
{
    public class EmailService : IEmailService
    {
        private readonly DataContext db;

        public EmailService(DataContext db)
        {
            this.db = db;
        }

        public void SendEmail(MailAddress recipient, string subject, string body, bool allowUnsubscribe = true, bool inlineCss = true)
        {
            SmtpClient sc = new SmtpClient();
            var message = new MailMessage(
                new MailAddress(Properties.Settings.Default.DefaultSenderEmail,
                    Properties.Settings.Default.DefaultSenderName),
                recipient);
            message.Subject = subject;
            if (inlineCss)
            {
                message.Body = PreMailer.Net.PreMailer.MoveCssInline(body).Html;
            }
            else
            {
                message.Body = body;
            }
            message.IsBodyHtml = true;

            // SendGrid implementation below
            /*
            SendGridMessage myMessage = new SendGridMessage();
            myMessage.To = new [] {recipient};
            myMessage.AddBcc("emil@estreambg.com");
            myMessage.From = new MailAddress("site@AspNetBase.com", "AspNetBase");
            myMessage.Subject = subject;
            if (inlineCss)
            {
                myMessage.Html = PreMailer.Net.PreMailer.MoveCssInline(body).Html;
            }
            else
            {
                myMessage.Html = body;
            }

            if (!allowUnsubscribe)
                myMessage.DisableUnsubscribe();

            var transportWeb = new Web(Properties.Settings.Default.SendGridAPIKey);

            // Send the email.
            transportWeb.DeliverAsync(myMessage).ContinueWith(resp => resp.Wait());
            */
        }
    }
}
