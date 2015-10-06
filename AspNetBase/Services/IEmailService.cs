using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Mail;
using System.Threading.Tasks;
using System.Web;

namespace AspNetBase.Services
{
    public interface IEmailService
    {
        void SendEmail(MailAddress recipient, string subject, string body, bool allowUnsubscribe = true, bool inlineCss = true);
    }
}