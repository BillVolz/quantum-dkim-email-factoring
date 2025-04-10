using System;
using System.Net;
using System.Net.Mail;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace QuantumEmail.Host
{
    internal class SendMail
    {

        public static async Task SendEmailWithDkim(string fromEmail, string toEmail, string subject, string body, string dkimDomain, string dkimSelector, RSA privateKey)
        {
            try
            {
                var message = new MailMessage(fromEmail, toEmail, subject, body);
                message.Headers.Add("DKIM-Signature", GenerateDkimHeader(message, dkimDomain, dkimSelector, privateKey));

                using var smtpClient = new SmtpClient("smtp.yourdomain.com")
                {
                    Port = 587,
                    Credentials = new NetworkCredential("your-username", "your-password"),
                    EnableSsl = true
                };

                await smtpClient.SendMailAsync(message);
                Console.WriteLine("Email sent successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error sending email: {ex.Message}");
            }
        }

        private static string GenerateDkimHeader(MailMessage message, string domain, string selector, RSA privateKey)
        {
            string header = $"v=1; a=rsa-sha256; d={domain}; s={selector}; c=relaxed/simple; q=dns/txt; t={DateTimeOffset.UtcNow.ToUnixTimeSeconds()}; h=from:to:subject:date:message-id; bh={ComputeBodyHash(message.Body)}; b=";
            string canonicalizedHeader = CanonicalizeHeader(message, header);
            string signature = SignData(canonicalizedHeader, privateKey);
            return header + signature;
        }

        private static string CanonicalizeHeader(MailMessage message, string header)
        {
            var builder = new StringBuilder();
            builder.AppendLine($"from:{message.From}");
            builder.AppendLine($"to:{message.To}");
            builder.AppendLine($"subject:{message.Subject}");
            builder.AppendLine($"date:{DateTime.UtcNow:R}");
            builder.AppendLine($"message-id:{message.Headers["Message-ID"]}");
            builder.Append(header);
            return builder.ToString();
        }

        private static string ComputeBodyHash(string body)
        {
            using var sha256 = SHA256.Create();
            byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(body));
            return Convert.ToBase64String(hash);
        }

        private static string SignData(string data, RSA rsa)
        {
            byte[] dataBytes = Encoding.UTF8.GetBytes(data);
            byte[] signatureBytes = rsa.SignData(dataBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return Convert.ToBase64String(signatureBytes);
        }
    }
}
