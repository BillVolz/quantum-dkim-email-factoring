using System.Numerics;
using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using Microsoft.Quantum.Simulation.Core;
using Microsoft.Quantum.Simulation.Simulators;
using Quantum.QuantumEmail;

namespace QuantumEmail.Host
{
    internal class Program
    {
        static async Task Main(string[] args)
        {
            var mailDomain = "microsoft.com";
            var mailSelector = "s1024-meo";

            var largePrime = await BigintegerMath.GetDkimKeyAsync(mailDomain, mailSelector);
            if (string.IsNullOrEmpty(largePrime))
            {
                Console.WriteLine("No DKIM key found.");
                return;
            }

            var rsaParameters = BigintegerMath.GetRsaParameters(largePrime);
            if (rsaParameters == null)
            {
                Console.WriteLine("Failed to import RSA parameters.");
                return;
            }

            /*
               RSA keys are based on:

               Public Key: (n, e)

               Private Key: (n, d)

               n = p * q is the modulus

               e is the public exponent

               d is the private exponent
           */

            var (n, e) = rsaParameters.Value;
            Console.WriteLine($"Modulus (n): {n}");
            Console.WriteLine($"Exponent (e): {e}");

            int qnum = 15;
            int qa = 2;

            // ToDo: Add BigInteger support to Q# QuantumMultiplyByModulus
            using var sim = new QuantumSimulator();
            var res = await Quantum.QuantumEmail.QuantumPeriodFinding.Run(sim, qnum, qa);

            //Non-Quantum version.  If you have many years of time, you can use this.
            var (p, q) = BigintegerMath.FactorizeModulus(n);
            if (p == 0 || q == 0)
            {
                Console.WriteLine("Failed to factor n.");
                return;
            }


            Console.WriteLine($"Found factors: p = {p}, q = {q}");

            var d = BigintegerMath.CalculatePrivateExponent(e, p, q);
            Console.WriteLine($"Private exponent d = {d}");

            var message = new BigInteger(123456);
            var ciphertext = BigintegerMath.EncryptMessage(message, e, n);
            var decrypted = BigintegerMath.DecryptMessage(ciphertext, d, n);

            Console.WriteLine($"Encrypted message: {ciphertext}");
            Console.WriteLine($"Decrypted message: {decrypted}");

            await SendEmailWithDkim(mailDomain, mailSelector, n, e);
        }

        private static async Task SendEmailWithDkim(string mailDomain, string mailSelector, BigInteger n, BigInteger e)
        {
            var rsaSending = RSA.Create();
            rsaSending.ImportParameters(new RSAParameters
            {
                Modulus = n.ToByteArray(),
                Exponent = e.ToByteArray()
            });

            await SendMail.SendEmailWithDkim($"Test@{mailDomain}", "test@example.com", "Test Subject",
                "Hello, this is my DKIM signed email.", mailDomain, mailSelector, rsaSending);
        }
    }
}
