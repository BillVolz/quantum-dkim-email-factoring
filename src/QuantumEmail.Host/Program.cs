using System.Numerics;
using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using DnsClient;
using DnsClient.Protocol;
using Microsoft.Quantum.Simulation.Core;
using Microsoft.Quantum.Simulation.Simulators;

namespace QuantumEmail.Host
{
    internal class Program
    {
        static async Task Main(string[] args)
        {
            var mailDomain = "microsoft.com";
            var mailSelector = "s1024-meo";

            var largePrime = await GetDkimKeyAsync(mailDomain, mailSelector);
            /*
             * RSA keys are based on:

                Public Key: (n, e)

                Private Key: (n, d)

                n = p * q is the modulus

                e is the public exponent

                d is the private exponent
            */
             

            if (string.IsNullOrEmpty(largePrime))
            {
                Console.WriteLine("No DKIM key found.");
                return;
            }

            using RSA rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(largePrime), out _);

            RSAParameters parameters = rsa.ExportParameters(false);
            BigInteger n = new BigInteger(parameters.Modulus, isUnsigned: true, isBigEndian: true);
            BigInteger e = new BigInteger(parameters.Exponent, isUnsigned: true, isBigEndian: true);

            Console.WriteLine($"Modulus (n): {n}");
            Console.WriteLine($"Exponent (e): {e}");

            int qnum = 15;
            int qa = 2;

            //ToDo: Add BigInteger support to Q# QuantumMultiplyByModulus
            using var sim = new QuantumSimulator();
            var array = new QArray<Qubit>();
            var res = await Quantum.QuantumEmail.QuantumMultiplyByModulus.Run(sim,qnum,qa, array);

            BigInteger p = 0;
            BigInteger q = 0;

            // Brute force loop: try every odd number from 3 up to sqrt(n)
            BigInteger i = 3;
            BigInteger sqrtN = Sqrt(n);
            while (i <= sqrtN)
            {
                if (n % i == 0)
                {
                    p = i;
                    q = n / i;
                    break;
                }
                i += 2;
            }

            if (p != 0)
            {
                Console.WriteLine("Failed to factor n.");
                return;
            }



            Console.WriteLine($"Found factors: p = {p}, q = {q}");

            BigInteger phi = (p - 1) * (q - 1);
            BigInteger d = ModInverse(e, phi);
            Console.WriteLine($"Private exponent d = {d}");

            


            // Message must be < n
            BigInteger message = new BigInteger(123456);

            // Encrypt with public key: c = m^e mod n
            BigInteger ciphertext = BigInteger.ModPow(message, e, n);

            // Decrypt with private key: m' = c^d mod n
            BigInteger decrypted = BigInteger.ModPow(ciphertext, d, n);



            BigInteger N = new BigInteger(Convert.FromBase64String(largePrime));
            BigInteger a = 2; // choose coprime a

            if (BigInteger.GreatestCommonDivisor(a, N) != 1)
            {
                Console.WriteLine("Not coprime.");
                return;
            }

            // Send a, N to Q# quantum operation (for period finding)
            var r = 1;// RunQuantumPeriodFinding(a, N); // Q# call

            if (r % 2 != 0)
            {
                Console.WriteLine("r is not even, retry");
                return;
            }

            BigInteger y = BigInteger.ModPow(a, r / 2, N);
            BigInteger factor1 = BigInteger.GreatestCommonDivisor(y - 1, N);
            BigInteger factor2 = BigInteger.GreatestCommonDivisor(y + 1, N);

            Console.WriteLine($"Factors: {factor1}, {factor2}");
        }

        // Compute modular inverse of a mod m using Extended Euclidean Algorithm
        static BigInteger ModInverse(BigInteger a, BigInteger m)
        {
            BigInteger m0 = m, t, q;
            BigInteger x0 = 0, x1 = 1;

            if (m == 1) return 0;

            while (a > 1)
            {
                q = a / m;
                t = m;
                m = a % m; a = t;
                t = x0;
                x0 = x1 - q * x0; x1 = t;
            }

            if (x1 < 0) x1 += m0;

            return x1;
        }

        public static BigInteger Sqrt(BigInteger n)
        {
            if (n < 0)
            {
                throw new ArgumentException("Cannot calculate the square root of a negative number.");
            }

            if (n == 0)
            {
                return 0;
            }

            BigInteger root = n;
            BigInteger prevRoot;

            do
            {
                prevRoot = root;
                root = (root + n / root) / 2;
            } while (root < prevRoot && root != 0);

            return root;
        }

        public static async Task<string?> GetDkimKeyAsync(string domain, string selector)
        {
            string query = $"{selector}._domainkey.{domain}";
            try
            {
                var dnsClient = new DnsClient.LookupClient();
                var txtRecords = await dnsClient.QueryAsync(new DnsQuestion(query,QueryType.TXT));
                var builder = new StringBuilder();
                foreach (var record in txtRecords.Answers)
                {
                    if(record is TxtRecord txtRecord)
                        builder.Append(string.Join("", txtRecord.Text));
                }
                var items = builder.ToString().Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var item in items)
                {
                    if (item.Contains("p="))
                    {
                        var key = item.Split(new[] { '=' }, 2);
                        if (key.Length == 2)
                        {
                            return key[1].Trim();
                        }
                    }
                }

                return null;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error fetching DKIM key: {ex.Message}");
                return null;
            }
        }
    }
}
