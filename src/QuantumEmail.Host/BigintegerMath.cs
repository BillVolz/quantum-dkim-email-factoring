using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using DnsClient;
using DnsClient.Protocol;

namespace QuantumEmail.Host;

internal class BigintegerMath
{

    public static (BigInteger n, BigInteger e)? GetRsaParameters(string largePrime)
    {
        using RSA rsa = RSA.Create();
        try
        {
            rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(largePrime), out _);
            RSAParameters parameters = rsa.ExportParameters(false);
            BigInteger n = new BigInteger(parameters.Modulus, isUnsigned: true, isBigEndian: true);
            BigInteger e = new BigInteger(parameters.Exponent, isUnsigned: true, isBigEndian: true);
            return (n, e);
        }
        catch
        {
            return null;
        }
    }

    // Pollard's rho O(n^1/4) — still infeasible for RSA-1024 but vastly better than trial division for smaller keys.
    public static (BigInteger p, BigInteger q) FactorizeModulus(BigInteger n)
    {
        if (n % 2 == 0) return (2, n / 2);

        for (BigInteger c = 1; c < 20; c++)
        {
            BigInteger x = 2, y = 2, d = 1;
            while (d == 1)
            {
                x = (x * x + c) % n;
                y = (y * y + c) % n;
                y = (y * y + c) % n;
                d = BigInteger.GreatestCommonDivisor(BigInteger.Abs(x - y), n);
            }
            if (d != n) return (d, n / d);
        }
        return (0, 0);
    }

    public static BigInteger CalculatePrivateExponent(BigInteger e, BigInteger p, BigInteger q)
    {
        BigInteger phi = (p - 1) * (q - 1);
        return ModInverse(e, phi);
    }

    public static BigInteger EncryptMessage(BigInteger message, BigInteger e, BigInteger n)
    {
        return BigInteger.ModPow(message, e, n);
    }

    public static BigInteger DecryptMessage(BigInteger ciphertext, BigInteger d, BigInteger n)
    {
        return BigInteger.ModPow(ciphertext, d, n);
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
            var txtRecords = await dnsClient.QueryAsync(new DnsQuestion(query, QueryType.TXT));
            var builder = new StringBuilder();
            foreach (var record in txtRecords.Answers)
            {
                if (record is TxtRecord txtRecord)
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