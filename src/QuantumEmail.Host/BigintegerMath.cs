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
    // MaxIterations per polynomial prevents hanging on prime/malformed inputs or rho cycles that don't converge.
    public static (BigInteger p, BigInteger q) FactorizeModulus(BigInteger n, int maxIterationsPerC = 1_000_000)
    {
        if (n % 2 == 0) return (2, n / 2);

        for (BigInteger c = 1; c < 20; c++)
        {
            BigInteger x = 2, y = 2, d = 1;
            for (int i = 0; i < maxIterationsPerC && d == 1; i++)
            {
                x = (x * x + c) % n;
                y = (y * y + c) % n;
                y = (y * y + c) % n;
                d = BigInteger.GreatestCommonDivisor(BigInteger.Abs(x - y), n);
            }
            if (d > 1 && d < n) return (d, n / d);
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

    // Returns a random a where 1 < a < n and gcd(a, n) == 1.
    // If gcd(a, n) > 1 on the first try, that value IS a factor — check before calling the circuit.
    public static BigInteger PickCoprime(BigInteger n)
    {
        using var rng = RandomNumberGenerator.Create();
        while (true)
        {
            var bytes = new byte[n.GetByteCount(isUnsigned: true)];
            rng.GetBytes(bytes);
            var a = new BigInteger(bytes, isUnsigned: true) % (n - 2) + 2;
            if (BigInteger.GreatestCommonDivisor(a, n) == 1) return a;
        }
    }

    // Convert a bit array (MSB first) to a BigInteger.
    public static BigInteger BitsToInt(bool[] bits)
    {
        BigInteger result = 0;
        foreach (bool b in bits)
            result = (result << 1) | (b ? BigInteger.One : BigInteger.Zero);
        return result;
    }

    // Yield continued-fraction convergent denominators of p/q, up to maxDenom.
    public static IEnumerable<BigInteger> ContinuedFractionDenominators(BigInteger p, BigInteger q, BigInteger maxDenom)
    {
        BigInteger h0 = 1, h1 = 0;
        while (q != 0)
        {
            BigInteger a = p / q;
            BigInteger hn = a * h1 + h0;
            if (hn > maxDenom) yield break;
            if (hn > 0) yield return hn;
            h0 = h1;
            h1 = hn;
            BigInteger r = p % q;
            p = q;
            q = r;
        }
    }

    // Interpret the QFT output xBits as the fraction measured/2^n1, apply continued
    // fractions to extract period candidates, and return the first r where a^r ≡ 1 (mod N).
    public static BigInteger FindPeriodFromMeasurements(bool[] xBits, BigInteger a, BigInteger N)
    {
        int n1 = xBits.Length;
        BigInteger measured = BitsToInt(xBits);
        if (measured == 0) return 0;

        BigInteger domainSize = BigInteger.Pow(2, n1);
        foreach (BigInteger r in ContinuedFractionDenominators(measured, domainSize, N))
        {
            if (r > 0 && BigInteger.ModPow(a, r, N) == 1)
                return r;
        }
        return 0;
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