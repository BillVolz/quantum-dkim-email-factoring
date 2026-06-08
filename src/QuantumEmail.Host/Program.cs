using System.Numerics;
using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using Microsoft.Quantum.Providers.Honeywell;
using Microsoft.Quantum.Simulation.Core;
using Microsoft.Quantum.Simulation.Simulators;
using Quantum.QuantumEmail;

namespace QuantumEmail.Host
{
    internal class Program
    {
        static async Task Main(string[] args)
        {
            var mailDomain = "example.com";
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

            // Quantum period-finding via Shor's algorithm.
            // On the simulator: use small test values — QuantumSimulator caps at ~30 qubits.
            // On hardware: swap to the real modulus by uncommenting the two lines below.
            System.Numerics.BigInteger qnum = 15;
            System.Numerics.BigInteger qa = 2;
            // qnum = n;
            // qa = BigintegerMath.PickCoprime(n);

            // Lucky early exit: if gcd(qa, qnum) > 1 we already have a factor.
            var luckyFactor = BigInteger.GreatestCommonDivisor(qa, qnum);
            if (luckyFactor > 1 && luckyFactor < qnum)
            {
                Console.WriteLine($"Lucky factor found without quantum circuit: {luckyFactor}");
            }

            // To target real Quantinuum hardware, set these four environment variables and
            // ensure you are authenticated via `az login`:
            //   AZURE_SUBSCRIPTION_ID, AZURE_RESOURCE_GROUP, AZURE_WORKSPACE_NAME, AZURE_LOCATION
            var workspaceName = Environment.GetEnvironmentVariable("AZURE_WORKSPACE_NAME");
            Microsoft.Quantum.Simulation.Core.IOperationFactory qmachine;
            if (!string.IsNullOrEmpty(workspaceName))
            {
                var workspace = new Microsoft.Azure.Quantum.Workspace(
                    subscriptionId: Environment.GetEnvironmentVariable("AZURE_SUBSCRIPTION_ID")!,
                    resourceGroupName: Environment.GetEnvironmentVariable("AZURE_RESOURCE_GROUP")!,
                    workspaceName: workspaceName,
                    location: Environment.GetEnvironmentVariable("AZURE_LOCATION") ?? "eastus"
                );
                qmachine = (IOperationFactory)new Microsoft.Quantum.Providers.Quantinuum.Targets.QuantinuumQuantumMachine("quantinuum.qpu.h1-1", workspace);
                Console.WriteLine("Submitting to Quantinuum H1-1 via Azure Quantum.");
                // For hardware, use the real RSA modulus and a random a coprime to n:
                // qnum = n;
                // qa = PickCoprime(n);
            }
            else
            {
                qmachine = new QuantumSimulator();
                Console.WriteLine("Running on local QuantumSimulator (set AZURE_WORKSPACE_NAME to target hardware).");
            }

            // Shor's algorithm is probabilistic: retry until a valid period is found.
            const int MaxRetries = 20;
            BigInteger period = 0;
            try
            {
                for (int attempt = 0; attempt < MaxRetries && period == 0; attempt++)
                {
                    var rawResults = await Quantum.QuantumEmail.RunPeriodFindingCircuit.Run(qmachine, qnum, qa);
                    bool[] xBits = rawResults.Select(r => r == Microsoft.Quantum.Simulation.Core.Result.One).ToArray();
                    period = BigintegerMath.FindPeriodFromMeasurements(xBits, qa, qnum);
                    if (period == 0)
                        Console.WriteLine($"Attempt {attempt + 1}: no period found, retrying...");
                }
            }
            finally
            {
                if (qmachine is IDisposable disposable) disposable.Dispose();
            }

            if (period > 0)
                Console.WriteLine($"Quantum period found: r = {period}");
            else
                Console.WriteLine("Quantum period finding did not converge; proceeding with classical fallback.");

            //Non-Quantum version.  If you have many years of time, you can use this.
            var (p, q) = BigintegerMath.FactorizeModulus(n);
            if (p == 0 || q == 0)
            {
                Console.WriteLine("Failed to factor n.");
                return;
            }

            Console.WriteLine($"Found factors: p = {p}, q = {q}");

            var privateExp = BigintegerMath.CalculatePrivateExponent(e, p, q);
            Console.WriteLine($"Private exponent d = {privateExp}");

            var message = new BigInteger(123456);
            var ciphertext = BigintegerMath.EncryptMessage(message, e, n);
            var decrypted = BigintegerMath.DecryptMessage(ciphertext, privateExp, n);

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
