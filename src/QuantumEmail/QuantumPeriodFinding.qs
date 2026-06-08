namespace Quantum.QuantumEmail {

//Credit: https://tsmatz.wordpress.com/2019/06/04/quantum-integer-factorization-by-shor-period-finding-algorithm/
// BigInt migration: all Int parameters changed to BigInt to support large RSA moduli.
//
// Architecture: the quantum circuit returns raw measurement results; all classical
// post-processing (continued fractions, period verification, retry loop) is handled
// by the C# host. This makes the circuit compatible with hardware targets including
// Quantinuum H-series, where classical control flow inside operations is restricted.

    open Microsoft.Quantum.Canon;
    open Microsoft.Quantum.Intrinsic;
    open Microsoft.Quantum.Math;
    open Microsoft.Quantum.Measurement;
    open Microsoft.Quantum.Arrays;

    @EntryPoint()
    operation GetRandomResult() : Result {
        use q = Qubit();
        H(q);
        return M(q);
    }

    // Runs one iteration of Shor's period-finding circuit.
    // Returns the x-register measurements (n1 = 2 * BitSizeL(N) bits).
    // The C# host interprets these via continued fractions, verifies the period,
    // and retries as needed — no quantum-side classical loop required.
    operation RunPeriodFindingCircuit(N : BigInt, a : BigInt) : Result[] {
        let n1 = BitSizeL(N) * 2;
        let n2 = BitSizeL(N);
        use (x, y) = (Qubit[n1], Qubit[n2]) {
            ApplyToEachCA(H, x);

            // |x⟩ |0⟩ -> |x⟩ |a^x mod N⟩
            QuantumExponentForPeriodFinding(a, N, x, y);

            // Measure y to collapse entanglement (values not needed by host)
            for idx in 0 .. n2 - 1 {
                let _ = MResetZ(y[idx]);
            }

            // Apply QFT then measure x
            QFTImpl(x);
            mutable xResults = [Zero, size = n1];
            for idx in 0 .. n1 - 1 {
                set xResults w/= idx <- MResetZ(x[idx]);
            }
            return xResults;
        }
    }

    operation QuantumExponentForPeriodFinding(a : BigInt, N : BigInt, x : Qubit[], y : Qubit[]) : Unit {
        let n1 = Length(x);
        let n2 = Length(y);
        X(y[n2 - 1]);
        for idx in 0 .. n1 - 1 {
            // Compute a^(2^((n1-1)-idx)) mod N via repeated squaring — avoids overflow
            mutable a_mod = a % N;
            for _ in 1 .. (n1 - 1) - idx {
                set a_mod = (a_mod * a_mod) % N;
            }
            Controlled QuantumMultiplyByModulus([x[idx]], (N, a_mod, y));
        }
    }

    // Classically precomputes [factor*2^0 mod N, ..., factor*2^(n-1) mod N].
    // A Q# function so mutable/set are allowed without blocking Adj+Ctl auto-generation.
    function BitDecompFactors(N : BigInt, factor : BigInt, n : Int) : BigInt[] {
        mutable result = [0L, size = n];
        mutable aMod = factor % N;
        for i in 0 .. n - 1 {
            set result w/= i <- aMod;
            set aMod = (aMod * 2L) % N;
        }
        return result;
    }

    // |y⟩ -> |a*y mod N⟩
    // O(log a) bit-decomposition. No set-statements in body → Q# auto-generates Adj and Ctl.
    operation QuantumMultiplyByModulus(N : BigInt, a : BigInt, y : Qubit[]) : Unit is Adj + Ctl {
        let n = Length(y);
        let a_mod = a % N;
        let factors = BitDecompFactors(N, a_mod, n);
        let inv_factors = BitDecompFactors(N, InverseModL(a_mod, N), n);
        use s = Qubit[n] {
            for i in 0 .. n - 1 {
                Controlled QuantumAddConstByModulus([y[i]], (N, factors[i], s));
            }
            ApplyToEachCA(SWAP, Zipped(y, s));
            for i in 0 .. n - 1 {
                Controlled Adjoint QuantumAddConstByModulus([y[i]], (N, inv_factors[i], s));
            }
        }
    }

    // Add classical BigInt constant c to quantum register y, modulo N.
    // No set-statements → Q# auto-generates Adj and Ctl specializations.
    operation QuantumAddConstByModulus(N : BigInt, c : BigInt, y : Qubit[]) : Unit is Adj + Ctl {
        use (ancilla, cy) = (Qubit(), Qubit()) {
            let y_large = [cy] + y;
            let c_mod = c % N;
            QuantumAddByNumber(y_large, c_mod);
            Adjoint QuantumAddByNumber(y_large, N);
            Controlled X([y_large[0]], ancilla);
            Controlled QuantumAddByNumber([ancilla], (y_large, N));
            Adjoint QuantumAddByNumber(y_large, c_mod);
            X(ancilla);
            Controlled X([y_large[0]], ancilla);
            QuantumAddByNumber(y_large, c_mod);
        }
    }

    operation QuantumAddByModulus(N : BigInt, x : Qubit[], y : Qubit[]) : Unit is Adj + Ctl {
        use (ancilla, cx, cy) = (Qubit(), Qubit(), Qubit()) {
            let x_large = [cx] + x;
            let y_large = [cy] + y;
            QuantumAdd(x_large, y_large);
            Adjoint QuantumAddByNumber(y_large, N);
            Controlled X([y_large[0]], ancilla);
            Controlled QuantumAddByNumber([ancilla], (y_large, N));
            Adjoint QuantumAdd(x_large, y_large);
            X(ancilla);
            Controlled X([y_large[0]], ancilla);
            QuantumAdd(x_large, y_large);
        }
    }

    // QFT-based Draper adder: |x⟩ |y⟩ -> |x⟩ |x + y mod 2^n⟩
    operation QuantumAdd(x : Qubit[], y : Qubit[]) : Unit is Adj + Ctl {
        let n = Length(x);
        QFTImpl(y);
        for i in 0 .. n - 1 {
            for j in 0 .. (n - 1) - i {
                Controlled R1Frac([x[i + j]], (2, j + 1, y[(n - 1) - i]));
            }
        }
        Adjoint QFTImpl(y);
    }

    // Add classical BigInt constant b to quantum register x, mod 2^n (Draper / QFT-based).
    // Uses 1L <<< shift for BigInt-safe bit extraction.
    operation QuantumAddByNumber(x : Qubit[], b : BigInt) : Unit is Adj + Ctl {
        let n = Length(x);
        QFTImpl(x);
        for i in 0 .. n - 1 {
            for j in 0 .. (n - 1) - i {
                let shift = (n - 1) - (i + j);
                if (not ((b / (1L <<< shift)) % 2L == 0L)) {
                    R1Frac(2, j + 1, x[(n - 1) - i]);
                }
            }
        }
        Adjoint QFTImpl(x);
    }

    operation QFTImpl(qs : Qubit[]) : Unit is Adj + Ctl {
        body (...) {
            let nQubits = Length(qs);
            for i in 0 .. nQubits - 1 {
                H(qs[i]);
                for j in i + 1 .. nQubits - 1 {
                    Controlled R1Frac([qs[j]], (1, j - i, qs[i]));
                }
            }
            SwapReverseRegister(qs);
        }
    }
}
