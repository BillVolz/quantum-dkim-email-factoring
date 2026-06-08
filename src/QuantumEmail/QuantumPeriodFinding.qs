namespace Quantum.QuantumEmail {

//Credit: https://tsmatz.wordpress.com/2019/06/04/quantum-integer-factorization-by-shor-period-finding-algorithm/
// BigInt migration: all Int parameters changed to BigInt to support large RSA moduli.
// Simulator limit: QuantumSimulator supports ~30 qubits. RSA-1024 needs ~3000+ logical qubits.
// Use small test inputs (e.g. num=15, a=2) on the simulator; real keys require physical hardware.

    open Microsoft.Quantum.Canon;
    open Microsoft.Quantum.Intrinsic;
    open Microsoft.Quantum.Math;
    open Microsoft.Quantum.Measurement;
    open Microsoft.Quantum.Arrays;
    open Microsoft.Quantum.Convert;
    open Microsoft.Quantum.Diagnostics;

    @EntryPoint()
    operation GetRandomResult() : Result {
        use q = Qubit();
        H(q);
        return M(q);
    }

    operation QuantumPeriodFinding(num : BigInt, a : BigInt) : BigInt {
        let n1 = BitSizeL(num) * 2;
        let n2 = BitSizeL(num);
        mutable periodCandidateL = 1L;
        repeat {
            use (x, y) = (Qubit[n1], Qubit[n2]) {
                ApplyToEachCA(H, x);

                // |x⟩ |0⟩ -> |x⟩ |a^x mod num⟩
                QuantumExponentForPeriodFinding(a, num, x, y);

                mutable tmpResult = [Zero, size = n2];
                for idx in 0 .. n2 - 1 {
                    set tmpResult w/= idx <- MResetZ(y[idx]);
                }

                QFTImpl(x);

                mutable realResult = [Zero, size = n1];
                for idx in 0 .. n1 - 1 {
                    set realResult w/= idx <- MResetZ(x[idx]);
                }

                // get integer result from measured array
                let resultBool = [false] + ResultArrayAsBoolArray(realResult);
                let resultBool_R = Reversed(resultBool);
                let resultIntL = BoolArrayAsBigInt(resultBool_R);

                // get period candidate by continued fraction expansion
                let twoToN1 = 1L <<< n1;
                let gcdL = GreatestCommonDivisorL(resultIntL, twoToN1);
                let calculatedNumerator = resultIntL / gcdL;
                let calculatedDenominator = twoToN1 / gcdL;
                let approximatedFraction =
                    ContinuedFractionConvergentL(BigFraction(calculatedNumerator, calculatedDenominator), num);
                let (approximatedNumerator, approximatedDenominator) = approximatedFraction!;

                if (approximatedDenominator < 0L) {
                    set periodCandidateL = -approximatedDenominator;
                } else {
                    set periodCandidateL = approximatedDenominator;
                }

                Message($"Measured Fraction : {resultIntL} / {twoToN1}");
                Message($"Approximated Fraction : {approximatedNumerator} / {approximatedDenominator}");
                Message($"Period Candidate : {periodCandidateL}");
            }
        }
        until ((periodCandidateL != 0L) and (ExpModL(a, periodCandidateL, num) == 1L))
        fixup {}

        Message($"Found period {periodCandidateL}");
        return periodCandidateL;
    }

    operation QuantumExponentForPeriodFinding(a : BigInt, N : BigInt, x : Qubit[], y : Qubit[]) : Unit {
        let n1 = Length(x);
        let n2 = Length(y);
        X(y[n2 - 1]);
        for idx in 0 .. n1 - 1 {
            // Compute a^(2^((n1-1)-idx)) mod N via repeated squaring — avoids Int overflow
            mutable a_mod = a % N;
            for _ in 1 .. (n1 - 1) - idx {
                set a_mod = (a_mod * a_mod) % N;
            }
            Controlled QuantumMultiplyByModulus([x[idx]], (N, a_mod, y));
        }
    }

    // Classically precomputes [factor*2^0 mod N, factor*2^1 mod N, ..., factor*2^(n-1) mod N].
    // A Q# function (not operation) so mutable/set are allowed without blocking Adj+Ctl auto-generation.
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
    // O(log a) bit-decomposition replaces the original O(a) repeated-addition loop.
    // No set-statements in body, so Q# can auto-generate Adj and Ctl specializations.
    operation QuantumMultiplyByModulus(N : BigInt, a : BigInt, y : Qubit[]) : Unit is Adj + Ctl {
        let n = Length(y);
        let a_mod = a % N;
        let factors = BitDecompFactors(N, a_mod, n);
        let inv_factors = BitDecompFactors(N, InverseModL(a_mod, N), n);
        use s = Qubit[n] {
            // Forward: s = a * y_orig mod N  (bit-decompose y as the control register)
            for i in 0 .. n - 1 {
                Controlled QuantumAddConstByModulus([y[i]], (N, factors[i], s));
            }
            // s = a*y_orig mod N,  y = y_orig
            ApplyToEachCA(SWAP, Zipped(y, s));
            // y = a*y_orig mod N,  s = y_orig
            // Uncompute s: subtract a_inv * y from s, leaving s = 0
            for i in 0 .. n - 1 {
                Controlled Adjoint QuantumAddConstByModulus([y[i]], (N, inv_factors[i], s));
            }
        }
    }

    // Add classical BigInt constant c to quantum register y, modulo N.
    // No set-statements: all bindings are let, all called operations are Adj+Ctl.
    // Q# auto-generates Adj (subtract c = add N-c) and Ctl specializations correctly.
    operation QuantumAddConstByModulus(N : BigInt, c : BigInt, y : Qubit[]) : Unit is Adj + Ctl {
        use (ancilla, cy) = (Qubit(), Qubit()) {
            let y_large = [cy] + y;
            let c_mod = c % N;
            QuantumAddByNumber(y_large, c_mod);
            Adjoint QuantumAddByNumber(y_large, N);
            // ancilla = 1 when y + c - N < 0 (i.e. y + c < N; no reduction needed)
            Controlled X([y_large[0]], ancilla);
            Controlled QuantumAddByNumber([ancilla], (y_large, N));
            // reset ancilla
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
    // Uses 1L <<< shift for BigInt-safe bit extraction instead of the original Int-based 2^k.
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
