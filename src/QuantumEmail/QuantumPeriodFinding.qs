﻿namespace Quantum.QuantumEmail {

//Credit: https://tsmatz.wordpress.com/2019/06/04/quantum-integer-factorization-by-shor-period-finding-algorithm/

    open Microsoft.Quantum.Canon;
    open Microsoft.Quantum.Intrinsic;
    open Microsoft.Quantum.Math;
    open Microsoft.Quantum.Measurement;

    @EntryPoint()
    operation GetRandomResult() : Result {
        use q = Qubit();
        H(q);
        return M(q);
    }
    

operation QuantumPeriodFinding (num : Int, a : Int) : Int {
  // Get least integer n1 such as : num^2 <= 2^n1
  let n1 = BitSizeI(num) * 2;
  let n2 = BitSizeI(num);
  mutable periodCandidate = 1;
  repeat {
    use (x, y) = (Qubit[n1], Qubit[n2]) {
      Microsoft.Quantum.Canon.ApplyToEachCA(H, x);

      // |x⟩ |0 (=y)⟩ -> |x⟩ |a^x mod N⟩
      QuantumExponentForPeriodFinding(a, num, x, y);

      // measure y and reset
      mutable tmpResult = new Result[n2];
      for idx in 0 .. n2 - 1 {
        set tmpResult w/= idx <-MResetZ(y[idx]);
      }

      // QFT for x
      QFTImpl(x);

      // Measure x and reset
      mutable realResult = new Result[n1];
      for idx in 0 .. n1 - 1 {
        set realResult w/= idx <-MResetZ(x[idx]);
      }
      
      // get integer's result from measured array (ex : |011⟩ -> 3)
      let resultBool = [false] + Microsoft.Quantum.Convert.ResultArrayAsBoolArray(realResult); // for making unsigned positive integer, add first bit
      let resultBool_R = Microsoft.Quantum.Arrays.Reversed(resultBool); // because BoolArrayAsBigInt() is Little Endian order
      let resultIntL = Microsoft.Quantum.Convert.BoolArrayAsBigInt(resultBool_R);

      // get period candidate by continued fraction expansion (thanks to Euclid !)
      let gcdL = GreatestCommonDivisorL(resultIntL, 2L^n1);
      let calculatedNumerator = resultIntL / gcdL;
      let calculatedDenominator = 2L^n1 / gcdL;
      let numL = Microsoft.Quantum.Convert.IntAsBigInt(num);
      let approximatedFraction =
        ContinuedFractionConvergentL(BigFraction(calculatedNumerator, calculatedDenominator), numL);
      let (approximatedNumerator, approximatedDenominator) = approximatedFraction!;
      mutable periodCandidateL = 0L;
      if(approximatedDenominator < 0L) {
        set periodCandidateL = approximatedDenominator * -1L;
      }
      else {
        set periodCandidateL = approximatedDenominator;       
      }
      set periodCandidate = ReduceBigIntToInt(periodCandidateL);

      // output for debugging
      Message($"Measured Fraction : {resultIntL} / {2L^n1}");
      Message($"Approximated Fraction : {approximatedNumerator} / {approximatedDenominator}");
      Message($"Period Candidate : {periodCandidate}");
    }
  }
  until ((periodCandidate != 0) and (ExpModI(a, periodCandidate, num) == 1))
  fixup {
  }

  // output for debugging
  Message("Found period " + Microsoft.Quantum.Convert.IntAsString(periodCandidate));
  Message("");
  return periodCandidate;
}

// Implement : |x⟩ |0 (=y)⟩ -> |x⟩ |a^x mod N⟩ for some integer a
// (where y should be |0⟩)
// This is modified version of QuantumExponentByModulus() in my post.
// See https://tsmatz.wordpress.com/2019/05/22/quantum-computing-modulus-add-subtract-multiply-exponent/
operation QuantumExponentForPeriodFinding (a : Int, N : Int, x : Qubit[], y : Qubit[]) : Unit {
  let n1 = Length(x);
  let n2 = Length(y);

  // set |y⟩ = |0...01⟩
  X(y[n2 - 1]);

  for idx in 0 .. n1 - 1 {
    // a^(2^((n1-1) - idx)) is too big, then we reduce beforehand
    mutable a_mod = 1;
    for power in 1 .. 2^((n1-1) - idx) {
      set a_mod = (a_mod * a) % N;
    }
    // apply decomposition elements
    Controlled QuantumMultiplyByModulus([x[idx]], (N, a_mod, y));
  }
}

// This is helper function to convert BigInt to Int ...
operation ReduceBigIntToInt(numL : BigInt) : Int {
  // Check if numL is not large
  Microsoft.Quantum.Diagnostics.Fact(BitSizeL(numL) <= 32, $"Cannot convert to Int. Input is too large");

  mutable resultInt = 0;
  let numArray = Microsoft.Quantum.Convert.BigIntAsBoolArray(numL);
  let numArray_R = Microsoft.Quantum.Arrays.Reversed(numArray); // because BigIntAsBoolArray() is Little Endian order
  let nSize = Length(numArray_R);
  for idx in 0 .. nSize - 1 {
    if(numArray_R[idx] and ((nSize - 1) - idx <= 31)) {
      set resultInt = resultInt + (2 ^ ((nSize - 1) - idx));
    }
  }
  return resultInt;
}

//
// Implement : |x⟩ |y⟩ -> |x⟩ |x+y mod N⟩ for some integer N
// (where N < 2^n, x < N, y < N)
//
operation QuantumAddByModulus (N : Int, x : Qubit[], y : Qubit[]) : Unit is Adj + Ctl {
  use (ancilla, cx, cy) = (Qubit(), Qubit(), Qubit()) {
    // add bit for preventing overflow
    let x_large = [cx] + x;
    let y_large = [cy] + y;
    // |x⟩ |y⟩ -> |x⟩ |x + y⟩
    QuantumAdd(x_large, y_large);
    // |y⟩ -> |y - N⟩
    Adjoint QuantumAddByNumber(y_large, N);
    // Turn on ancilla when first bit is |1⟩ (i.e, when x + y - N < 0)
    Controlled X([y_large[0]], ancilla);
    // Add N back when ancilla is |1⟩
    Controlled QuantumAddByNumber([ancilla], (y_large, N));
    // set ancilla to |0⟩ (See my above description)
    Adjoint QuantumAdd(x_large, y_large);
    X(ancilla);
    Controlled X([y_large[0]], ancilla);
    QuantumAdd(x_large, y_large);
  }
}

//
// Implement : |y⟩ -> |a y mod N⟩ for some integer a and N
// (where N < 2^n, y < N)
//
// Important Note :
// Integer "a" and "N" must be co-prime number.
// (For making this operator must be controlled. Otherwise InverseModI() raises an error.)
//
operation QuantumMultiplyByModulus (N : Int, a : Int, y : Qubit[]) : Unit is Adj + Ctl {
  let n = Length(y);
  let a_mod = a % N;

  use s = Qubit[n] {
    // start |y⟩ |0⟩

    // apply adder by repeating "a" (integer) times
    for r in 0 .. a_mod - 1 {
      QuantumAddByModulus(N, y, s);
    }
    // now |y⟩ |a y mod N⟩

    // swap first register and second one by tuple
    Microsoft.Quantum.Canon.ApplyToEachCA(SWAP, Microsoft.Quantum.Arrays.Zipped(y, s));
    // now |a y mod N⟩ |y⟩

    // reset all s qubits !
    // but it's tricky because we cannot use "Reset()". (See my above description.)
    let a_inv = InverseModI(a_mod, N);
    for r in 0 .. a_inv - 1 {
      Adjoint QuantumAddByModulus(N, y, s);
    }
  }
}

//
// Implement : |x⟩ -> |a^x mod N⟩ for some integer a and N
// (where N < 2^n)
//
// Important Note :
// Integer "a" and "N" must be co-prime number.
// (Because this invokes QuantumMultiplyByModulus().)
//
operation QuantumExponentByModulus (N : Int, a : Int, x : Qubit[]) : Unit {
  let n = Length(x);
  use s = Qubit[n] {
    // set |s⟩ = |1⟩
    X(s[n - 1]);

    // apply decomposition elements
    for idx in 0 .. n - 1 {
      Controlled QuantumMultiplyByModulus([x[idx]], (N, a^(2^((n-1) - idx)), s));
    }

    // swap |x⟩ and |s⟩
    Microsoft.Quantum.Canon.ApplyToEachCA(SWAP, Microsoft.Quantum.Arrays.Zipped(x, s));

    // Reset s
    for idx in 0 .. n - 1 {
      Reset(s[idx]);
    }
  }
}


//
// Implement : |x⟩ |y⟩ -> |x⟩ |x + y mod 2^n⟩ where n = Length(x) = Length(y)
// with Drapper algorithm (See https://arxiv.org/pdf/1411.5949.pdf)
//
operation QuantumAdd (x : Qubit[], y : Qubit[]) : Unit is Adj + Ctl {
  let n = Length(x);
  QFTImpl(y);
  for i in 0 .. n - 1 {
    for j in 0 .. (n - 1) - i {
      Controlled R1Frac([x[i + j]], (2, j + 1, (y)[(n - 1) - i]));
    }
  }
  Adjoint QFTImpl(y);
}


//
// Implement : |x⟩ -> |x + b mod 2^n⟩ for some integer b
//
operation QuantumAddByNumber (x : Qubit[], b : Int) : Unit is Adj + Ctl {
  let n = Length(x);

  // apply Draper adder for numeric
  QFTImpl(x);
  for i in 0 .. n - 1 {
    for j in 0 .. (n - 1) - i {
      if(not((b / 2^((n - 1) - (i + j))) % 2 == 0)) {
        R1Frac(2, j + 1, (x)[(n - 1) - i]);
      }
    }
  }
  Adjoint QFTImpl(x);
}
operation QFTImpl (qs : Qubit[]) : Unit is Adj + Ctl
{
  body (...)
  {
    let nQubits = Length(qs);
      
    for i in 0 .. nQubits - 1
    {
      H(qs[i]);
      for j in i + 1 .. nQubits - 1
      {
        Controlled R1Frac([qs[j]], (1, j - i, qs[i]));
      }
    }
      
    Microsoft.Quantum.Canon.SwapReverseRegister(qs);
  }
}
}

