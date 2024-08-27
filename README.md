# ML-KEM
A simple implementation of ML-KEM in C# created according to <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf">FIPS 203</a>. This was created for educational purposes. I wanted a better understanding of how this new protocol works and what better way to learn than to do.
I would highly advise against using this if your goal is security. 
<br/>
<br>
This implementation has been tested with test cases generated by <a href="https://github.com/GiacomoPope/kyber-py">kyber-py</a> so it's at least functionally correct.

If you do wish to use this, the API exists within `ML_KEM.Primitives.MlKem`
