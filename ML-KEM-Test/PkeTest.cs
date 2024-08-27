using ML_KEM;

namespace ML_KEM_Test;

[TestClass]
public class PkeTest
{
    [TestMethod]
    public void KeyGenDeterministicTest()
    {
        ParameterSet[] parameterSets = [Parameters.ML_KEM_512, Parameters.ML_KEM_768, Parameters.ML_KEM_512];
        foreach (var p in parameterSets)
        {
            Random rnd = new Random();
            byte[] seed = new byte[32];
            rnd.NextBytes(seed);
        
            (EncryptionKey ek1, DecryptionKey dk1) = Pke.KeyGen(seed, p);
        
            (EncryptionKey ek2, DecryptionKey dk2) = Pke.KeyGen(seed, p);
        
            CollectionAssert.AreEqual(ek1.Serialize(), ek2.Serialize());
            CollectionAssert.AreEqual(dk1.Serialize(), dk2.Serialize());
        }
        
    }

    [TestMethod]
    public void EncryptDecryptTest()
    {
        ParameterSet[] parameterSets = [Parameters.ML_KEM_512, Parameters.ML_KEM_768, Parameters.ML_KEM_512];
        foreach (var p in parameterSets)
        {
            Random rnd = new Random();
            byte[] seed = new byte[32];
            byte[] r = new byte[32];
            byte[] message = new byte[32];
            rnd.NextBytes(seed);
            rnd.NextBytes(r);
            rnd.NextBytes(message);

            (EncryptionKey ek1, DecryptionKey dk1) = Pke.KeyGen(seed, p);
            byte[] c = ek1.Encrypt(message, r);
            byte[] m = dk1.Decrypt(c);

            CollectionAssert.AreEqual(message, m);
        }
    }

    [TestMethod]
    public void SerializeDeserializeTest()
    {
        ParameterSet[] parameterSets = [Parameters.ML_KEM_512, Parameters.ML_KEM_768, Parameters.ML_KEM_512];
        foreach (var p in parameterSets)
        {
            Random rnd = new Random();
            byte[] seed = new byte[32];
            rnd.NextBytes(seed);
            (EncryptionKey ek, DecryptionKey dk) = Pke.KeyGen(seed, p);
            
            byte[] ekBytes = ek.Serialize();
            byte[] dkBytes = dk.Serialize();
            
            EncryptionKey ekP = EncryptionKey.Deserialize(ekBytes, p);
            DecryptionKey dkP = DecryptionKey.Deserialize(dkBytes, p);
            
            CollectionAssert.AreEqual(dkBytes, dkP.Serialize());
            CollectionAssert.AreEqual(ekBytes, ekP.Serialize());
        }
    }
}