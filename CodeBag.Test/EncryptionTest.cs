using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using CodeBag.Extensions;

namespace CodeBag.Test
{
    [TestClass]
    public class EncryptionTest
    {
        [TestMethod]
        public void TestEncryption()
        {
            var password = "ThisIsTheStrongestPasswordInTheWord";
            var plainString = "{customerKey:12345,ieeeMemberNumber:5678}";
            var encryptedString = plainString.Encrypt(password);
            var decryptedString = encryptedString.Decrypt(password);
            Assert.AreEqual(decryptedString, plainString);
        }
    }
}
