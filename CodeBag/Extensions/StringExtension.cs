using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml;

namespace CodeBag.Extensions
{
    public static class StringExtension
    {
        public static TEnum ToEnum<TEnum>(this string value) where TEnum : struct
        {
            return (TEnum)Enum.Parse(typeof(TEnum), value);
        }

        public static TEnum? ToSafeEnum<TEnum>(this string value) where TEnum : struct
        {
            try
            {
                return String.IsNullOrEmpty(value)
                ? default(TEnum?)
                : (TEnum)Enum.Parse(typeof(TEnum), value);
            }
            catch
            {
                return default(TEnum?);
            }
        }

        public static string SubstringBefore(this string value, char c)
        {
            var index = value.IndexOf(c);
            return index > 0 ? value.Substring(0, index) : String.Empty;
        }

        public static string SubstringAfter(this string value, char c)
        {
            var index = value.IndexOf(c);
            return index > 0 ? value.Substring(index + 1) : String.Empty;
        }

        public static string ToWords(this string value)
        {
            return Regex.Replace(value, "([a-z](?=[A-Z])|[A-Z](?=[A-Z][a-z]))", "$1 ");
        }

        public static string ReplaceIgnoreCase(this string value, string pattern, string replacement)
        {
            return Regex.Replace(value, pattern, replacement ?? String.Empty, RegexOptions.IgnoreCase);
        }

        public static string ReplaceOne(this string value, string pattern, string replacement)
        {
            var regex = new Regex(pattern);
            return regex.Replace(value, replacement ?? String.Empty, 1);
        }

        public static string ToXmlSafeString(this string value, bool trim = true)
        {
            if (String.IsNullOrEmpty(value)) return value;
            var validChars = value.Where(XmlConvert.IsXmlChar).ToArray();
            if (validChars.Length == 0) return String.Empty;
            var newValue = new string(validChars);
            return (!String.IsNullOrEmpty(newValue) && trim)
                ? value.Trim()
                : value;
        }

        public static string Left(this string value, int maxLength)
        {
            if (String.IsNullOrEmpty(value)) return value;
            maxLength = Math.Abs(maxLength);

            return (value.Length <= maxLength
                   ? value
                   : value.Substring(0, maxLength)
                   );
        }

        public static string Right(this string value, int maxLength)
        {
            if (String.IsNullOrEmpty(value)) return value;
            maxLength = Math.Abs(maxLength);

            return (value.Length <= maxLength
                   ? value
                   : value.Substring(value.Length - maxLength)
                   );
        }

        public static bool Contains(this string value, IEnumerable<string> substrings, StringComparison comparisonType)
        {
            return substrings != null
                && substrings.Any(s => value.IndexOf(s, comparisonType) >= 0);
        }

        //There are several ways to do get the result, but this should be one of the most efficient.
        public static IEnumerable<string> GetLines(this string value, bool removeEmptyLines = false)
        {
            using (var sr = new System.IO.StringReader(value))
            {
                string line;
                while ((line = sr.ReadLine()) != null)
                {
                    if (removeEmptyLines && String.IsNullOrWhiteSpace(line))
                    {
                        continue;
                    }
                    yield return line;
                }
            }
        }

        public static string Encrypt(this string value, string password)
        {
            return Helpers.AESThenHMAC.SimpleEncryptWithPassword(value, password);
        }

        public static string Decrypt(this string value, string password)
        {
            return Helpers.AESThenHMAC.SimpleDecryptWithPassword(value, password);
        }
    }
}
