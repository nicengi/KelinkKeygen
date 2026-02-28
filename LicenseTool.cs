using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace KelinkKeygen
{
    internal static class LicenseTool
    {
        /// <summary>
        /// 原来的公钥。
        /// </summary>
        public static string PUBLIC_KEY_ORIGINAL =  "<RSAKeyValue><Modulus>uh9F4L86QqaXoFEPfnrkA5E205HsebGF1yf27JtAbY9CURc7cgx4mZFHn0pljnVRV6g/pUpgqXhzdbIAXulh1bm+Q3L5tjUY6/MEHWrDWmWQzXr1LO1MaFdeS6cMi2h/GnXjnKLTJT2sj2g4LiKWjmJQST60PkXuZPqHErLSyT0=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";
        public static string PUBLIC_KEY_KEYGEN =    "<RSAKeyValue><Modulus>wpcMSgQqlQzUnzRfkAebSwJfQ22febiW11dTvn78TQnMH+p4ZGqHXKJOHADFEjJeniTXwj2b96GlTr4N/wReZ0rL5NYZy1jSWJEqfkMxb5ENwKqxalGG6Fknbt6YFVCDTEkne5AJAz1MzhuxFnF2h0YvYN6Tdkz3pB3pMDLYOBE=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";
        public static string PRIVATE_KEY_KEYGEN =   "<RSAKeyValue><Modulus>wpcMSgQqlQzUnzRfkAebSwJfQ22febiW11dTvn78TQnMH+p4ZGqHXKJOHADFEjJeniTXwj2b96GlTr4N/wReZ0rL5NYZy1jSWJEqfkMxb5ENwKqxalGG6Fknbt6YFVCDTEkne5AJAz1MzhuxFnF2h0YvYN6Tdkz3pB3pMDLYOBE=</Modulus><Exponent>AQAB</Exponent><P>2FMkh8ys8qNR5DnAiQr7ZVYCJnq9TQMgFNrrw+OoJk0c3miubjFMPJw7iotQQNkozE+8rAlz4/MUWHKn6/5J3w==</P><Q>5kdq/chgB5dMUxefIH8LKZoogkiXiBiCCfteVq6kBIogI++gFolShDGBJ0/M0aptLWF62EvlnDqFgmKaT9KcDw==</Q><DP>LgDYZuy25s6mjqNdd4dXWQCGaop1kVgVzXmU486ZJrQFbKLUXWisbsNGwjrIMVI9I93dILTN6W77J6gSX9Ru/w==</DP><DQ>mGPmz++MbTmYztww+CZa0rsr15wGe5AMbmKk+aQ08rQdtOpc/Mz/iG/iUouitZWdDo0V6JHBb3Pi6ngqOmzbzQ==</DQ><InverseQ>z8DWYKYVPfTKJxPFzFs6BcskJGwpgYg9UHY85FRe0aIXBvJ/0m3uuMYA8H5rHcXl/MsRzJq7zrbaACVW/URYww==</InverseQ><D>AC5dz4/TblIVvJQy5pJrPZWh+xEWDenzEf490LaTi4rPytPQCt/igl6QTgxeIpczaVhFbyPZilB3M+yPXMZnRBbuUNMDXJ3/7Cd7QUEJW9qppmMYEqMMAoO5YZxhGP/U+iqptLQG/ab0A1Mi5NmGxly43Vb9Kc+y/HF1ikopkpU=</D></RSAKeyValue>";


        public static string GenerateRegcode(string LICENSE_ID, string KL_VERSION, string KL_SITEID, string LICENSE_DOMAIN, string funcs = "|art|bbs|pic|dow|rin|vid|wml|sho|gue|cha|lin|adl|pai|air|hot|gon|rol|")
        {
            // 11259|0|0|wi0.cccn-10086.com|art|bbs|pic|dow|rin|vid|wml|sho|gue|cha|lin|adl|pai|air|hot|gon|rol|
            string regStr = $"{LICENSE_ID}|{KL_VERSION}|{KL_SITEID}|{LICENSE_DOMAIN}{funcs}";
            string encRegStr = DesEncrypt(regStr);
            string signature = GenerateSignatureV2(GetMachineCode(LICENSE_DOMAIN));
            string regcode = signature + encRegStr;

            return regcode;
        }

        public static bool VerifySignature(string domain, string regcode)
        {
            string text = regcode;
            string xmlString = PUBLIC_KEY_ORIGINAL;
            text = text.Substring(0, text.IndexOf('=') + 1);
            RSACryptoServiceProvider rSACryptoServiceProvider = new RSACryptoServiceProvider();

            rSACryptoServiceProvider.FromXmlString(xmlString);
            RSAPKCS1SignatureDeformatter rSAPKCS1SignatureDeformatter = new RSAPKCS1SignatureDeformatter(rSACryptoServiceProvider);
            rSAPKCS1SignatureDeformatter.SetHashAlgorithm("SHA1");
            byte[] rgbSignature = Convert.FromBase64String(text);
            SHA1Managed sHA1Managed = new SHA1Managed();
            byte[] rgbHash = sHA1Managed.ComputeHash(Encoding.ASCII.GetBytes(domain));

            Console.WriteLine("\nVerifySignature:");
            Console.WriteLine($"{BitConverter.ToString(rgbHash)}");
            Console.WriteLine($"v[{domain}]");
            Console.WriteLine();

            bool flag = rSAPKCS1SignatureDeformatter.VerifySignature(rgbHash, rgbSignature);
            return flag;
        }

        public static bool VerifySignatureKeygen(string domain, string regcode)
        {
            

            string text = regcode;
            string xmlString = PUBLIC_KEY_KEYGEN;
            text = text.Substring(0, text.IndexOf('=') + 1);
            //Console.WriteLine($"Signature: {text}");
            RSACryptoServiceProvider rSACryptoServiceProvider = new RSACryptoServiceProvider();

            rSACryptoServiceProvider.FromXmlString(xmlString);
            RSAPKCS1SignatureDeformatter rSAPKCS1SignatureDeformatter = new RSAPKCS1SignatureDeformatter(rSACryptoServiceProvider);
            rSAPKCS1SignatureDeformatter.SetHashAlgorithm("SHA1");
            byte[] rgbSignature = Convert.FromBase64String(text);
            SHA1Managed sHA1Managed = new SHA1Managed();
            byte[] rgbHash = sHA1Managed.ComputeHash(Encoding.ASCII.GetBytes(domain));

            Console.WriteLine("\nVerifySignatureKeygen:");
            Console.WriteLine($"{BitConverter.ToString(rgbHash)}");
            Console.WriteLine($"v[{domain}]");
            Console.WriteLine();

            bool flag = rSAPKCS1SignatureDeformatter.VerifySignature(rgbHash, rgbSignature);
            return flag;
        }

        public static string GenerateSignatureV2(string domain)
        {
            Console.WriteLine("GenerateSignatureV2: ");
            string privateKeyXml = PRIVATE_KEY_KEYGEN;

            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(privateKeyXml);

            byte[] dataBytes = Encoding.ASCII.GetBytes(domain);

            SHA1Managed sha1 = new SHA1Managed();
            byte[] hashBytes = sha1.ComputeHash(dataBytes);

            Console.WriteLine(BitConverter.ToString(hashBytes));
            Console.WriteLine($"s[{domain}]");
            Console.WriteLine();

            RSAPKCS1SignatureFormatter formatter = new RSAPKCS1SignatureFormatter(rsa);
            formatter.SetHashAlgorithm("SHA1");

            byte[] signatureBytes = formatter.CreateSignature(hashBytes);

            return Convert.ToBase64String(signatureBytes);
        }

        public static string GetMachineCode(string domain)
        {
            string text = "";
            text += domain;
            text = text.Trim().Replace(".", "0");
            text = text.ToUpper();
            text = EnCode_KL(text);
            text = EnCode_KL(text);
            text = EnCode_KL(text);
            text = EnCode_KL(text);
            return EnCode_KL(text);
        }

        public static string EnCode_KL(string x)
        {
            string text2 = default(string);
            int num4 = default(int);
            string result = default(string);
            while (true)
            {
                int num = 0;
                int num2 = 0;
                string text = "";
                int length = x.Length;
                bool flag = length % 2 != 0;
                int num3 = 11;
                while (true)
                {
                    switch (num3)
                    {
                        case 11:
                            if (!flag)
                            {
                                num3 = 6;
                                continue;
                            }
                            num2 = 3;
                            num3 = 18;
                            continue;
                        case 21:
                            text2 = "0" + text2;
                            num = 1;
                            num3 = 3;
                            continue;
                        case 5:
                            text2 = "00" + text2;
                            num = 2;
                            num3 = 8;
                            continue;
                        case 10:
                        case 18:
                            num4 = 0;
                            num3 = 0;
                            continue;
                        case 1:
                            text = text2 + text;
                            num4 += num2;
                            num3 = 13;
                            continue;
                        case 9:
                            if (!flag)
                            {
                                num3 = 21;
                                continue;
                            }
                            goto case 3;
                        case 2:
                            result = text + num;
                            num3 = 15;
                            continue;
                        case 4:
                        case 12:
                            flag = num2 != 3;
                            num3 = 14;
                            continue;
                        case 14:
                            if (!flag)
                            {
                                num3 = 20;
                                continue;
                            }
                            goto case 1;
                        case 17:
                            if (!flag)
                            {
                                num3 = 19;
                                continue;
                            }
                            text2 = x.Substring(num4, x.Length - num4);
                            num3 = 12;
                            continue;
                        case 0:
                        case 13:
                            flag = num4 < length;
                            num3 = 7;
                            continue;
                        case 7:
                            if (flag)
                            {
                                text2 = "";
                                flag = x.Length - num4 < num2;
                                num3 = 17;
                            }
                            else
                            {
                                num3 = 2;
                            }
                            continue;
                        case 3:
                        case 8:
                            num3 = 1;
                            continue;
                        case 19:
                            text2 = x.Substring(num4, num2);
                            num3 = 4;
                            continue;
                        case 6:
                            if (true)
                            {
                            }
                            num2 = 2;
                            num3 = 10;
                            continue;
                        case 20:
                            flag = text2.Length != 1;
                            num3 = 16;
                            continue;
                        case 16:
                            if (flag)
                            {
                                flag = text2.Length != 2;
                                num3 = 9;
                            }
                            else
                            {
                                num3 = 5;
                            }
                            continue;
                        case 15:
                            return result;
                    }
                    break;
                }
            }
        }

        public static string GetFunction(string regcode)
        {
            int num = regcode.IndexOf('=');
            string text = regcode.Substring(num + 1, regcode.Length - num - 1);
            string result = text;
            return result;
        }

        public static string DesEncrypt(string encryptString)
        {
            string text = "KL****KL**Kelink.com";
            byte[] bytes = Encoding.UTF8.GetBytes(text.Substring(0, 8));
            byte[] rgbIV = bytes;
            byte[] bytes2 = Encoding.UTF8.GetBytes(encryptString);
            DESCryptoServiceProvider dESCryptoServiceProvider = new DESCryptoServiceProvider();
            MemoryStream memoryStream = new MemoryStream();
            CryptoStream cryptoStream = new CryptoStream(memoryStream, dESCryptoServiceProvider.CreateEncryptor(bytes, rgbIV), CryptoStreamMode.Write);
            cryptoStream.Write(bytes2, 0, bytes2.Length);
            cryptoStream.FlushFinalBlock();
            string result = Convert.ToBase64String(memoryStream.ToArray());
            return result;
        }

        public static string DesDecrypt(string decryptString)
        {
            string text = "KL****KL**Kelink.com";
            byte[] bytes = Encoding.UTF8.GetBytes(text.Substring(0, 8));
            byte[] rgbIV = bytes;
            byte[] array = Convert.FromBase64String(decryptString);
            DESCryptoServiceProvider dESCryptoServiceProvider = new DESCryptoServiceProvider();
            MemoryStream memoryStream = new MemoryStream();
            CryptoStream cryptoStream = new CryptoStream(memoryStream, dESCryptoServiceProvider.CreateDecryptor(bytes, rgbIV), CryptoStreamMode.Write);
            cryptoStream.Write(array, 0, array.Length);
            cryptoStream.FlushFinalBlock();
            return Encoding.UTF8.GetString(memoryStream.ToArray());
        }

        public static string getArryString(string tempStr, char splitstr, int key)
        {
            try
            {
                return tempStr.Split(splitstr)[key];
            }
            catch (Exception)
            {
                return "";
            }
        }

        public static string GetSiteDefault(string stremp, int ints)
        {
            stremp += "||||||||||||||||||||||||||||||||||||||";
            try
            {
                if (true)
                {
                }
                return stremp.Split('|')[ints];
            }
            catch (Exception)
            {
                return "0";
            }
        }

        public static string GetLang(string title, string lang)
        {
            string result;
            try
            {
                result = title.Split('|')[int.Parse(lang)];
            }
            catch (Exception)
            {
                try
                {
                    result = title.Split('|')[2];
                }
                catch (Exception)
                {
                    result = title.Split('|')[0];
                }
            }
            if (true)
            {
            }
            return result;
        }

        public static string GetSystemVersion(string id, string lang)
        {
            string result = default(string);
            while (true)
            {
                string text = "";
                bool flag = !(id == "0");
                int num = 11;
                while (true)
                {
                    switch (num)
                    {
                        case 11:
                            if (!flag)
                            {
                                if (true)
                                {
                                }
                                num = 15;
                            }
                            else
                            {
                                flag = !(id == "1");
                                num = 9;
                            }
                            continue;
                        case 6:
                            result = GetLang("开发版|开发版|开发版", lang);
                            num = 3;
                            continue;
                        case 13:
                            result = GetLang("DIY版|DIY版|DIY版", lang);
                            num = 5;
                            continue;
                        case 10:
                            result = GetLang("标准版|标准版|标准版", lang);
                            num = 17;
                            continue;
                        case 18:
                            result = GetLang("源码版|源码版|源码版", lang);
                            num = 7;
                            continue;
                        case 9:
                            if (!flag)
                            {
                                num = 10;
                                continue;
                            }
                            flag = !(id == "2");
                            num = 4;
                            continue;
                        case 2:
                            if (!flag)
                            {
                                num = 6;
                                continue;
                            }
                            flag = !(id == "5");
                            num = 14;
                            continue;
                        case 12:
                            result = GetLang("个人版|个人版|个人版", lang);
                            num = 1;
                            continue;
                        case 15:
                            result = GetLang("企业版|企业版|企业版", lang);
                            num = 0;
                            continue;
                        case 14:
                            if (flag)
                            {
                                result = text;
                                num = 16;
                            }
                            else
                            {
                                num = 18;
                            }
                            continue;
                        case 8:
                            if (flag)
                            {
                                flag = !(id == "4");
                                num = 2;
                            }
                            else
                            {
                                num = 13;
                            }
                            continue;
                        case 4:
                            if (flag)
                            {
                                flag = !(id == "3");
                                num = 8;
                            }
                            else
                            {
                                num = 12;
                            }
                            continue;
                        case 0:
                        case 1:
                        case 3:
                        case 5:
                        case 7:
                        case 16:
                        case 17:
                            return result;
                    }
                    break;
                }
            }
        }

    }
}
