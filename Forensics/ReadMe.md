## Forensic Projects 

SysMainView



http://computer-forensics.sans.org/blog/author/mpilkington
http://www.f-response.com/
http://blog.commandlinekungfu.com/
http://computer-forensics.sans.org/blog/2012/06/01/digital-forensic-case-leads-flame-on-the-most-sophisticated-malware-since-the-last-one-higher-ed-data-breach-and-powershell-forensics
http://blogs.technet.com/b/heyscriptingguy/archive/2012/05/28/use-powershell-to-aid-in-security-forensics.aspx
1. Avoid interactive logons
   - Details here: http://computer-forensics.sans.org/blog/2012/02/21/protecting-privileged-domain-account-safeguarding-password-hashes

2. Protect delegate-level access tokens
   - Details here: http://computer-forensics.sans.org/blog/2012/03/21/protecting-privileged-domain-accounts-access-tokens

3. Enforce Kerberos network authentication
   - Details here: http://computer-forensics.sans.org/blog/2012/09/18/protecting-privileged-domain-accounts-network-authentication-in-depth


To address the 1st issue, I suggest you run your scripts against a test machine and then go through the event logs with a fine-tooth comb to verify the logon types that occur.  You want to make sure all logons from your privileged account are network logons (Type 3) rather than interactive logons (Type 2).  Once you're comfortable that your scripts are performing network logons only, make sure to set your privileged account(s) to "Account is sensitive and cannot be delegated", as detailed in the 2nd article.  Finally, do your best to enforce Kerberos authentication, including the use of NTLM blocking on Windows 7, as discussed in the 3rd article.

You might also want to check out my recent SANS webcast on this topic:  https://www.sans.org/webcasts/protecting-privileged-domain-accounts-live-response-95589

Keep us posted on your scripts.  I'd love to see what you come up with.  



You can find malware samples here :  https://github.com/ytisf/theZoo




You might even consider reaching out to him directly on his website:  http://www.petefinnigan.com/

https://www.amazon.com/Oracle-Incident-Response-Forensics-Responding/dp/1484232631



http://www.processlibrary.com/



Complete list of iOS settings app urls.mhtml.txt

http://forensic4cast.com/2013/03/4mag-issue-1/

tuts4you.com
Online training material — ENISA (europa.eu)

https://hatsoffsecurity.com/

### 	ios-settings-urls/settings-urls.md at master - GitHub
https://github.com/FifiTheBulldog/ios-settings-urls/blob/master/settings-urls.md

### Configuration Profile Reference - Apple Developer
https://developer.apple.com/business/documentation/Configuration-Profile-Reference.pdf

### Digital Corpora – Producing the Digital Body
https://digitalcorpora.org/

### CFReDS Portal (nist.gov)
https://cfreds.nist.gov/

### Online training material — ENISA (europa.eu)
https://www.enisa.europa.eu/topics/trainings-for-cybersecurity-specialists/online-training-material





























