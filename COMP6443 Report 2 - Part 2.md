<style>
@media print {
    .pagebreak { page-break-after: always; }
}
</style>

# COMP6443 Report 2 - Part 2
![](https://i.imgur.com/AMETBdu.png)

Peter Chen (z5255813)
Jayden Leung (z5312070)
Yanning Cao (z5135152)
William Yin (z5017279)
Emma Soo (z5206961)

<div class="pagebreak"> </div>

# CORS Testing:
## 1. **[JS]** Set content type as “application/json; charset=utf-8”. Send GET request to server.
### 1.1. Is prefight request sent? Capture the request & response.
*Yes*

![](https://i.imgur.com/Yi1mIoP.png)

*Pre-flight Request:*
``` 
OPTIONS /server?id=7157765&enable=true&status=200&credentials=false HTTP/2
Host: server.test-cors.org
Accept: */*
Access-Control-Request-Method: GET
Access-Control-Request-Headers: content-type
Origin: https://www.test-cors.org
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-site
Sec-Fetch-Dest: empty
Referer: https://www.test-cors.org/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
```

*Pre-flight Response:*
``` 
HTTP/2 200 OK
Cache-Control: no-cache
Content-Type: application/json
Access-Control-Allow-Origin: https://www.test-cors.org
Set-Cookie: cookie-from-server=noop
X-Cloud-Trace-Context: 1f9697de75f1a0d4e05eb2261c441ff9
Date: Mon, 19 Jul 2021 20:42:04 GMT
Server: Google Frontend
Content-Length: 0
Expires: Mon, 19 Jul 2021 20:42:04 GMT
```

### 1.2. Is there any CORS error in browser? If so, capture it.
*CORS error:*
![](https://i.imgur.com/ufdZXtb.png)
This error has been generated as a result of `content-type` being present in the pre-flight response returned. As such, the browser blocks the response from showing.

<div class="pagebreak"> </div>

## 2. **[JS]** Set content type as “text/plain”. Send GET request to server.
### 2.1. Is prefight request sent? Capture the request & response.
*No, the prefight request was not sent*
###     2.2. Is there any CORS error in browser? If so, capture it.
*CORS Error:*
![](https://i.imgur.com/ijaPsAr.png)
This error has been generated as a result of `content-type` being present in the pre-flight response returned. As such, the browser blocks the response from showing.

<div class="pagebreak"> </div>

## 3. **[JS]** Set content type as “text/plain”. Send requests to server using POST, OPTIONS, DELETE, PUT methods.
### 3.1. Is prefight request sent for each of the above method? Capture the request & response.
#### *POST*
- No preflighting

#### *OPTIONS*
*Pre-flight Request:*
```
OPTIONS /server?id=2367942&enable=true&status=200&credentials=false HTTP/2
Host: server.test-cors.org
Accept: */*
Access-Control-Request-Method: OPTIONS
Origin: https://www.test-cors.org
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-site
Sec-Fetch-Dest: empty
Referer: https://www.test-cors.org/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
```
*Pre-flight Response:*
```
HTTP/2 200 OK
Cache-Control: no-cache
Content-Type: application/json
Access-Control-Allow-Origin: https://www.test-cors.org
Set-Cookie: cookie-from-server=noop
X-Cloud-Trace-Context: 96d7211762dd9e84d4ae148ba1d9bdf1
Date: Mon, 19 Jul 2021 21:16:28 GMT
Server: Google Frontend
Content-Length: 0
Expires: Mon, 19 Jul 2021 21:16:28 GMT
```

#### *DELETE*
*Pre-flight Request:*
```
OPTIONS /server?id=8459664&enable=true&status=200&credentials=false HTTP/2
Host: server.test-cors.org
Accept: */*
Access-Control-Request-Method: DELETE
Origin: https://www.test-cors.org
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-site
Sec-Fetch-Dest: empty
Referer: https://www.test-cors.org/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
```
*Pre-flight Response:*
```
HTTP/2 200 OK
Cache-Control: no-cache
Content-Type: application/json
Access-Control-Allow-Origin: https://www.test-cors.org
Set-Cookie: cookie-from-server=noop
X-Cloud-Trace-Context: 70d1d24e24ca7a6161317c323f1069d7
Date: Mon, 19 Jul 2021 21:19:35 GMT
Server: Google Frontend
Content-Length: 0
Expires: Mon, 19 Jul 2021 21:19:35 GMT
```

#### *PUT*
*Pre-flight Request:*
```
OPTIONS /server?id=8916170&enable=true&status=200&credentials=false HTTP/2
Host: server.test-cors.org
Accept: */*
Access-Control-Request-Method: PUT
Origin: https://www.test-cors.org
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-site
Sec-Fetch-Dest: empty
Referer: https://www.test-cors.org/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
```
*Pre-flight Response:*
```
HTTP/2 200 OK
Cache-Control: no-cache
Content-Type: application/json
Access-Control-Allow-Origin: https://www.test-cors.org
Set-Cookie: cookie-from-server=noop
X-Cloud-Trace-Context: 6951d6d3013d1ecd64033f72c7a60da2
Date: Mon, 19 Jul 2021 21:22:15 GMT
Server: Google Frontend
Content-Length: 0
Expires: Mon, 19 Jul 2021 21:22:15 GMT
```

### 3.2. Is there any CORS error in browser? If so, capture it.
#### *POST*
No CORS error

#### *OPTIONS*
*CORS Error*
![](https://i.imgur.com/0rzVEPy.png)
This error has been generated as a result of `OPTIONS` method not allowed by Access-Control-Allow-Method in preflight response.

#### *DELETE*
*CORS Error*
![](https://i.imgur.com/y0APnAn.png)
This error has been generated as a result of `DELETE` method not allowed by Access-Control-Allow-Method in preflight response.

#### *PUT*
![](https://i.imgur.com/KhE5JtI.png)
This error has been generated as a result of `PUT` method not allowed by Access-Control-Allow-Method in preflight response.

<div class="pagebreak"> </div>

## 4. **[Research]** What are the headers that can be set by JS and not trigger a pre-flight for GET request. Please explain, why the decision was made to allow a select set of content type for GET simple requests?
CORS Pre-flight requests are not triggered by all requests. Preflight requests are simply used in order to check if a server can understand the incoming CORS protocol and is aware of all the headers and methods.

For a request not to have a CORS preflight request, it must be safe-listed by CORS. This is pre-defined as a `GET`, `HEAD` or `POST` request with manual headers of `Accept`, `Content-Language` and `Content-Type`. For more in-depth details on acceptable attributes for the header fields listed, refer to the following:
- [Source 1 - Mozilla Developer explanation](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#preflighted_requests)
- [Source 2 - CORS Specifications](https://fetch.spec.whatwg.org/#cors-safelisted-request-header)

Furthermore, a safe-listed request must be made with a `XMLHttpRequest` and have no `ReadableStream` object in the request.

The reason for the pre-defined safe-listed values for `Content-Type` header is that CORS determines that with these parameters, it is safe to expose the payload to client scripts. Only safelifted response headers are made available to web pages. One may note that developers can choose to extend the safelist with their own preferences.

<div class="pagebreak"> </div>

## 5. **[Research]** Is wildcard character (*) allowed in Access-Control-Allow-Origin response header? If so, under what conditions would wildcard not be allowed as value of “Access-Control-Allow-Origin” header?

The wild card character `*` is allowed in `Access-Control-Allow-Origin` response headers only if `Access-Control-Allow-Credentials` is set to `false`.

For example, an allowed response would be:
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: false
```
A prohibited response would be:
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```
In addition, the wild card cannot be used within any other value. For example:
```
Access-Control-Allow-Origin: https://*.quoccabank.com
```
For more information visit [PortSwigger Access Control Allow Origin](https://portswigger.net/web-security/cors/access-control-allow-origin).

<div class="pagebreak"> </div>

## 6. **[HTML5]** Insert your own HTML form. Should contain at least 1 field. Ensure form uses POST method and sends request to server endpoint. Do not use JavaScript.

The below form was injected into the HTML on https://www.test-cors.org/ via inspect element.
```html
<form action="https://server.test-cors.org/server?id=7866054&enable=true&status=200&credentials=false" method="post" role="form">
    <input type="text" id="input" name="input" placeholder="Input"><br>
    <input type="submit" value="Submit">
</form>
```

### 6.1. Does this trigger pre-flight request? If so, capture it.
No, there was no pre-flight request detected.

### 6.2. Does the server respond with any “Access-Control-*” headers? If so, capture it. If not, please explain why?
Yes, the server responds with the following `Access-Control-*` headers:
```
access-control-allow-origin: https://www.test-cors.org
```
This can be seen in the attached response header below.

![](https://i.imgur.com/fToekYw.png)

<div class="pagebreak"> </div>

## 7. **[JS]** Set content type as “text/plain”. Add a dummy cookie (“my-dummy-cookie”) in cookie jar of browser for domain server.test-cors.org. Send an explicit credentialed GET request to server. See picture below:
![](https://i.imgur.com/w0fq0IV.png)
##    Invoke using JS. This could vary when using XHR vs Fetch. Refer documentation.
    
![](https://i.imgur.com/BA1SoI2.png)

### 7.1. Does this invoke a pre-flighted request? If so, please capture request & response.

No. It only sends a GET request. It does necessitate the "Enable CORS" checkbox checked on the server side.

*Response Headers*
```
Request URL: https://server.test-cors.org/server?id=9737034&enable=true&status=200&credentials=false
Referrer Policy: strict-origin-when-cross-origin
access-control-allow-origin: http://test-cors.org
cache-control: no-cache
content-encoding: gzip
content-length: 781
content-type: application/json
date: Wed, 28 Jul 2021 09:31:00 GMT
expires: Wed, 28 Jul 2021 09:31:00 GMT
server: Google Frontend
set-cookie: cookie-from-server=noop
vary: Accept-Encoding
x-cloud-trace-context: b3afd38c01a2e47869c24e591f19604e
```

*Request Headers*
```
:authority: server.test-cors.org
:method: GET
:path: /server?id=9737034&enable=true&status=200&credentials=false
:scheme: https
accept: */*
accept-encoding: gzip, deflate, br
accept-language: en-GB,en;q=0.9,en-US;q=0.8
cache-control: no-cache
content-type: text/plain
origin: http://test-cors.org
pragma: no-cache
referer: http://test-cors.org/
sec-ch-ua: "Chromium";v="92", " Not A;Brand";v="99", "Microsoft Edge";v="92"
sec-ch-ua-mobile: ?0
sec-fetch-dest: empty
sec-fetch-mode: cors
sec-fetch-site: cross-site
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36 Edg/92.0.902.55

Query String Parameters:
id: 9737034
enable: true
status: 200
credentials: false
```

### 7.2. Does the first request from browser to server contain the “my-dummy-cookie”? if so, please capture request & response.

![](https://i.imgur.com/MJ6KKbX.png)
As can be seen above, the CORS request has "Cookie: my-dummy-cookie=value; cookie-from-server=noop" in the request header.

A copy of the request and response data can be seen in 7.1.


### 7.3. Is there any “Access-Control-Allow-Credentials” header in server response? If so, please capture request & response.

As can be seen by the image in Q2, The response has "Access-Control-Allow-Credentials: true" in its header.

### 7.4. What happens in the browser if server responds with “Access-Control-Allow-Credentials: false”?

The request is dropped and the browser errors out with the below error:
```
Sending GET request to `https://server.test-cors.org/server?id=9519959&enable=true&status=200&credentials=false&response_headers=Access-Control-Allow-Credentials%3A%20false`
, with credentials, with custom headers: Content-Type
Fired XHR event: loadstart
Fired XHR event: readystatechange
Fired XHR event: error

XHR status: 0
XHR status text:
Fired XHR event: loadend
```
![](https://i.imgur.com/7kvrHFB.png)
<!-- ![](https://i.imgur.com/9hMSLqz.png) -->

<div class="pagebreak"> </div>

## 8. **[JS]** – Optional question Set content-type as “application/json; charset=utf-8”. Send a GET request to server. Allow the pre-flight response to reach the browser. When the browser makes GET request, modify the response from the server to 301 redirect to https://google.com
### 8.1. How does the browser behave? Please capture, request/response.
There is a notable difference between the response headers of the HTTP codes `200 success` (Q1) and `301 redirect` (Q8). In the 301 redirect, `cache-control` contained an extra value `must-revalidate`, along with a new header field `pragma: no-cache` compared to the 200 success.

Additionally, a CORS error is returned because the response to the preflight request doesn't pass access control check - it does not have HTTP ok status.

*Configuration:*
![](https://i.imgur.com/5cKZf6l.png)

*Request Headers:*
![](https://i.imgur.com/ntR6x6D.png)

*Response Headers:*
![](https://i.imgur.com/1aEr6cU.png)

*CORS error:*
![](https://i.imgur.com/xRH53HB.png)

<div class="pagebreak"> </div>

# SameSite Impact:
The test site to use https://samesitedemo.jub0bs.com/

Please note, this demo site has not implemented CORS headers. Ensure you modify request and response to allow any CORS headers as needed.

If you encounter error similar to above, please add relevant Access-Control-Allow-* headers using Burp Suite in the server response.

Start by setting a cookie by default. The cookie can be set by clicking on the following link https://samesitedemo.jub0bs.com/setcookie
## 1. **[HTML5]** In a new browser tab navigate to https://jub0bs.github.io/samesitedemo-attacker-foiled . Click on the link on that page.
### 1.1. Is “StrictCookie” sent to server when navigating to https://samesitedemo.jub0bs.com/readcookie? If so, please capture request/response.

No, cookies with samesite attribute Strict are not sent to the server.


### 1.2. Change, “SameSite” attribute to “Lax” and navigate to https://samesitedemo.jub0bs.com/readcookie. Is “StrictCookie” sent to server? If so, please capture request/response.
Yes, cookies with samesite attribute Lax are sent to the server.
```
GET /readcookie HTTP/2
Host: samesitedemo.jub0bs.com
Cookie: LaxCookie=foo
Sec-Ch-Ua: " Not;A Brand";v="99", "Google Chrome";v="91", "Chromium";v="91"
Sec-Ch-Ua-Mobile: ?0
Upgrade-Insecure-Requests: 1
Dnt: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://jub0bs.github.io/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
```

```
HTTP/2 200 OK
Content-Type: text/plain; charset=utf-8
X-Cloud-Trace-Context: 00a257c0070fd69965d97e9fce014749;o=1
Date: Sun, 01 Aug 2021 03:21:47 GMT
Server: Google Frontend
Content-Length: 0
```
### 1.3. Change, “SameSite” attribute to “None” and navigate to https://samesitedemo.jub0bs.com/readcookie. Is “StrictCookie” sent to server? If so, please capture request/response.
Yes, cookies with samesite attribute None are sent to the server.
```
GET /readcookie HTTP/2
Host: samesitedemo.jub0bs.com
Cookie: NoneCookie=foo
Sec-Ch-Ua: " Not;A Brand";v="99", "Google Chrome";v="91", "Chromium";v="91"
Sec-Ch-Ua-Mobile: ?0
Upgrade-Insecure-Requests: 1
Dnt: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://jub0bs.github.io/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
```

```
HTTP/2 200 OK
Content-Type: text/plain; charset=utf-8
X-Cloud-Trace-Context: f6a6e3be940a24124c7c8ce21e8fbdf9
Date: Sun, 01 Aug 2021 03:24:33 GMT
Server: Google Frontend
Content-Length: 0
```

<div class="pagebreak"> </div>

## 2. **[JS]** Repeat question 1 but instead of navigating to https://samesitedemo.jub0bs.com/readcookie make a JS GET request to https://samesitedemo.jub0bs.com/readcookie from https://jub0bs.github.io/samesitedemo-attacker-foiled.
### 2.1. Is “StrictCookie” sent to server when sending GET request to https://samesitedemo.jub0bs.com/readcookie? If so, please capture request/response.
No, StrictCookie is not sent to the server.
### 2.2. Change, “SameSite” attribute to “Lax” and send GET request to https://samesitedemo.jub0bs.com/readcookie. Is “StrictCookie” sent to server? If so, please capture request/response.
No, cookies with SameSite attribute set to Lax are not sent to the server.
### 2.3. Change, “SameSite” attribute to “None” and send GET request to https://samesitedemo.jub0bs.com/readcookie. Is “StrictCookie” sent to server? If so, please capture request/response.
No, cookies with SameSite attribute set to None are not sent to the server.
### 2.4. Set “Secure” attribute and “SameSite” set to “None” and send GET request to https://samesitedemo.jub0bs.com/readcookie. Is “StrictCookie” sent to server? If so, please capture request/response.
No, cookies with SameSite attribute set to None and Secure attribute are not sent to the server.

<div class="pagebreak"> </div>

## 3. **[HTML5 & JS]** Repeat question 1 & 2, however instead of to https://jub0bs.github.io/samesitedemo-attacker-foiled use https://samesitedemo-attacker.jub0bs.com. Notice, https://samesitedemo-attacker.jub0bs.com is now SameSite as https://samesitedemo.jub0bs.com/

![](https://i.imgur.com/6RN7czv.jpg)

### 3.1.1 Is “StrictCookie” sent to server when navigating to https://samesitedemo-attacker.jub0bs.com/readcookie? If so, please capture request/response.
Yes, it is sent.
![](https://i.imgur.com/nRheLKw.png)


### 3.1.2. Change, “SameSite” attribute to “Lax” and navigate to https://samesitedemo-attacker.jub0bs.com/readcookie. Is “StrictCookie” sent to server? If so, please capture request/response.
Yes, the cookie is sent.
![](https://i.imgur.com/PajMWTB.png)

### 3.1.3. Change, “SameSite” attribute to “None” and navigate to https://samesitedemo-attacker.jub0bs.com/readcookie. Is “StrictCookie” sent to server? If so, please capture request/response.
Yes, it is also sent.
![](https://i.imgur.com/yoLvBsL.png)

### Question 2 Repeated

When repeating Question 2 from the designated URL, no cookies were sent.
![](https://i.imgur.com/jQVYp4L.jpg)

<div class="pagebreak"> </div>

## 4. **[Research]** – Optional question In question 3, does adding new cookie with value of “domain” attribute to “.jub0bs.com” have any impact to behaviour with respect to question 3? If so, please explain.

![](https://i.imgur.com/IaFTzr5.png)
*WeirdCookie set with attributes matching image in question. WeirdCookie has "domain" attribute set to ".jub0bs.com"*

When making a request to https://samesitedemo.jub0bs.com/readcookie with the new `WeirdCookie` in the cookie jar, the cookie is sent alongside the StrictCookie as shown below. Notably, the page only prints out the `StrictCookie=foo` as before indicating that the server likely looks only for the `StrictCookie` to prevent undefined behaviour.

```
GET /readcookie HTTP/1.1
Host: samesitedemo.jub0bs.com
Cookie: StrictCookie=foo; WeirdCookie=foo
Pragma: no-cache
Cache-Control: no-cache
Sec-Ch-Ua: "Chromium";v="92", " Not A;Brand";v="99", "Microsoft Edge";v="92"
Sec-Ch-Ua-Mobile: ?0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36 Edg/92.0.902.62
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en;q=0.9,en-US;q=0.8
Connection: close
```
![](https://i.imgur.com/GygP42T.png)
*All cookies in the cookie jar associated with the "jub0bs.com" domain being sent*

Similarly, performing the request via JavaScript will lead to the same behaviour - sending both cookies associated with the jub0bs.com domain. 

```
GET /readcookie HTTP/2
Host: samesitedemo.jub0bs.com
Cookie: StrictCookie=foo; WeirdCookie=foo
Pragma: no-cache
Cache-Control: no-cache
Sec-Ch-Ua: "Chromium";v="92", " Not A;Brand";v="99", "Microsoft Edge";v="92"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36 Edg/92.0.902.62
Accept: */*
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://samesitedemo.jub0bs.com/readcookie
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en;q=0.9,en-US;q=0.8
Connection: close
```
![](https://i.imgur.com/LYryU44.png)

However, since the subdomain is not specified, the cookie will be available to all subdomains sharing the same domain name.
![](https://i.imgur.com/lnWfi8m.png)

