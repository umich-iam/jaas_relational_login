# Shibboleth: Using Relational DBMS as authentication backend
## Learn how to use a relational DBMS as authentication provider for Shibboleth IDP instead of default LDAP

The information in README.md has additional information about updated features.

[The original documentation can be found here](https://robertogallea.com/posts/development/shibboleth-using-relational-dbms-as-authentication-backend)

_**NOTE:** This code seems to be heavily influenced by the [tagish-jaas](https://github.com/chriseldredge/tagish-jaas/tree/master).  I think the original repository is gone - the tagish.com domain seems to be for sale, and the only copy of the code I found looks like it started as a fork?_

Natively, Shibboleth supports a variety of authentication methods, among those the most general (and default) is Password-based authentication. It performs a username-password pair check against a user backend. The backend could be provided in many ways. Off the shelves Shibboleth provides following:

* LDAP-based, uses an LDAP source;
* JAAS-based, uses a JAAS authentication scheme;
* Kerberos, uses a Kerberos authentication system.
* JAAS is the most flexible, because allows to use any backend, provided that it is interfaced through the JAAS (Java Autentication and Authorization Service) scheme. The drawback is that you need to write the JAAS Class to interface your backend.

This guide shows you how to implement JAAS authetication for Shibboleth using a relational DBMS such as MySQL, Oracle or MSSQL. Note that this describes how to autheticate against a relational DBMS, not how to acquire attributes from it, which is possible out of the box.

1) [Prerequisites](#prerequisites)
2) [JAAS custom classes creation](#jaas-custom-classes-creation)
3) [JAAS custom classes deployment](#jaas-custom-class-deployment)
4) [Shibboleth configuration](#shibboleth-configuration)

## Prerequisites
This guide assumes the following:

* Familiarity with Shibboleth IDP.
 * _**NOTE:** This code was originally written for IDP v3, but we've used it with v4 and v5 at UMich, and the URL references to Shibboleth documentation have been made current_
* You have a Shibboleth IDP installation already running on your system. If not, refer to official installation instructions at [Shibboleth Identity Provider 5 / DeployerResources / Installation](https://shibboleth.atlassian.net/wiki/spaces/IDP5/pages/3199500577/Installation).
* You have a relational database of your choice containing a user table with username and (hashed) password columns, as follows (column names maybe different)

| username | password | salt_column (optional) | last_login_column (optional) | other_data |
| :------: | :------: | :--------------------: | :--------------------------: | :--------: |
| -        | -        | -                      | -                            | -          |

## JAAS Custom Classes Creation
For authentican purposes, a Java class must inherit from the LoginModule abstract class, and must implement five methods:

* initialize
* login
* commit
* abort
* logout

The complete code repository implementing JAAS LoginModule for Relational DBMS Authentication is available at: https://github.com/robertogallea/jaas_relational_login or you could download the compiled JAR from this page.
Build it to obtain a jar archive, that has to be deployed to your shibboleth IDP instance.

## JAAS Custom Class Deployment
After building the JAAS module, you are required to deploy to the IDP application, in order to make it available for use. This is accomplished following some steps:

1) Copy the archive jaas_relational_login-2.0.0.jar under /edit-webapp/WEB-INF/lib
2) Download the JDBC driver for your DBMS, for example, for Oracle is ojdbc7.jar and copy it under /edit-webapp/WEB-INF/lib
3) Run /bin/build.sh script to rebuild the IDP web application
4) If required, deploy the newly built application into your container (tomcat, jetty, IIs, etc.)

## Shibboleth Configuration
This is the most important part, some configurations are required:

* Creation of jaas.config
* Setting JAAS as authenticator for Shibboleth IDP

### Creation of jaas.config
Create or replace the file jaas.config under /conf/authn using the following content:

```
/** Login Configuration for the JAAS Sample Application **/

ShibUserPassAuth  {
   com.robertogallea.shibboleth.idp.relationalLogin.DBLogin required debug=true
   dbDriver="oracle.jdbc.driver.OracleDriver"
   userTable="userTableName"
   userColumn="username"
   passColumn="password_sha"
   dbURL="your_db_url"
   dbUser="dbUserName"
   dbPassword="dbPassword"
   hashAlgorithm="SHA-512"
   saltColumn=""
   lastLoginColumn=""
   rehashCryptEnabled=false
   errorMessage="Invalid password";
};
```
edit it as required including the relevant data according to your DBMS configuration.

**Note**: if in your table you have a salt stored in a column, set it in saltColumn, parameter, otherwise leave it blank, or omit it. The salted hash will be calculated as hash(password + salt)

**Note2**: in the case you wish to use cleartext password, leave hashAlgorithm blank or omit it.

**Note3**: available hashing algorithms are DBMS native hashing functions (e.g. SHA-1, SHA-256), bcrypt, and GNU crypt compatible hashes (SHA-512, SHA-256, MD5, DES)

**Note4**: if you set **hashAlgorithm** to `crypt`, you need to set saltColumn to the same value you provide for **passwordColum**.  crypted strings contain the salt.

**Note5**: if your database credential has write access to the userTable, and you provide a value for lastLoginColumn, the timestamp of the user's login will be stored

**Note6**: if you are using `crypt` and the database has write access to the userTable, the module can be configured to re-hash the password using a more secure algorithm, by setting `rehashCryptEnabled` to `true`. (commons-codec Crypt.crypt() currently defaults to SHA-512)

## Setting JAAS as authenticator for Shibboleth IDP
Open the file /conf/authn/password-authn-config.xml, and modify it from:
```
    <util:list id="shibboleth.authn.Password.Validators">
        <ref bean="shibboleth.LDAPValidator" />
        <!-- <ref bean="shibboleth.KerberosValidator" /> -->
        <!-- <ref bean="shibboleth.JAASValidator" /> -->
        <!-- <bean parent="shibboleth.HTPasswdValidator" p:resource="%{idp.home}/credentials/demo.htpasswd" /> -->
    </util:list>
```
to
```
    <util:list id="shibboleth.authn.Password.Validators">
        <!-- <ref bean="shibboleth.LDAPValidator" /> -->
        <!-- <ref bean="shibboleth.KerberosValidator" /> -->
        <!-- <ref bean="shibboleth.JAASValidator" />
        <bean parent="shibboleth.HTPasswdValidator" p:resource="%{idp.home}/credentials/demo.htpasswd" /> -->
    </util:list>
```
to disable ldap authenticator and enable jaas authenticator.


**Note**: Do not change jaas.config filename or the login context name inside it (ShibUserPassAuth) to something else, otherwise you will need to change the content of the 

---

# Building
## jaas_relational_login
JAAS module for authenticating against a relational DBMS

For details and instruction, please visit http://www.robertogallea.com/blog/shibboleth_using_relational_dbms_as_authentication_backend

## Navigate to the project root directory
`cd path/to/my-java-project`

## Build the project using Maven
`mvn package`

## Verify the contents of the generated JAR file
```
jar tf target/jaas_relational_login-2.0-SNAPSHOT.jar
```

### Run the Java application using the generated JAR file
```
java -cp target/jaas_relational_login-2.0.0-SNAPSHOT.jar:lib/mysql-connector-j-8.3.0.jar:lib/spring-security-crypto-5.1.3.RELEASE.jar:lib/commons-logging-1.3.3.jar:lib/commons-codec-1.16.1.jar -Djava.security.auth.login.config=config/jaas.config -Dlogback.configurationFile=config/logback.xml sample.SampleAcn
```

## THIS SEEMS LESS ANNOYING?
```
mvn dependency:build-classpath -Dmdep.outputFile=classpath.txt

java -cp "$(cat classpath.txt):lib/mysql-connector-j-8.3.0.jar:target/classes" \
  -Djava.security.auth.login.config=config/jaas.config \
  -Dlogback.configurationFile=config/logback.xml \
  sample.SampleAcn
```
or
```
java -cp "$(cat classpath.txt):lib/mysql-connector-j-8.3.0.jar:target/classes" -Djava.security.auth.login.config=config/jaas.config -Dlogback.configurationFile=config/logback.xml com.robertogallea.shibboleth.idp.sample.SampleAcn
```
