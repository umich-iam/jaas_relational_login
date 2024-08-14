# jaas_relational_login
JAAS module for authenticating against a relational DBMS

For details and instruction, please visit http://www.robertogallea.com/blog/shibboleth_using_relational_dbms_as_authentication_backend



# Navigate to the project root directory
cd path/to/my-java-project

# Build the project using Maven
mvn package

# Verify the contents of the generated JAR file
jar tf target/jaas_relational_login-0.0.1-SNAPSHOT.jar

# Run the Java application using the generated JAR file
java -cp target/jaas_relational_login-0.0.1-SNAPSHOT.jar:lib/mysql-connector-j-8.3.0.jar:lib/spring-security-crypto-5.1.3.RELEASE.jar:lib/commons-logging-1.3.3.jar:lib/commons-codec-1.16.1.jar -Djava.security.auth.login.config=config/jaas.config -Dlogback.configurationFile=config/logback.xml sample.SampleAcn

# THIS SEEMS LESS ANNOYING?
mvn dependency:build-classpath -Dmdep.outputFile=classpath.txt
java -cp "$(cat classpath.txt):lib/mysql-connector-j-8.3.0.jar:target/classes" \
  -Djava.security.auth.login.config=config/jaas.config \
  -Dlogback.configurationFile=config/logback.xml \
  sample.SampleAcn

java -cp "$(cat classpath.txt):lib/mysql-connector-j-8.3.0.jar:target/classes" -Djava.security.auth.login.config=config/jaas.config -Dlogback.configurationFile=config/logback.xml com.robertogallea.shibboleth.idp.sample.SampleAcn
