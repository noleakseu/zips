## Signed ZIP library
The library extends standard ZipOutputStream by implementing SHA-256 signatures and trusted time stamps.
Signed ZIP archive can be verified by `jarsigner`.

## Requirements
- Java 8+

## Installation
Add Maven dependency
```xml
<dependency>
    <groupId>eu.noleaks</groupId>
    <artifactId>zips</artifactId>
    <version>1.0.1</version>
</dependency>
```

## Usage
Create self-signed archive:
```java
KeyStore.PrivateKeyEntry privateKeyEntry;
FileOutputStream archive = new FileOutputStream("signed.zip");
URL tsa = new URL("http://rfc3161timestamp.globalsign.com/advanced");
try (SignedZipOutputStream stream = new SignedZipOutputStream(archive, privateKeyEntry, tsa)) {
    String lorem = "Lorem ipsum dolor sit amet";
    ZipEntry entry = new ZipEntry("lorem ipsum.txt");
    entry.setSize(lorem.getBytes(StandardCharsets.UTF_8).length);
    stream.putNextEntry(entry);
    stream.write(lorem.getBytes(StandardCharsets.UTF_8));
    stream.closeEntry();
}
```
Annotate the archive by a tag:
```java
stream
    .setTag(Tags.Title, "Lorem ipsum")
    .setTag(Tags.Possessor, "Cicero")
    .setTag(Tags.Subject, "Lorem ipsum is a placeholder text commonly used to demonstrate the visual form of a document")
    .setTag(Tags.Keywords, "placeholder design")
    .setTag(Tags.Version, "1.10.32")
```
Verify:
```shell
$ jarsigner -verbose -verify signed.zip
jar verified.
```
