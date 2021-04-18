package eu.noleaks.zips;

import org.junit.Assert;
import org.junit.Test;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.zip.ZipEntry;

public class SignedZipOutputStreamTest {
    private static final String TSA = "http://rfc3161timestamp.globalsign.com/advanced";
    private static final String ALIAS = "alias";
    private static final String PASSWORD = "password";
    private static final String ARCHIVE = "signed.zip";

    @Test
    public void signedZipOutputStream() throws Exception {
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) generateKeyStore().getEntry(ALIAS, new KeyStore.PasswordProtection(PASSWORD.toCharArray()));
        SignedZipOutputStream stream = new SignedZipOutputStream(new FileOutputStream(ARCHIVE), privateKeyEntry, new URL(TSA));

        String lorem = "Lorem ipsum dolor sit amet";
        ZipEntry entry = new ZipEntry("lorem ipsum.txt");
        entry.setSize(lorem.getBytes(StandardCharsets.UTF_8).length);
        stream.putNextEntry(entry);
        stream.write(lorem.getBytes(StandardCharsets.UTF_8));
        stream.closeEntry();

        String sed = "Sed ut perspiciatis unde omnis";
        entry = new ZipEntry("dir/Cicero.txt");
        entry.setSize(sed.getBytes(StandardCharsets.UTF_8).length);
        stream.putNextEntry(entry);
        stream.write(sed.getBytes(StandardCharsets.UTF_8));
        stream.closeEntry();

        stream
                .setTag(Tags.Title, "Lorem ipsum")
                .setTag(Tags.Possessor, "Cicero")
                .setTag(Tags.Subject, "Lorem ipsum is a placeholder text commonly used to demonstrate the visual form of a document")
                .setTag(Tags.Keywords, "placeholder design")
                .setTag(Tags.Version, "1.10.32")
                .setTag(Tags.TimestampingAuthority, "fictional")
                .setTag(Tags.SignedBy, "fictional")
                .setTag(Tags.Timestamp, "fictional");

        stream.close();

        Assert.assertArrayEquals(
                new String[]{"Keywords", "Possessor", "SignedBy", "Subject", "Timestamp", "TimestampingAuthority", "Title", "Version"},
                stream.getTags().keySet().stream().sorted().toArray()
        );
    }

    private KeyStore generateKeyStore() throws NoSuchProviderException, NoSuchAlgorithmException, KeyStoreException, InvalidKeyException, IOException, CertificateException, SignatureException {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, new char[0]);
        CertAndKeyGen certGenerator = new CertAndKeyGen("RSA", "SHA256WithRSA", null);
        certGenerator.generate(4096);
        X509Certificate certificate = certGenerator.getSelfCertificate(new X500Name("CN=selfsigned, O=org, L=city, C=country"), (long) 7 * 24 * 60 * 60);
        keyStore.setKeyEntry(ALIAS, certGenerator.getPrivateKey(), PASSWORD.toCharArray(), new X509Certificate[]{certificate});
        return keyStore;
    }
}