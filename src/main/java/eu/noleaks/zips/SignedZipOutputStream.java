package eu.noleaks.zips;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.tsp.TimeStampResp;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.attribute.FileTime;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.util.*;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * https://docs.oracle.com/javase/10/docs/specs/jar/jar.html
 */
final public class SignedZipOutputStream extends ZipOutputStream {
    private static final String MANIFEST_MF = "META-INF/MANIFEST.MF";
    private static final String SIGNER_RSA = "META-INF/SIGNER.RSA";
    private static final String SIGNER_SF = "META-INF/SIGNER.SF";
    private static final String TAG_MANIFEST_VERSION = "Manifest-Version";
    private static final String TAG_SIGNATURE_VERSION = "Signature-Version";
    private static final String NEWLINE = "\r\n";
    private static MessageDigest messageDigest;
    static {
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    private final Manifest manifest = new Manifest();
    private final Manifest signature = new Manifest();
    private final KeyStore.PrivateKeyEntry privateKeyEntry;
    private final URL tsa;
    private ZipEntry current;
    private FileTime now;

    /**
     * @param out Output stream
     * @param privateKeyEntry KeyStore's private key
     * @param tsa Timestamp-Authority
     */
    public SignedZipOutputStream(OutputStream out, KeyStore.PrivateKeyEntry privateKeyEntry, URL tsa) {
        super(out);
        this.privateKeyEntry = privateKeyEntry;
        this.tsa = tsa;
        this.manifest.getMainAttributes().putValue(TAG_MANIFEST_VERSION, "1.0");
        this.signature.getMainAttributes().putValue(TAG_SIGNATURE_VERSION, "1.0");
    }

    /**
     * Annotate zip by a tag
     */
    public SignedZipOutputStream setTag(Tags tags, String value) {
        if (tags == Tags.SignedBy || tags == Tags.Timestamp || tags == Tags.TimestampingAuthority) {
            return this;
        }
        this.signature.getMainAttributes().putValue(tags.getAttribute(), value);
        return this;
    }

    /**
     * Get tags
     */
    public Map<String, Object> getTags() {
        Map<String, Object> tags = new HashMap<>();
        this.signature.getMainAttributes().forEach((key, value) -> {
            try {
                tags.put(Tags.nameOf(key.toString()).name(), value);
            } catch (IllegalArgumentException ignored) {
            }
        });
        this.manifest.getMainAttributes().forEach((key, value) -> {
            try {
                tags.put(Tags.nameOf(key.toString()).name(), value);
            } catch (IllegalArgumentException ignored) {
            }
        });
        return tags;
    }

    @Override
    public void putNextEntry(ZipEntry e) throws IOException {
        this.current = e;
        super.putNextEntry(e);
    }

    @Override
    public void write(byte[] b) throws IOException {
        if (null != this.current && !this.current.isDirectory()) {
            final Attributes manifestAttrs = new Attributes();
            manifestAttrs.putValue(
                    messageDigest.getAlgorithm() + "-Digest",
                    Base64.getEncoder().encodeToString(messageDigest.digest(b))
            );
            this.manifest.getEntries().put(this.current.getName(), manifestAttrs);

            final StringBuilder sb = new StringBuilder();
            sb.append("Name: ").append(this.current.getName()).append(NEWLINE);
            for (Map.Entry<Object, Object> attr : manifestAttrs.entrySet()) {
                sb.append(attr.getKey()).append(": ").append(attr.getValue()).append(NEWLINE);
            }
            sb.append(NEWLINE);

            final Attributes signatureAttrs = new Attributes();
            signatureAttrs.putValue(
                    messageDigest.getAlgorithm() + "-Digest",
                    Base64.getEncoder().encodeToString(messageDigest.digest(sb.toString().getBytes(StandardCharsets.UTF_8)))
            );
            this.signature.getEntries().put(this.current.getName(), signatureAttrs);
        }
        super.write(b);
    }

    @Override
    public void closeEntry() throws IOException {
        this.current = null;
        super.closeEntry();
    }

    @Override
    public void close() throws IOException {
        try {
            // SIGNER_RSA
            final ByteArrayOutputStream signer = new ByteArrayOutputStream();
            this.signature.write(signer);
            addEntry(new ZipEntry(SIGNER_RSA), sign(signer.toByteArray(), this.privateKeyEntry));

            // MANIFEST_MF
            final ByteArrayOutputStream manifest = new ByteArrayOutputStream();
            this.manifest.write(manifest);
            addEntry(new ZipEntry(MANIFEST_MF), manifest.toByteArray());

            // SIGNER_SF
            Attributes attributes = this.signature.getMainAttributes();
            attributes.putValue(
                    messageDigest.getAlgorithm() + "-Digest-Manifest",
                    Base64.getEncoder().encodeToString(messageDigest.digest(manifest.toByteArray()))
            );

            final StringBuilder sb = new StringBuilder();
            for (Map.Entry<Object, Object> attr : this.manifest.getMainAttributes().entrySet()) {
                sb.append(attr.getKey()).append(": ").append(attr.getValue()).append(NEWLINE);
            }
            sb.append(NEWLINE);

            attributes.putValue(
                    messageDigest.getAlgorithm() + "-Digest-Manifest-Main-Attributes",
                    Base64.getEncoder().encodeToString(messageDigest.digest(sb.toString().getBytes(StandardCharsets.UTF_8)))
            );
            addEntry(new ZipEntry(SIGNER_SF), signer.toByteArray());
        } catch (CertificateEncodingException | TSPException | CMSException | OperatorCreationException e) {
            throw new IOException(e);
        }
        super.close();
    }

    /**
     * Add zip file
     */
    private void addEntry(ZipEntry entry, byte[] content) throws IOException {
        entry.setCreationTime(this.now);
        entry.setLastModifiedTime(this.now);
        entry.setLastAccessTime(this.now);
        entry.setSize(content.length);
        super.putNextEntry(entry);
        super.write(content);
        super.closeEntry();
    }

    /**
     * Generate SIGNER.RSA in PKCS7 DER format
     * Check: openssl pkcs7 -in SIGNER.RSA -inform DER -print_certs
     */
    private byte[] sign(byte[] data, KeyStore.PrivateKeyEntry privateKeyEntry) throws IOException, CertificateEncodingException, CMSException, TSPException, OperatorCreationException {
        Security.addProvider(new BouncyCastleProvider());
        final ContentSigner contentSigner = new ContentSigner() {
            final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

            @Override
            public AlgorithmIdentifier getAlgorithmIdentifier() {
                return new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withRSA");
            }

            @Override
            public OutputStream getOutputStream() {
                return byteArrayOutputStream;
            }

            @Override
            public byte[] getSignature() {
                try {
                    byte[] content = byteArrayOutputStream.toByteArray();
                    Signature signature = Signature.getInstance("SHA256withRSA");
                    signature.initSign(privateKeyEntry.getPrivateKey());
                    signature.update(content);
                    return signature.sign();
                } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
                    e.printStackTrace();
                }
                return null;
            }
        };
        final CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        org.bouncycastle.asn1.x509.Certificate cert = org.bouncycastle.asn1.x509.Certificate.getInstance(ASN1Primitive.fromByteArray(privateKeyEntry.getCertificate().getEncoded()));
        final X509CertificateHolder signingCertificate = new X509CertificateHolder(cert);
        generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(contentSigner, signingCertificate));
        generator.addCertificates(new JcaCertStore(Arrays.asList(privateKeyEntry.getCertificateChain())));

        final CMSTypedData cmsData = new CMSProcessableByteArray(data);
        final CMSSignedData signedData = generator.generate(cmsData, false);

        SignerInformation signerInformation = signedData.getSignerInfos().getSigners().iterator().next();

        final ASN1EncodableVector timestampVector = new ASN1EncodableVector();
        TimeStampToken timestampToken = timestamp(messageDigest.digest(signerInformation.getSignature()));
        timestampVector.add(
                new Attribute(
                        PKCSObjectIdentifiers.id_aa_signatureTimeStampToken,
                        new DERSet(ASN1Primitive.fromByteArray(timestampToken.getEncoded()))
                )
        );

        final AttributeTable attributeTable = new AttributeTable(timestampVector);
        SignerInformation signerInformationWithTimestamp = SignerInformation.replaceUnsignedAttributes(signerInformation, attributeTable);
        List<SignerInformation> signerInformationStore = Collections.singletonList(signerInformationWithTimestamp);
        final SignerInformationStore newSignerStore = new SignerInformationStore(signerInformationStore);
        CMSSignedData newSignedData = CMSSignedData.replaceSigners(signedData, newSignerStore);

        ASN1Primitive signedDataAsASN1 = newSignedData.toASN1Structure().toASN1Primitive();

        this.now = FileTime.from(timestampToken.getTimeStampInfo().getGenTime().toInstant());
        this.manifest.getMainAttributes().putValue(Tags.Timestamp.getAttribute(), this.now.toString());
        this.manifest.getMainAttributes().putValue(Tags.TimestampingAuthority.getAttribute(), timestampToken.getSID().getIssuer().toString());
        this.manifest.getMainAttributes().putValue(Tags.SignedBy.getAttribute(), signerInformation.getSID().getIssuer().toString());

        return signedDataAsASN1.getEncoded("DER");
    }

    /**
     * Timestamp by TSA
     */
    private TimeStampToken timestamp(byte[] data) throws IOException, TSPException {
        final TimeStampRequestGenerator timeStampRequestGenerator = new TimeStampRequestGenerator();
        timeStampRequestGenerator.setCertReq(true);
        TimeStampRequest request = timeStampRequestGenerator.generate(TSPAlgorithms.SHA256, data);
        final byte[] requestEncoded = request.getEncoded();
        HttpURLConnection connection = (HttpURLConnection) tsa.openConnection();
        connection.setDoOutput(true);
        connection.setDoInput(true);
        connection.setRequestProperty("Content-Type", "application/timestamp-query");
        connection.setRequestProperty("Content-Length", String.valueOf(requestEncoded.length));
        OutputStream out = connection.getOutputStream();
        out.write(requestEncoded);
        out.flush();
        if (connection.getResponseCode() != HttpURLConnection.HTTP_OK) {
            throw new IOException("HTTP " + connection.getResponseCode() + ": " + connection.getResponseMessage());
        }
        InputStream inputStream = connection.getInputStream();
        TimeStampResp resp = TimeStampResp.getInstance(new ASN1InputStream(inputStream).readObject());
        final TimeStampResponse response = new TimeStampResponse(resp);
        response.validate(request);
        if (0 != response.getStatus()) {
            throw new IOException("Error: " + response.getFailInfo());
        }
        return response.getTimeStampToken();
    }
}
