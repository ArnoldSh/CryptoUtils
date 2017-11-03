package org.crypto;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.Base64;

/**
 * Created by ashamsutdinov on 22.09.2017.
 * <pre>
 * Fast utils to parsing RSA Keys from different sources:
 *      - XML as File, XML Document or raw string,
 *      - PEM encoded file or raw string,
 *      - DER bytes
 * </pre>
 * TODO: extend with another inputs (mb byte[] and other)
 * TODO: consider opportunity of implementation of parsing another types of keys (EC, DH, DSA and etc)
 */
public class RSAKeyParser {
    
    public RSAPrivateKey privateKeyFromXML(Document xmlDoc) throws Exception {
        BigInteger  modulus = null,
                    publicExponent = null,
                    primeP = null,
                    primeQ = null,
                    primeExponentP = null,
                    primeExponentQ = null,
                    crtCoefficient = null,
                    privateExponent = null;
        
        NodeList nodeList =  xmlDoc.getChildNodes();
        for(int i = 0; i < nodeList.getLength(); i++) {
            String nodeName = nodeList.item(i).getNodeName();
            BigInteger number = new BigInteger( 1, Base64.getDecoder().decode( nodeList.item(i).getTextContent() ) );
            switch(nodeName) {
                case "Modulus":
                    modulus = number;
                    break;
                case "Exponent":
                    publicExponent = number;
                    break;
                case "P":
                    primeP = number;
                    break;
                case "Q":
                    primeQ = number;
                    break;
                case "DP":
                    primeExponentP = number;
                    break;
                case "DQ":
                    primeExponentQ = number;
                    break;
                case "InverseQ":
                    crtCoefficient = number;
                    break;
                case "D":
                    privateExponent = number;
                    break;
            }
        }
        
        return buildPrivateKey(new BigInteger[] {
                modulus,
                publicExponent,
                privateExponent,
                primeP,
                primeQ,
                primeExponentP,
                primeExponentQ,
                crtCoefficient
        });
    }
    
    public RSAPrivateKey privateKeyFromXML(String xml) throws Exception {
        try {
            
            BigInteger modulus = new BigInteger( 1, Base64.getDecoder().decode( getXmlTagValue(xml, "Modulus") ) );
            BigInteger publicExponent = new BigInteger( 1, Base64.getDecoder().decode( getXmlTagValue(xml, "Exponent") ) );
            BigInteger privateExponent = new BigInteger( 1, Base64.getDecoder().decode( getXmlTagValue(xml, "D") ) );
            BigInteger primeP = new BigInteger(1, Base64.getDecoder().decode( getXmlTagValue(xml, "P") ) );
            BigInteger primeQ = new BigInteger( 1, Base64.getDecoder().decode( getXmlTagValue(xml, "Q") ) );
            BigInteger primeExponentP = new BigInteger( 1, Base64.getDecoder().decode( getXmlTagValue(xml, "DP") ) );
            BigInteger primeExponentQ = new BigInteger( 1, Base64.getDecoder().decode( getXmlTagValue(xml, "DQ") ) );
            BigInteger crtCoefficient = new BigInteger( 1, Base64.getDecoder().decode( getXmlTagValue(xml, "InverseQ") ) );
            
            return buildPrivateKey(new BigInteger[] {
                    modulus,
                    publicExponent,
                    privateExponent,
                    primeP,
                    primeQ,
                    primeExponentP,
                    primeExponentQ,
                    crtCoefficient
            });
            
        } catch(Exception ex) {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            
            DocumentBuilder db = dbf.newDocumentBuilder();
            
            return privateKeyFromXML(db.parse(new ByteArrayInputStream(xml.getBytes("UTF-8"))));
        }
        
    }
    
    public RSAPrivateKey privateKeyFromXML(File file) throws Exception {
        return privateKeyFromXML(new String(Files.readAllBytes(file.toPath()), "UTF-8"));
    }
    
    public RSAPrivateKey privateKeyFromPEM(String pem) throws Exception {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(getDecodedBytes(pem));
        java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    }
    
    public RSAPrivateKey privateKeyFromDER(byte[] bytes) throws Exception {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
        java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    }
    
    public RSAPrivateKey privateKeyFromPemFile(File file) throws Exception {
        return privateKeyFromPEM(new String(Files.readAllBytes(file.toPath()), "UTF-8"));
    }
    
    public RSAPublicKey publicKeyFromPEM(File file) throws Exception {
        return publicKeyFromPEM(new String(Files.readAllBytes(file.toPath()), "UTF-8"));
    }
    
    public RSAPublicKey publicKeyFromPEM(String pem) throws Exception {
        byte[] decodedBytes = getDecodedBytes(pem);
        try {
            RSAPrivateCrtKey privateKeyWithCert;
            {
                KeySpec keySpec = new PKCS8EncodedKeySpec(decodedBytes);
                java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
                privateKeyWithCert = (RSAPrivateCrtKey) keyFactory.generatePrivate(keySpec);
            }
            {
                KeySpec keySpec = new RSAPublicKeySpec(privateKeyWithCert.getModulus(), privateKeyWithCert.getPublicExponent());
                java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
                return (RSAPublicKey) keyFactory.generatePublic(keySpec);
            }

        } catch(Exception ex) {
            KeySpec keySpec = new X509EncodedKeySpec(decodedBytes);
            java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        }
    }
    
    private byte[] getDecodedBytes(String base64pem) throws Exception {
        String content = new String(base64pem);
        content = content.replaceAll("((-----)(.)+(-----))", "").replaceAll("\\s", "").trim();
        return Base64.getDecoder().decode(content);
    }
    
    public RSAPublicKey publicKeyFromXML(Document xmlDoc) throws Exception {
        BigInteger  modulus = null,
                    publicExponent = null;
    
        NodeList nodeList =  xmlDoc.getChildNodes();
        for(int i = 0; i < nodeList.getLength(); i++) {
            String nodeName = nodeList.item(i).getNodeName();
            BigInteger number = new BigInteger(1, Base64.getDecoder().decode( nodeList.item(i).getTextContent() ) );
            switch(nodeName) {
                case "Modulus":
                    modulus = number;
                    break;
                case "Exponent":
                    publicExponent = number;
                    break;
            }
        }
        return buildPublicKey(new BigInteger[] {
                modulus,
                publicExponent
        });
    }
    
    public RSAPublicKey publicKeyFromXML(String xml) throws Exception {
        try {
            BigInteger modulus = new BigInteger(1,  Base64.getDecoder().decode( getXmlTagValue(xml, "Modulus") ) );
            BigInteger publicExponent = new BigInteger(1,  Base64.getDecoder().decode( getXmlTagValue(xml, "Exponent") ) );
    
            return buildPublicKey(new BigInteger[] {
                    modulus,
                    publicExponent
            });
            
        } catch(Exception ex) {
    
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
    
            DocumentBuilder db = dbf.newDocumentBuilder();
    
            return publicKeyFromXML(db.parse(new ByteArrayInputStream(xml.getBytes("UTF-8"))));
            
        }
    }
    
    public RSAPublicKey publicKeyFromXML(File file) throws Exception {
        return publicKeyFromXML(new String(Files.readAllBytes(file.toPath()), "UTF-8"));
    }
    
    private RSAPublicKey buildPublicKey(BigInteger[] params) throws Exception {
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(params[0], params[1]);
        java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
        return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    }
    
    private RSAPrivateKey buildPrivateKey(BigInteger[] params) throws Exception {
        RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(
                params[0],
                params[1],
                params[2],
                params[3],
                params[4],
                params[5],
                params[6],
                params[7]
        );
        java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    }
    
    private String getXmlTagValue(String xml, String tagName) {
        try {
            return xml.split("<" + tagName + ">")[1].split("</" + tagName + ">")[0];
        } catch(RuntimeException ex) {
            return "";
        }
    }
    
}
