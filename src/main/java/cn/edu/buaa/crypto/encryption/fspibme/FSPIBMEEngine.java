package cn.edu.buaa.crypto.encryption.fspibme;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.fspibme.generators.FSPIBMEDecrtptionGenerator;
import cn.edu.buaa.crypto.encryption.fspibme.generators.FSPIBMEEncryptionGenerator;
import cn.edu.buaa.crypto.encryption.fspibme.generators.FSPIBMERKeyGenerator;
import cn.edu.buaa.crypto.encryption.fspibme.generators.FSPIBMESKeyGenerator;
import cn.edu.buaa.crypto.encryption.fspibme.serparams.FSPIBMECiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.fspibme.serparams.FSPIBMEESKSerParameter;
import cn.edu.buaa.crypto.encryption.fspibme.serparams.FSPIBMERKeySerParameter;
import cn.edu.buaa.crypto.encryption.fspibme.serparams.FSPIBMESKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.HIBEBBG05Engine;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.generators.HIBEBBG05KeyPairGenerator;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.generators.HIBEBBG05SecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05SecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.genparams.HIBEKeyPairGenerationParameter;
import cn.edu.buaa.crypto.encryption.hibe.genparams.HIBESecretKeyGenerationParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import edu.princeton.cs.algs4.Out;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.util.Map;

public class FSPIBMEEngine {
    //Scheme name, used for exceptions
    public static final String SCHEME_NAME = "FS-PIBME";

    private static FSPIBMEEngine engine;
    String default_path = "benchmarks/encryption/fs-PIBME/";
    Out out = new Out(default_path + "fs-pibme");
    long startTime, endTime;

    public static FSPIBMEEngine getInstance() {
        if (engine == null) {
            engine = new FSPIBMEEngine();
        }
        return engine;
    }


    public PairingKeySerPair setup(PairingParameters pairingParameters, int maxDepth) {
        HIBEBBG05KeyPairGenerator keyPairGenerator = new HIBEBBG05KeyPairGenerator();
        keyPairGenerator.init(new HIBEKeyPairGenerationParameter(pairingParameters, maxDepth));

        return keyPairGenerator.generateKeyPair();
    }


    public FSPIBMESKeySerParameter SkeyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String id) {


        FSPIBMESKeyGenerator secretKeyGenerator = new FSPIBMESKeyGenerator();
        secretKeyGenerator.init(publicKey, masterKey, id);

        return secretKeyGenerator.generateKey();
    }

    public FSPIBMERKeySerParameter RkeyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String... ids) {
        HIBEBBG05SecretKeyGenerator secretKeyGenerator = new HIBEBBG05SecretKeyGenerator();

        FSPIBMERKeyGenerator SecretKeyGenerator = new FSPIBMERKeyGenerator();
        SecretKeyGenerator.init(publicKey, masterKey, ids);

        return SecretKeyGenerator.generateKey();
    }

    public FSPIBMERKeySerParameter Puncture(PairingKeySerParameter publicKey, FSPIBMERKeySerParameter rk, HIBEBBG05Engine engine, String tau, String tag) {
        StringBuffer punIdBuffer = new StringBuffer();
        punIdBuffer.append(rk.getRho());
        punIdBuffer.append(tau);
        punIdBuffer.append(tag);
        String punctureNode = punIdBuffer.toString();


        out.println("Puncture : ");
        out.println("目前RK拥有的结点秘钥 ：" + rk.getTk().keySet());
        out.println("刺穿结点" + punctureNode + "在第" + (punctureNode.length() + 1) + "层");
        startTime = System.currentTimeMillis();
        //System.out.println("刺穿结点" + punctureNode + "在第" + (punctureNode.length() + 1) + "层");

        Map<String, FSPIBMEESKSerParameter> tkP = PairingUtils.PunctureTree(publicKey, engine, rk.getTk(), punctureNode);

        out.println("刺穿后RK拥有的结点秘钥 ：" + rk.getTk().keySet());
        endTime = System.currentTimeMillis();
        out.println("Puncture运行时间：" + (endTime - startTime) + "ms");
        out.println();
        rk.setTk(tkP);
        return rk;
    }

    public boolean verifyESK(PairingKeySerParameter publicKey, FSPIBMEESKSerParameter esk) {
        HIBEBBG05PublicKeySerParameter publicKeyParameter = (HIBEBBG05PublicKeySerParameter) publicKey;
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        HIBEBBG05SecretKeySerParameter sk = (HIBEBBG05SecretKeySerParameter) esk.getX_rho();

        Element[] bs = sk.getBs();

        Element r = pairing.getZr().newOneElement().getImmutable();
        Element temp1 = pairing.pairing(sk.getA0().mul(bs[bs.length - 1].powZn(r)), publicKeyParameter.getG());
        Element temp2 = pairing.getG2().newOneElement();
        for (int i = 0; i < bs.length; i++) {
            temp2 = temp2.mul(bs[i]);
        }
        Element temp3 = pairing.pairing(temp2.mul(publicKeyParameter.getG3()), esk.getR_rho());
        temp1 = pairing.pairing(sk.getA1(), publicKeyParameter.getG()).mul(pairing.pairing(publicKeyParameter.getG(), esk.getR_rho()));
        for (int i = 0; i < bs.length; i++) {
            temp1 = pairing.pairing(bs[i], publicKeyParameter.getG()).mul(pairing.pairing(publicKeyParameter.getHsAt(i), esk.getR_rho()));
        }

        return true;
    }

//    public FSPIBMERKeySerParameter Update(PairingKeySerParameter publicKey, FSPIBMERKeySerParameter rk, HIBEBBG05Engine engine, String tau)
//    {
//
//        //String id[] = null;
//
//        String[] rho = rk.getRho();
//        String punctureNode = null;
//
//        for (int i = 1; i < rho.length; i++)
//        {
//            if (punctureNode == null)
//                punctureNode = rho[i];
//            else
//                punctureNode = punctureNode + rho[i];
//        }
//
//        punctureNode = punctureNode + tau;
//        out.println("Update : ");
//        out.println("目前RK拥有的结点秘钥 ：" + rk.getTk().keySet());
//
//        out.println("刺穿结点" + punctureNode + "在第" + (punctureNode.length() + 1) + "层");
//        startTime = System.currentTimeMillis();
//        System.out.println("刺穿结点" + punctureNode + "在第" + (punctureNode.length() + 1) + "层");
//
//        Map<String, HIBEBBG05SecretKeySerParameter> tkP = PairingUtils.PunctureTree(publicKey, engine, rk.getTk(), punctureNode);
//
//        out.println("更新后RK拥有的结点秘钥 ：" + rk.getTk().keySet());
//        endTime = System.currentTimeMillis();
//        out.println("Update运行时间：" + (endTime - startTime) + "ms");
//        out.println();
//
//        rk.setTK(tkP);
//        return rk;
//    }

    public FSPIBMECiphertextSerParameter encryption(HIBEBBG05Engine hibebbg05Engine, PairingKeySerParameter publicKey, FSPIBMESKeySerParameter ek, String ids, Element message, String tau, String tag) {

        FSPIBMEEncryptionGenerator encryptionGenerator = new FSPIBMEEncryptionGenerator();
        encryptionGenerator.init(hibebbg05Engine, publicKey, ek, ids, message, tau, tag);

        return encryptionGenerator.computeEncapsulation();
    }


    public Element decryption(HIBEBBG05Engine hibebbg05Engine, PairingKeySerParameter publicKey, FSPIBMERKeySerParameter dk, FSPIBMEESKSerParameter eskId,
                              String ids, FSPIBMECiphertextSerParameter ciphertext, String tau) throws InvalidCipherTextException {
        FSPIBMEDecrtptionGenerator decrtptionGenerator = new FSPIBMEDecrtptionGenerator();
        decrtptionGenerator.init(hibebbg05Engine, publicKey, dk, eskId, ids, ciphertext, tau);
        return decrtptionGenerator.computeDecapsulation();
    }


    public String getEngineName() {
        return SCHEME_NAME;
    }
}
