package cn.edu.buaa.crypto.encryption.fspibme;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.fspibme.serparams.FSPIBMECiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.fspibme.serparams.FSPIBMERKeySerParameter;
import cn.edu.buaa.crypto.encryption.fspibme.serparams.FSPIBMESKeySerParameter;
import cn.edu.buaa.crypto.encryption.fspibme.utils.BinaryTreeBuild;
import cn.edu.buaa.crypto.encryption.fspibme.utils.TestUtils;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.HIBEBBG05Engine;
import edu.princeton.cs.algs4.Out;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.util.Set;

import static cn.edu.buaa.crypto.utils.PairingUtils.setCompare;

public class FSPIBMEMain {
    private String tau;

    //private static final String[] identityVector12 = {"E", "0"};


    public static void main(String[] args) throws InvalidCipherTextException {
        String id = "e";
        long startTime, endTime;

        PairingParameters pairingParameters = PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256);
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        FSPIBMEEngine fspibmeEngine = FSPIBMEEngine.getInstance();
        HIBEBBG05Engine engine = HIBEBBG05Engine.getInstance();

        //Setup
        PairingKeySerPair keyPair = engine.setup(pairingParameters, BinaryTreeBuild.depth);
        PairingKeySerParameter publicKey = keyPair.getPublic();
        PairingKeySerParameter masterKey = keyPair.getPrivate();

        //Keygen
        startTime = System.currentTimeMillis();
        FSPIBMESKeySerParameter sk = fspibmeEngine.SkeyGen(publicKey, masterKey, id);
        endTime = System.currentTimeMillis();
        System.out.println("SKGEN运行时间：" + (endTime - startTime) + "ms");

        startTime = System.currentTimeMillis();
        FSPIBMERKeySerParameter rk = fspibmeEngine.RkeyGen(publicKey, masterKey, id);
        System.out.println("目前RK拥有的结点秘钥 ：" + rk.getTk().keySet());
        endTime = System.currentTimeMillis();
        System.out.println("RKGEN运行时间：" + (endTime - startTime) + "ms");

        //Encryption
        Element message = pairing.getGT().newRandomElement().getImmutable();
        String tau = "0";
        String tag = "0";
        startTime = System.currentTimeMillis();
        FSPIBMECiphertextSerParameter ciphertext = fspibmeEngine.encryption(engine, publicKey, sk, id, message, tau, tag);
        endTime = System.currentTimeMillis();
        System.out.println("加密运行时间：" + (endTime - startTime) + "ms");
        System.out.println("enc" + message);

//        //Decryption
//        startTime = System.currentTimeMillis();
//        Element anMessage = fspibmeEngine.decryption(engine, publicKey, rk, id, ciphertext, tau);
//        endTime = System.currentTimeMillis();
//        System.out.println("解密运行时间：" + (endTime - startTime) + "ms");
//        System.out.println("dec" + anMessage);

//        //puncture
//        System.out.println("======Puncture=====");
//        startTime = System.currentTimeMillis();
//        rk = fspibmeEngine.Puncture(publicKey, rk, engine, punID[i], tag);
//        endTime = System.currentTimeMillis();
//        System.out.println("Puncture运行时间：" + (endTime - startTime) + "ms");
//        System.out.println("目前RK拥有的结点秘钥有" + rk.getTk().keySet().size() + "个 ：" + rk.getTk().keySet());
//
//        Set<String> set1 = rk.getTk().keySet();
//        //Update
//        System.out.println("======Update=====");
//        startTime = System.currentTimeMillis();
//        rk = fspibmeEngine.Update(publicKey, rk, engine, updateID[j]);
//        endTime = System.currentTimeMillis();
//        System.out.println("Update运行时间：" + (endTime - startTime) + "ms");
//        System.out.println("目前RK拥有的结点秘钥有" + rk.getTk().keySet().size() + "个 ：" + rk.getTk().keySet());
//        Set<String> set2 = rk.getTk().keySet();
//        setCompare(set1, set2);


    }
}
