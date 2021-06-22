package com.example.encryption.hibe;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.fspibme.FSPIBMEEngine;
import cn.edu.buaa.crypto.encryption.fspibme.serparams.FSPIBMECiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.fspibme.serparams.FSPIBMEESKSerParameter;
import cn.edu.buaa.crypto.encryption.fspibme.serparams.FSPIBMERKeySerParameter;
import cn.edu.buaa.crypto.encryption.fspibme.serparams.FSPIBMESKeySerParameter;
import cn.edu.buaa.crypto.encryption.fspibme.utils.BinaryTreeBuild;
import cn.edu.buaa.crypto.encryption.fspibme.utils.TestUtils;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.HIBEBBG05Engine;

import cn.edu.buaa.crypto.utils.FileTransferClient;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.junit.Test;

import java.io.*;

public class FSPIBMEJUnitTest {

    @Test
    public void test1() throws Exception {
        String id = "E";
        String[] taus = {"00000000000", "000000000000", "0000000000000", "000000000000", "000000000000", "000000000000"};
        String[] tags = {"000", "000", "000", "00", "000", "0000"};


        long startTime, endTime;
        ObjectOutputStream oos;
//        ObjectInputStream ois;
//        File file;
//        FileTransferClient client = new FileTransferClient();


        PairingParameters pairingParameters = PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256);
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        FSPIBMEEngine fspibmeEngine = FSPIBMEEngine.getInstance();
        HIBEBBG05Engine engine = HIBEBBG05Engine.getInstance();

        //Setup
        PairingKeySerPair keyPair = engine.setup(pairingParameters, BinaryTreeBuild.depth);
        PairingKeySerParameter publicKey = keyPair.getPublic();
        PairingKeySerParameter masterKey = keyPair.getPrivate();

        for (int j = 0; j < 6; j++) {
            String[] ids = null;
            String tau = taus[j];
            String tag = tags[j];

            int num = tau.length() + tag.length();
            for (int i = 0; i <= num; i++) {
                if (i == 0) {
                    ids = new String[num + 1];
                    ids[0] = "E";
                } else {
                    ids[i] = "0";
                }
            }
            System.out.println(num);
            //Keygen
            startTime = System.currentTimeMillis();
            FSPIBMESKeySerParameter sk = fspibmeEngine.SkeyGen(publicKey, masterKey, id);
            endTime = System.currentTimeMillis();
            System.out.println("SKGEN运行时间：" + (endTime - startTime) + "ms");

            startTime = System.currentTimeMillis();
            FSPIBMERKeySerParameter rk = fspibmeEngine.RkeyGen(publicKey, masterKey, ids);
            //System.out.println("目前RK拥有的结点秘钥 ：" + rk.getTk().keySet());
            endTime = System.currentTimeMillis();
            System.out.println("RKGEN运行时间：" + (endTime - startTime) + "ms");

            //序列化
            oos = new ObjectOutputStream(new FileOutputStream("outputs/rk"));
            oos.writeObject(rk);
            oos.close();
//            file = new File("outputs/rk");
//            ois = new ObjectInputStream(new FileInputStream(file));
//            System.out.println(System.currentTimeMillis());
//            client.sendFile("rk");

            //Verify
            startTime = System.currentTimeMillis();
            StringBuffer HIBEId = new StringBuffer();
            HIBEId.append("E");
            HIBEId.append(tau);
            HIBEId.append(tag);
            String strHIBEId = HIBEId.toString();
            System.out.println("ver:" + fspibmeEngine.verifyESK(publicKey, rk.getTk().get(strHIBEId)));
            endTime = System.currentTimeMillis();
            System.out.println("Ver运行时间：" + (endTime - startTime) + "ms");

            //Encryption
            Element message = pairing.getGT().newRandomElement().getImmutable();

            startTime = System.currentTimeMillis();
            FSPIBMECiphertextSerParameter ciphertext = fspibmeEngine.encryption(engine, publicKey, sk, id, message, tau, tag);
            endTime = System.currentTimeMillis();
            System.out.println("加密运行时间：" + (endTime - startTime) + "ms");
            //System.out.println("enc" + message);

            //Decryption
            startTime = System.currentTimeMillis();

            StringBuffer decId = new StringBuffer();
            decId.append(id);
            decId.append(tau);
            decId.append(ciphertext.getTag());
            String strDecId = decId.toString();
            FSPIBMEESKSerParameter eskId = rk.getTk().get(strDecId);

//            oos = new ObjectOutputStream(new FileOutputStream("outputs/esk"));
//            oos.writeObject(eskId.getX_rho());
//            oos.close();
//            System.out.println(System.currentTimeMillis());
//            client.sendFile("esk");

            Element anMessage = fspibmeEngine.decryption(engine, publicKey, rk, eskId, id, ciphertext, tau);

            endTime = System.currentTimeMillis();
            System.out.println("解密运行时间：" + (endTime - startTime) + "ms");
            //System.out.println("dec" + anMessage);

            //puncture
            startTime = System.currentTimeMillis();
            rk = fspibmeEngine.Puncture(publicKey, rk, engine, tau, tag);
            endTime = System.currentTimeMillis();
            System.out.println("Puncture运行时间：" + (endTime - startTime) + "ms");
            System.out.println();
            //System.out.println("目前RK拥有的结点秘钥有" + rk.getTk().keySet().size() + "个 ：" + rk.getTk().keySet());


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
}
