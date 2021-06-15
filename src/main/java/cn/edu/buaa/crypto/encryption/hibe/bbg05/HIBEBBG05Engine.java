package cn.edu.buaa.crypto.encryption.hibe.bbg05;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.fspibme.serparams.FSPIBMEESKSerParameter;
import cn.edu.buaa.crypto.encryption.hibe.HIBEEngine;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.generators.HIBEBBG05DecryptionGenerator;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.generators.HIBEBBG05EncryptionGenerator;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.generators.HIBEBBG05KeyPairGenerator;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.generators.HIBEBBG05SecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05HeaderSerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05SecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.genparams.*;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2015/11/3.
 *
 * Boneh-Boyen-Goh HIBE engine.
 */
public class HIBEBBG05Engine extends HIBEEngine {
    //Scheme name, used for exceptions
    public static final String SCHEME_NAME = "Boneh-Boyen-Goh-05 HIBE scheme";

    private static HIBEBBG05Engine engine;

    public static HIBEBBG05Engine getInstance() {
        if (engine == null) {
            engine = new HIBEBBG05Engine();
        }
        return engine;
    }

    private HIBEBBG05Engine() {
        super(SCHEME_NAME, ProveSecModel.Standard, PayloadSecLevel.CPA, PredicateSecLevel.NON_ANON);
    }

    public PairingKeySerPair setup(PairingParameters pairingParameters, int maxDepth) {
        HIBEBBG05KeyPairGenerator keyPairGenerator = new HIBEBBG05KeyPairGenerator();
        keyPairGenerator.init(new HIBEKeyPairGenerationParameter(pairingParameters, maxDepth));

        return keyPairGenerator.generateKeyPair();
    }

    public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String... ids) {

        HIBEBBG05SecretKeyGenerator secretKeyGenerator = new HIBEBBG05SecretKeyGenerator();
        secretKeyGenerator.init(new HIBESecretKeyGenerationParameter(
                publicKey, masterKey, ids));

        return secretKeyGenerator.generateKey();
    }

    public PairingKeySerParameter delegate(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey, String id) {

        HIBEBBG05SecretKeyGenerator secretKeyGenerator = new HIBEBBG05SecretKeyGenerator();
        secretKeyGenerator.init(new HIBEDelegateGenerationParameter(
                publicKey, secretKey, id));

        return secretKeyGenerator.generateKey();
    }

    public FSPIBMEESKSerParameter delegateESK(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey, String id) {


        HIBEBBG05SecretKeyGenerator secretKeyGenerator = new HIBEBBG05SecretKeyGenerator();
        secretKeyGenerator.init(new HIBEDelegateGenerationParameter(
                publicKey, secretKey, id));

        return secretKeyGenerator.generateEKey();
    }

    public PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, String[] ids, Element message){

        HIBEBBG05EncryptionGenerator encryptionGenerator = new HIBEBBG05EncryptionGenerator();
        encryptionGenerator.init(new HIBEEncryptionGenerationParameter(publicKey, ids, message));

        return encryptionGenerator.generateCiphertext();
    }

    public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, String[] ids){

        HIBEBBG05EncryptionGenerator encryptionGenerator = new HIBEBBG05EncryptionGenerator();
        encryptionGenerator.init(new HIBEEncryptionGenerationParameter(publicKey, ids, null));

        return encryptionGenerator.generateEncryptionPair();
    }

    public Element decryption(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                              String[] ids, PairingCipherSerParameter ciphertext) throws InvalidCipherTextException {

        HIBEBBG05DecryptionGenerator decapsulationGenerator = new HIBEBBG05DecryptionGenerator();
        decapsulationGenerator.init(new HIBEDecryptionGenerationParameter(
                publicKey, secretKey, ids, ciphertext));
        return decapsulationGenerator.recoverMessage();
    }

    public byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                              String[] ids, PairingCipherSerParameter header) throws InvalidCipherTextException {

        HIBEBBG05DecryptionGenerator decapsulationGenerator = new HIBEBBG05DecryptionGenerator();
        decapsulationGenerator.init(new HIBEDecryptionGenerationParameter(
                publicKey, secretKey, ids, header));
        return decapsulationGenerator.recoverKey();
    }

    public String getEngineName() {
        return SCHEME_NAME;
    }
}
