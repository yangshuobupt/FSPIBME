package cn.edu.buaa.crypto.encryption.fspibme.generators;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.fspibme.serparams.FSPIBMECiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.fspibme.serparams.FSPIBMEESKSerParameter;
import cn.edu.buaa.crypto.encryption.fspibme.serparams.FSPIBMERKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.HIBEBBG05Engine;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05SecretKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.InvalidCipherTextException;

public class FSPIBMEDecrtptionGenerator {
    private Element message;
    private HIBEBBG05PublicKeySerParameter publicKeyParameter;
    private FSPIBMECiphertextSerParameter ciphertext;
    private FSPIBMERKeySerParameter dk;
    private HIBEBBG05Engine hibebbg05Engine;
    private String sigma;
    private PairingCipherSerParameter W;
    private String tau;
    private FSPIBMEESKSerParameter eskId;

    public void init(HIBEBBG05Engine hibebbg05Engine, PairingKeySerParameter publicKey, FSPIBMERKeySerParameter dk, FSPIBMEESKSerParameter eskId,
                     String sigma, FSPIBMECiphertextSerParameter FSPIBMEciphertext, String tau) {
        this.hibebbg05Engine = hibebbg05Engine;
        this.publicKeyParameter = (HIBEBBG05PublicKeySerParameter) publicKey;
        this.dk = dk;
        this.W = FSPIBMEciphertext.getW();
        this.sigma = sigma;
        this.tau = tau;
        this.ciphertext = FSPIBMEciphertext;
        this.eskId = eskId;

    }

    public Element computeDecapsulation() throws InvalidCipherTextException {
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());

        StringBuffer id = new StringBuffer();
        id.append(sigma);
        id.append(tau);
        id.append(ciphertext.getTag());
        String strHIBEId = id.toString();
        int length = strHIBEId.length();
        String[] strs = new String[length];
        for (int i = 0; i < length; i++) {
            strs[i] = String.valueOf(strHIBEId.charAt(i));
        }

        //FSPIBMEESKSerParameter eskId = dk.getTk().get(sigma);
        HIBEBBG05SecretKeySerParameter skId = (HIBEBBG05SecretKeySerParameter) eskId.getX_rho();
        Element a0Prime = skId.getA0().getImmutable();
        Element a0 = a0Prime.div(publicKeyParameter.getG().powZn(dk.getDk()));
        skId.setA0(a0);

        //PairingKeySerParameter delegateKey = hibebbg05Engine.delegate(publicKeyParameter, secretKeyParameters, "0");
        //delegateKey = hibebbg05Engine.delegate(publicKeyParameter, delegateKey, "1");

        Element elementIBMEID = PairingUtils.MapStringToGroup(pairing, sigma, PairingUtils.PairingGroupType.G1);
        Element kR = pairing.pairing(ciphertext.getU(), dk.getDk1()).getImmutable();
        Element temp = pairing.pairing(dk.getDk2(), elementIBMEID).getImmutable();
        Element kS = temp.mul(pairing.pairing(ciphertext.getV(), elementIBMEID)).getImmutable();

        Element pi = hibebbg05Engine.decryption(publicKeyParameter, skId, strs, W);

        byte[] byteKR = PairingUtils.hash(kR.toBytes());
        byte[] byteKS = PairingUtils.hash(kS.toBytes());
        byte[] bytePi = pi.toBytes();
        byte[] byteM = PairingUtils.twoByteXor(ciphertext.getZ(), byteKR);
        byteM = PairingUtils.twoByteXor(byteM, byteKS);
        byteM = PairingUtils.twoByteXor(byteM, bytePi);
        this.message = pairing.getGT().newElementFromBytes(byteM).getImmutable();
        return this.message;
    }
}
