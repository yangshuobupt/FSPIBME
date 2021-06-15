package cn.edu.buaa.crypto.encryption.fspibme.generators;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.fspibme.serparams.FSPIBMECiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.fspibme.serparams.FSPIBMESKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.HIBEBBG05Engine;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05PublicKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class FSPIBMEEncryptionGenerator {
    private HIBEBBG05PublicKeySerParameter publicKeyParameter;
    private FSPIBMESKeySerParameter ek;
    private HIBEBBG05Engine hibebbg05Engine;
    private byte[] Z;
    private String tag;
    private String tau;
    private String rho;
    private Element message;
    private Element kR;

    public void init(HIBEBBG05Engine hibebbg05Engine, PairingKeySerParameter publicKey, FSPIBMESKeySerParameter ek, String rho, Element message, String tau, String tag) {
        this.hibebbg05Engine = hibebbg05Engine;
        this.publicKeyParameter = (HIBEBBG05PublicKeySerParameter) publicKey;
        this.ek = ek;
        this.rho = rho;
        this.tag = tag;
        this.tau = tau;
        this.message = message;
    }


    public FSPIBMECiphertextSerParameter computeEncapsulation() {
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());

        Element elementIBMEID = PairingUtils.MapStringToGroup(pairing, rho, PairingUtils.PairingGroupType.G1);

        Element u = pairing.getZr().newRandomElement().getImmutable();
        Element v = pairing.getZr().newRandomElement().getImmutable();
        Element pi = pairing.getGT().newRandomElement().getImmutable();
        StringBuffer HIBEId = new StringBuffer();
        HIBEId.append(rho);
        HIBEId.append(tau);
        HIBEId.append(tag);
        String strHIBEId = HIBEId.toString();
        int length = strHIBEId.length();
        String[] strs = new String[length];
        for (int i = 0; i < length; i++) {
            strs[i] = String.valueOf(strHIBEId.charAt(i));
        }
        PairingCipherSerParameter W = hibebbg05Engine.encryption(publicKeyParameter, strs, pi);

        Element U = publicKeyParameter.getG().powZn(u).getImmutable();
        Element V = publicKeyParameter.getG().powZn(v).getImmutable();
        Element kR = pairing.pairing(publicKeyParameter.getH().powZn(u), elementIBMEID).getImmutable();
        Element kS = pairing.pairing(V.mul(ek.getEK()), elementIBMEID).getImmutable();

        byte[] byteM = this.message.toBytes();
        byte[] byteKR = PairingUtils.hash(kR.toBytes());
        byte[] byteKS = PairingUtils.hash(kS.toBytes());
        byte[] bytePi = pi.toBytes();
        this.Z = PairingUtils.twoByteXor(byteM, byteKR);
        this.Z = PairingUtils.twoByteXor(this.Z, byteKS);
        this.Z = PairingUtils.twoByteXor(this.Z, bytePi);

        return new FSPIBMECiphertextSerParameter(publicKeyParameter.getParameters(), U, V, W, Z, tag);
    }


}
