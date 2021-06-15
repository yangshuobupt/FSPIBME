package cn.edu.buaa.crypto.encryption.fspibme.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

public class FSPIBMECiphertextSerParameter extends PairingCipherSerParameter
{
    private transient Element A;
    private transient Element V;
    private transient Element U;
    private PairingCipherSerParameter W;
    private transient String tag;
    private byte[] Z;



    public FSPIBMECiphertextSerParameter(PairingParameters pairingParameters, Element U, Element V, PairingCipherSerParameter W, byte[] Z, String tag)
    {
        super(pairingParameters);
        this.V = V.getImmutable();
        this.U = U.getImmutable();
        this.W = W;
        this.Z = Z;
        this.tag = tag;

    }

    public Element getA() {
        return A;
    }

    public void setA(Element a) {
        A = a;
    }

    public Element getV() {
        return V;
    }

    public void setV(Element v) {
        V = v;
    }

    public Element getU() {
        return U;
    }

    public void setU(Element u) {
        U = u;
    }

    public PairingCipherSerParameter getW() {
        return W;
    }

    public void setW(PairingCipherSerParameter w) {
        W = w;
    }

    public String getTag() {
        return tag;
    }

    public void setTag(String tag) {
        this.tag = tag;
    }

    public byte[] getZ() {
        return Z;
    }

    public void setZ(byte[] z) {
        Z = z;
    }
}
