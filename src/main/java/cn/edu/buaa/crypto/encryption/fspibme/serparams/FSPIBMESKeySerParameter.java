package cn.edu.buaa.crypto.encryption.fspibme.serparams;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

public class FSPIBMESKeySerParameter
{
    private transient Element ek;
    //private PairingKeySerParameter SenderSecretKeyParameter;

    public FSPIBMESKeySerParameter(PairingParameters pairingParameters, Element ek)
    {
        this.ek = ek.getImmutable();
    }

    public Element getEK()
    {
        return this.ek.duplicate();
    }
}
