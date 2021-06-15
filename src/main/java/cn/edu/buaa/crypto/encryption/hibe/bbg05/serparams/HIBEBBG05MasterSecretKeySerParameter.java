package cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2015/11/3.
 *
 * Master Secret Key Paramaters for Boneh-Boyen-Goh HIBE.
 */
public class HIBEBBG05MasterSecretKeySerParameter extends PairingKeySerParameter {
    private transient Element g2Alpha;
    private final byte[] byteArrayG2Alpha;

    private transient Element r;
    private transient Element s;

    public HIBEBBG05MasterSecretKeySerParameter(PairingParameters pairingParameters, Element g2Alpha, Element r, Element s)
    {
        super(true, pairingParameters);
        this.g2Alpha = g2Alpha.getImmutable();
        this.r = r.getImmutable();
        this.s = s.getImmutable();
        this.byteArrayG2Alpha = this.g2Alpha.toBytes();
    }

    public Element getG2Alpha()
    {
        return this.g2Alpha.duplicate();
    }

    public Element getR()
    {
        return this.r.duplicate();
    }

    public Element getS()
    {
        return this.s.duplicate();
    }

}
