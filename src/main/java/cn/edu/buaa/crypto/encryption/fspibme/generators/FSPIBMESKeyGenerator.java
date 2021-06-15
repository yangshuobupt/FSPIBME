package cn.edu.buaa.crypto.encryption.fspibme.generators;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.fspibme.serparams.FSPIBMESKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05PublicKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class FSPIBMESKeyGenerator
{
    //private KeyGenerationParameters params;
    private HIBEBBG05MasterSecretKeySerParameter masterSecretKeyParameter;
    private HIBEBBG05PublicKeySerParameter publicKeyParameter;
    private String id;
    public void init(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String id)
    {
        this.masterSecretKeyParameter = (HIBEBBG05MasterSecretKeySerParameter)masterKey;
        this.publicKeyParameter =  (HIBEBBG05PublicKeySerParameter)publicKey;
        this.id = id;
    }

    public FSPIBMESKeySerParameter generateKey()
    {

        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        Element elementIds = PairingUtils.MapStringToGroup(pairing, this.id, PairingUtils.PairingGroupType.G1);
        Element ek = elementIds.powZn(masterSecretKeyParameter.getS()).getImmutable();
        return new FSPIBMESKeySerParameter(publicKeyParameter.getParameters(), ek);

    }
}
