package cn.edu.buaa.crypto.encryption.fspibme.generators;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.fspibme.serparams.FSPIBMEESKSerParameter;
import cn.edu.buaa.crypto.encryption.fspibme.serparams.FSPIBMERKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.generators.HIBEBBG05SecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05SecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.genparams.HIBEDelegateGenerationParameter;
import cn.edu.buaa.crypto.encryption.hibe.genparams.HIBESecretKeyGenerationParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.HashMap;
import java.util.Map;

public class FSPIBMERKeyGenerator {

    private HIBEBBG05MasterSecretKeySerParameter masterSecretKeyParameter;
    private HIBEBBG05PublicKeySerParameter publicKeyParameter;
    private HIBEBBG05SecretKeySerParameter rootSk;
    private String rho;
    private String[] ids;

    public void init(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String... ids) {
        this.masterSecretKeyParameter = (HIBEBBG05MasterSecretKeySerParameter) masterKey;
        this.publicKeyParameter = (HIBEBBG05PublicKeySerParameter) publicKey;
        this.rho = ids[0];
        this.ids = ids;
    }

    public FSPIBMERKeySerParameter generateKey() {

        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        Element elementIds = PairingUtils.MapStringToGroup(pairing, rho, PairingUtils.PairingGroupType.G1);
        Element dk1 = elementIds.powZn(masterSecretKeyParameter.getR()).getImmutable();
        Element dk2 = elementIds.powZn(masterSecretKeyParameter.getS()).getImmutable();
        Element delta = pairing.getZr().newRandomElement().getImmutable();

        HIBEBBG05SecretKeyGenerator secretKeyGenerator = new HIBEBBG05SecretKeyGenerator();
        String[] tempId = {ids[0]};
        secretKeyGenerator.init(new HIBESecretKeyGenerationParameter(publicKeyParameter, masterSecretKeyParameter, tempId));
        rootSk = (HIBEBBG05SecretKeySerParameter) secretKeyGenerator.generateKey();

        Element a0 = rootSk.getA0().getImmutable();
        a0 = a0.mul(publicKeyParameter.getG().powZn(delta)).getImmutable();
        rootSk.setA0(a0);

        Element R_rho = publicKeyParameter.getG().powZn(delta).getImmutable();

        Map<String, FSPIBMEESKSerParameter> tk = new HashMap<String, FSPIBMEESKSerParameter>();


        for (int i = 0; i < ids.length; i++) {
            if (i == 0) {
                FSPIBMEESKSerParameter eskRho = new FSPIBMEESKSerParameter(rootSk, R_rho);

                tk.put(ids[0], eskRho);
            } else {
                StringBuffer sb = new StringBuffer();
                String fatherId = null;
                for (int j = 0; j <= i; j++) {
                    sb.append(ids[j]);
                    if (j == i - 1)
                        fatherId = sb.toString();
                }
                String id = sb.toString();

                secretKeyGenerator = new HIBEBBG05SecretKeyGenerator();
                secretKeyGenerator.init(new HIBEDelegateGenerationParameter(publicKeyParameter, tk.get(fatherId).getX_rho(), ids[i]));
                PairingKeySerParameter sk_i = secretKeyGenerator.generateKey();
                FSPIBMEESKSerParameter esk_i = new FSPIBMEESKSerParameter(sk_i, R_rho);
                tk.put(id, esk_i);
            }
        }


        return new FSPIBMERKeySerParameter(dk1, dk2, delta, rho, tk);

    }
}
