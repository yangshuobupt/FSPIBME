package cn.edu.buaa.crypto.encryption.fspibme.serparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05SecretKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;

import java.io.Serializable;

public class FSPIBMEESKSerParameter implements Serializable {
    private transient PairingKeySerParameter X_rho;
    private transient Element R_rho;

    public PairingKeySerParameter getX_rho() {
        return X_rho;
    }

    public void setX_rho(PairingKeySerParameter x_rho) {
        X_rho = x_rho;
    }

    public Element getR_rho() {
        return R_rho;
    }

    public void setR_rho(Element r_rho) {
        R_rho = r_rho;
    }

    public FSPIBMEESKSerParameter(PairingKeySerParameter x_rho, Element r_rho) {

        X_rho = x_rho;
        R_rho = r_rho;
    }
}
