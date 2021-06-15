package cn.edu.buaa.crypto.encryption.fspibme.serparams;

import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05SecretKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

public class FSPIBMERKeySerParameter implements Serializable {
    private transient Element dk1;
    private transient Element dk2;
    private transient Element dk;
    private transient String rho;
    private transient Map<String, FSPIBMEESKSerParameter> tk;

    public FSPIBMERKeySerParameter(Element dk1, Element dk2, Element dk, String rho, Map<String, FSPIBMEESKSerParameter> tk) {
        this.dk1 = dk1;
        this.dk2 = dk2;
        this.dk = dk;
        this.rho = rho;
        this.tk = tk;
    }

    public Element getDk1() {
        return dk1;
    }

    public void setDk1(Element dk1) {
        this.dk1 = dk1;
    }

    public Element getDk2() {
        return dk2;
    }

    public void setDk2(Element dk2) {
        this.dk2 = dk2;
    }

    public Element getDk() {
        return dk;
    }

    public void setDk(Element dk) {
        this.dk = dk;
    }

    public String getRho() {
        return rho;
    }

    public void setRho(String rho) {
        this.rho = rho;
    }

    public Map<String, FSPIBMEESKSerParameter> getTk() {
        return tk;
    }

    public void setTk(Map<String, FSPIBMEESKSerParameter> tk) {
        this.tk = tk;
    }
}
