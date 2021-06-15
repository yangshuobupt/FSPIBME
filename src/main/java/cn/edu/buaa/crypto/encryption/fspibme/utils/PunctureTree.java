package cn.edu.buaa.crypto.encryption.fspibme.utils;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.HIBEBBG05Engine;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05SecretKeySerParameter;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

public class PunctureTree
{


    public static Map<String, HIBEBBG05SecretKeySerParameter>  PunctureTree(PairingKeySerParameter publicKeyParameter, HIBEBBG05Engine hibebbg05Engine, BTNode T, Map<String, BTNode> nodeList, Map<String, HIBEBBG05SecretKeySerParameter> tk, String n)
    {

        Map<String, HIBEBBG05SecretKeySerParameter> tkP = new HashMap<String, HIBEBBG05SecretKeySerParameter>();
        Set<String> keySet = tk.keySet();
        Iterator<String> it = keySet.iterator();
        while (it.hasNext())
        {
            String nP = it.next();
            char a = n.charAt(0);
            char b = nP.charAt(0);
            String ntmp;
            if (nP != n && a != b)
            {
                tkP.put(nP, tk.get(nP));
            }
            else if (a == b)
            {
                ntmp = n;
                while (T.getParent(T, nodeList.get(ntmp)) != null)
                {
                    BTNode<String> nodeFather= T.getParent(T, nodeList.get(ntmp));
                    BTNode<String> nodeSibling= T.getSibling(T, nodeList.get(ntmp));
                    String nodeString =  nodeSibling.getData();
                    if(nP.length() < nodeSibling.getData().length()&& b == nodeString.charAt(0))
                    {
                        PairingKeySerParameter delegateKey = hibebbg05Engine.delegate(publicKeyParameter, tk.get(nP), nodeString);
                        tkP.put(nodeString, (HIBEBBG05SecretKeySerParameter) delegateKey);
                        ntmp = nodeFather.getData();
                    }
                }

            }

        }
        return tkP;

    }


}

