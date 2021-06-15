package cn.edu.buaa.crypto.encryption.fspibme.utils;


import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05SecretKeySerParameter;

public class BTNode<E>
{
    private E data;
    private BTNode<E> left, right;
    private HIBEBBG05SecretKeySerParameter secretKeySerParameter;

    public BTNode(E initialData, BTNode<E> initialLeft, BTNode<E> initialRight)
    {
        left = initialLeft;
        right = initialRight;
        data = initialData;
    }

    public BTNode(E initialData)
    {
        data = initialData;
    }

    public E getData()
    {
        return data;
    }

    public HIBEBBG05SecretKeySerParameter getSecretKeySerParameter()
    {
        return secretKeySerParameter;
    }

    public void setSecretKeySerParameter(HIBEBBG05SecretKeySerParameter secretKeySerParameter)
    {
        this.secretKeySerParameter = secretKeySerParameter;
    }

    public BTNode<E> getLeft()
    {
        return left;
    }

    public void setLeft( BTNode<E> tempNode)
    {
        this.left = tempNode;
    }
    public void setRight( BTNode<E> tempNode)
    {
        this.right = tempNode;
    }

    public E getLeftmostData()
    {
        if (left == null)
            return data;
        else
            return left.getLeftmostData();
    }

    public BTNode<E> getRight()
    {
        return right;
    }

    public E getRightmostData()
    {
        if (right == null)
            return data;
        else
            return right.getRightmostData();
    }


    public BTNode<E> getParent(BTNode<E> p, BTNode<E> node)
    {
        if (p == null)
            return null;
        if (p.left == node || p.right == node)
            return p;
        BTNode<E> find = getParent(p.left, node);
        if (find == null)
            find = getParent(p.right, node);
        return find;
    }

    public BTNode<E> getSibling(BTNode<E> p, BTNode<E> node)
    {
        if (p == null)
            return null;

        BTNode<E> parent = getParent(p, node);

        if (parent == null)
            return null;
        if (node.getData() == parent.getLeft().getData())
            return parent.getRight();
        else
            return parent.getLeft();

    }

    //中序序遍历
    public void inorderPrint()
    {
        if (left != null)
            left.inorderPrint();
        System.out.println(data);
        if (right != null)
            right.inorderPrint();
    }

    //中序 遍历
    public void postorderPrint()
    {
        if (left != null)
            left.postorderPrint();
        if (right != null)
            right.postorderPrint();
        System.out.println(data);
    }

    //前序遍历
    public void preorderPrint()
    {
        System.out.println(data);
        if (left != null)
            left.preorderPrint();
        if (right != null)
            right.preorderPrint();
    }

    public boolean isLeaf()
    {
        return (left == null) && (right == null);
    }


}