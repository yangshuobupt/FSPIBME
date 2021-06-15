package cn.edu.buaa.crypto.encryption.fspibme.utils;

import javax.swing.tree.TreeNode;
import java.util.*;

public class BinaryTreeBuild
{
    public static int depth = 20;


    public static BTNode<String> BuildTree(Map<String, BTNode> nodeList, String treedata, int n)
    {

        if (n < Math.pow(2, depth) - 1)
        {

            int l = n * 2 + 1;
            int r = n * 2 + 2;
            if (treedata == "E")
            {
                BTNode<String> TreeRoot = new BTNode<String>(treedata, BuildTree(nodeList, "0", l), BuildTree(nodeList, "1", r));
                nodeList.put(treedata, TreeRoot);
                return TreeRoot;

            }
            else
            {
                BTNode<String> TreeRoot = new BTNode<String>(treedata, BuildTree(nodeList, treedata + "0", l), BuildTree(nodeList, treedata + "1", r));
                nodeList.put(treedata, TreeRoot);
                return TreeRoot;

            }

        }
        else
            return null;

    }

    public static void LevelOrderBuild(Queue<BTNode<String>> queue, Map<String, BTNode> nodeList)
    {
        int level = 2;
        while (!queue.isEmpty() && level <= depth)
        {
            int level_length = queue.size();
            for (int i = 0; i < level_length; i++)
            {
                BTNode<String> node = queue.poll();
                nodeList.put(node.getData(), node);
                if(level == depth) break;
                if (node.getLeft() == null)
                {
                    BTNode<String> tempNode = new BTNode<String>(node.getData() + "0");
                    node.setLeft(tempNode);
                    queue.add(tempNode);
                }
                if (node.getRight() == null)
                {
                    BTNode<String> tempNode = new BTNode<String>(node.getData() + "1");
                    node.setRight(tempNode);
                    queue.add(tempNode);
                }
            }
            level++;

        }
    }



    public static BTNode<String> BuildTree(Map<String, BTNode> nodeList, String[] treedata, int n)
    {

        if (treedata.length == 0)
            return null;
        else
        {
            if (n < treedata.length)
            {
                int l = n * 2 + 1;
                int r = n * 2 + 2;

                BTNode<String> TreeRoot = new BTNode<String>(treedata[n], BuildTree(nodeList, treedata, l), BuildTree(nodeList, treedata, r));
                nodeList.put(treedata[n], TreeRoot);
                return TreeRoot;
            }
            else
                return null;
        }
    }


    public static void main(String args[]) throws Exception
    {

        Map<String, BTNode> nodeList = new HashMap<String, BTNode>();
        BTNode<String> T = new BTNode<String>("E");
        BTNode<String> treeroot0 = new BTNode<String>("0");
        BTNode<String> treeroot1 = new BTNode<String>("1");
        T.setLeft(treeroot0);
        T.setRight(treeroot1);
        Queue<BTNode<String>> queue = new LinkedList<BTNode<String>>();
        queue.add(treeroot0);
        queue.add(treeroot1);
        nodeList.put("E", T);
        LevelOrderBuild(queue, nodeList);


       // String[] treedata = {"E", "0", "1", "00", "01", "10", "11", "000", "001", "010", "011", "100", "101", "110", "111"};


        //List<BTNode<String>> nodeList= new ArrayList<BTNode<String>>();
        //treeroot = BuildTree(nodeList, treedata, 0);
        //treeroot = BuildTree(nodeList, "E", 0);

        //BTNode<String> find = treeroot.getParent(treeroot, nodeList.get("101"));
        //BTNode<String> find2 = treeroot.getSibling(treeroot, nodeList.get("E"));

        System.out.println("后序遍历");
//        treeroot.postorderPrint();
//        System.out.println("前序遍历");
//        treeroot.preorderPrint();
//        System.out.println("中序遍历");
//        treeroot.inorderPrint();
    }


}
