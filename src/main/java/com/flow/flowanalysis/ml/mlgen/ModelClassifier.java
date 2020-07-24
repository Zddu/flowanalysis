package com.flow.flowanalysis.ml.mlgen;

import java.util.logging.Level;
import java.util.logging.Logger;
import weka.classifiers.Classifier;
import weka.classifiers.trees.J48;
import weka.core.Instances;
import weka.core.SerializationHelper;


public class ModelClassifier {

    public void classifiy(Instances test, String path) {
        Classifier cls = null;
        double score=0;
        try {
            cls = (J48) SerializationHelper.read(path);
//            result = classVal.get((int) cls.classifyInstance(insts.firstInstance()));
            for (int i = 0; i < test.numInstances(); i++){// 测试分类结果
                int preIndex = i + 1;
//                System.out.println("第"+ preIndex +"个样本的判断结果是：" + test.classAttribute().value((int) cls.classifyInstance(test.instance(i))));
//                System.out.println("第"+ preIndex +"个样本的类别属性是：" + test.instance(i).toString(test.classIndex()));
                boolean flag = false;
                if (cls.classifyInstance(test.instance(i)) == test.instance(i).classValue()){// 如果预测值和答案值相等（测试语料中的分类列提供的须为正确答案，结果才有意义）
                    score++;// 正确值加1
                    flag = true;
                }
                System.out.println("第"+ preIndex +"个样本的判断结果是否正确：" + flag);
            }
            System.out.println("Model classification precision:" + (score / test.numInstances()));
        } catch (Exception ex) {
            Logger.getLogger(ModelClassifier.class.getName()).log(Level.SEVERE, null, ex);
        }
    }



}
