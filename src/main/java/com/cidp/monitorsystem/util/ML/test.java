package com.cidp.monitorsystem.util.ML;

import weka.classifiers.bayes.NaiveBayesUpdateable;
import weka.classifiers.lazy.IBk;
import weka.classifiers.trees.J48;
import weka.core.Instance;
import weka.core.Instances;
import weka.core.Utils;
import weka.core.converters.ArffLoader;
import weka.core.converters.ConverterUtils;
import weka.core.converters.ConverterUtils.DataSource;

import java.io.File;
import java.util.Random;

public class test {
    public static void main(String[] args) throws Exception {
//        String path = "C:\\Users\\Administrator\\Desktop\\entry01.weka.allclass.arff";
//        ArffLoader loader = new ArffLoader();
//        loader.setFile(new File(path));
//        Instances stru = loader.getStructure();
//        System.out.println(stru);
//        stru.setClassIndex(stru.numAttributes()-1);
//        Instances data =  KNN.getFileInstances(path);
//        System.out.println(data.numInstances());
//        if (data.classIndex() == -1)
//            data.setClassIndex(data.numAttributes()-1);
        //决策树分类
//        String [] options =new String[1];
//        options[0] = "-U";
//        J48 tree = new J48();
//        tree.setOptions(options);
        //朴素贝叶斯分类
//        NaiveBayesUpdateable updateable = new NaiveBayesUpdateable();
//        updateable.buildClassifier(data);
//        Instance instance;
//        while ((instance= loader.getNextInstance(stru))!=null){
//            updateable.updateClassifier(instance);
//        }
//        System.out.println(updateable);

            new test().doSplit();

    }

    /**
     * 决策树分类
     * @throws Exception
     */
    public void doSplit() throws Exception {
        String path = "C:\\Users\\Administrator\\Desktop\\netflowtest.arff";
        Instances trainingSet = DataSource.read(path);
        trainingSet.randomize(new Random(0));
        int trainSize = (int) Math.round(trainingSet.numInstances()*0.66);
        int testSize = trainingSet.numInstances() - trainSize;
        Instances train = new Instances(trainingSet,0,trainSize);
        Instances test = new Instances(trainingSet,trainSize,testSize);
        train.setClassIndex(train.numAttributes()-1);//训练集
        test.setClassIndex(test.numAttributes()-1);//测试集
        System.out.println(test.numInstances());
        if (!train.equalHeaders(test)){
            throw new Exception("训练集和测试集不兼容"+train.equalHeadersMsg(test));
        }
        //训练分类器
        J48 classifier = new J48();
        classifier.buildClassifier(train);
        //KNN
        IBk classifierKnn = new IBk();
        classifierKnn.buildClassifier(train);
        double score=0;
        for (int i = 0; i < test.numInstances(); i++){// 测试分类结果
            int preIndex = i + 1;
            System.out.println("第"+ preIndex +"个样本的判断结果是：" + test.classAttribute().value((int) classifier.classifyInstance(test.instance(i))));
            System.out.println("第"+ preIndex +"个样本的类别属性是：" + test.instance(i).toString(test.classIndex()));
            boolean flag = false;

            if (classifier.classifyInstance(test.instance(i)) == test.instance(i).classValue()){// 如果预测值和答案值相等（测试语料中的分类列提供的须为正确答案，结果才有意义）
                score++;// 正确值加1
                flag = true;
            }
            System.out.println("第"+ preIndex +"个样本的判断结果是否正确：" + flag);
        }
        System.out.println("KNN classification precision:" + (score / test.numInstances()));




        //输出数据
//        System.out.println("编号\t-\t实际\t-\t预测\t-\t错误\t-\t分布");

//        for (int i = 0; i < 2; i++) {
//            //得到预测值
//            double pred = classifier.classifyInstance(test.instance(i));
//            double[] dist = classifier.distributionForInstance(test.instance(i));
//            System.out.print(i+1);
//            System.out.print("\t-\t");
//            System.out.print(test.instance(i).toString(test.classIndex()));
//            System.out.print("\t-\t");
//            System.out.print(test.classAttribute().value((int) pred));
//            System.out.print("\t-\t");
//            if (pred!=test.instance(i).classValue()){
//                System.out.print("是");
//            }
//            else{
//                score++;
//                System.out.print("否");
//            }
//            System.out.print("\t-\t");
//            System.out.print(Utils.arrayToString(dist));
//            System.out.println();
//        }
//        System.out.println(score/test.numInstances());
    }


}
