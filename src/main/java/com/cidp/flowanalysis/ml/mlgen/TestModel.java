package com.cidp.flowanalysis.ml.mlgen;

import com.cidp.flowanalysis.ml.util.Utils;
import weka.classifiers.evaluation.Evaluation;
import weka.classifiers.misc.InputMappedClassifier;
import weka.classifiers.trees.J48;
import weka.core.Instances;
import weka.core.SerializationHelper;
import weka.core.converters.CSVLoader;

import java.io.*;

public class TestModel {
    public static void main(String[] args) throws Exception {
        ModelGenerator mg = new ModelGenerator();


        CSVLoader loader = new CSVLoader();
        loader.setSource(new FileInputStream("C:\\Users\\Administrator\\Desktop\\1\\1.pcap_Flow.csv"));
        String [] options = new String[1];
        options[0]="-H";
        loader.setOptions(options);
//        Instances test = loader.getDataSet();
        //classifiy a single instance
        J48 cls = (J48) SerializationHelper.read("D:\\htmlMade\\javaprac\\flowanalysis\\src\\main\\resources\\j48.model");
//        test.setClassIndex(test.numAttributes()-1);
//        for (int i = 0; i < test.numInstances(); i++){// 测试分类结果
////            double v = cls.classifyInstance(test.instance(i));
//            double[] doubles = cls.distributionForInstance(test.instance(i));
//            for (double aDouble : doubles) {
//                System.out.printf("%.1f\t",aDouble);
//            }
//
//            System.out.println();
//        }

        Instances test = new Instances(
                new BufferedReader(
                        new FileReader("C:\\Users\\Administrator\\Desktop\\1 (1).arff")));
        InputMappedClassifier imc = new InputMappedClassifier();
        test.setClassIndex(test.numAttributes() - 1);
        imc.setModelPath("D:\\htmlMade\\javaprac\\flowanalysis\\src\\main\\resources\\j48.model");
        imc.setSuppressMappingReport(true);
        Evaluation evaluation = new Evaluation(test);
        evaluation.evaluateModel(imc,test);
//        Prediction pre = new NumericPrediction();
//        System.out.println(pre.predicted());
//        System.out.println(evaluation.predictions());
        // set class attribute

        // create copy
        Instances labeled = new Instances(test);
        for (int i = 0; i < test.numInstances(); i++) {
            double clsLabel = imc.classifyInstance(imc.constructMappedInstance(test.instance(i)));
            double[] doubles = imc.distributionForInstance(imc.constructMappedInstance(test.instance(i)));
            System.out.println(Utils.MAX(doubles));
            labeled.instance(i).setClassValue(clsLabel);
            System.out.println(labeled.instance(i).toString(labeled.classIndex()));
        }

//        Evaluation eva = new Evaluation(labeled);
//        eva.evaluateModel(imc,imc.getModelHeader(labeled));
//        System.out.println();
//        System.out.println(eva.predictions().get(1).predicted());
//        for (int i = 0; i < eva.predictions().size(); i++) {
//            System.out.print(eva.predictions().get(i).predicted()+"---");
//            System.out.println(eva.predictions().get(i).actual());
//        }
        // label instances
//        for (int i = 0; i < test.numInstances(); i++) {
//            double clsLabel = imc.classifyInstance(test.instance(i));
//            labeled.instance(i).setClassValue(clsLabel);
//        }
        // save labeled data
//        BufferedWriter writer = new BufferedWriter(
//                new FileWriter("C:\\Users\\Administrator\\Desktop\\1\\324.arff"));
//        writer.write(labeled.toString());
//        writer.newLine();
//        writer.flush();
//        writer.close();

        //        ModelClassifier cls = new ModelClassifier();
        //        cls.classifiy(test, "C:\\Users\\Administrator\\Desktop\\flowanalysis\\src\\main\\resources\\EP2FLOW.model");
    }
}
