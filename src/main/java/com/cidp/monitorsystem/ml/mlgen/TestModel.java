package com.cidp.monitorsystem.ml.mlgen;

import weka.classifiers.trees.J48;
import weka.core.Instances;
import weka.core.SerializationHelper;
import weka.core.converters.CSVLoader;
import weka.filters.Filter;

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
        J48 cls = (J48) SerializationHelper.read("D:\\htmlMade\\javaprac\\monitorsystem\\src\\main\\resources\\EP2FLOW.model");
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
                        new FileReader("C:\\Users\\Administrator\\Desktop\\1.out_ (7).arff")));

        // set class attribute
        test.setClassIndex(test.numAttributes() - 1);

        // create copy
        Instances labeled = new Instances(test);
        // label instances
        for (int i = 0; i < test.numInstances(); i++) {
            double clsLabel = cls.classifyInstance(test.instance(i));
            labeled.instance(i).setClassValue(clsLabel);
        }
        // save labeled data
        BufferedWriter writer = new BufferedWriter(
                new FileWriter("C:\\Users\\Administrator\\Desktop\\1\\testep6.arff"));
        writer.write(labeled.toString());
        writer.newLine();
        writer.flush();
        writer.close();

        //        ModelClassifier cls = new ModelClassifier();
        //        cls.classifiy(test, "C:\\Users\\Administrator\\Desktop\\monitorsystem\\src\\main\\resources\\EP2FLOW.model");
    }
}
