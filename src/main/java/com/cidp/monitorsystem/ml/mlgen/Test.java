package com.cidp.monitorsystem.ml.mlgen;

import com.cidp.monitorsystem.ml.convert.PcapReader;
import weka.classifiers.functions.MultilayerPerceptron;
import weka.classifiers.trees.J48;
import weka.core.Debug;
import weka.core.Instances;
import weka.core.converters.CSVLoader;
import weka.core.converters.ConverterUtils;
import weka.filters.Filter;
import weka.filters.unsupervised.attribute.Normalize;

import java.io.File;

public class Test {
    public static final String DATASETPATH = "C:\\Users\\Administrator\\Desktop\\1\\EP2FLOW.arff";
    public static final String MODElPATH = "C:\\Users\\Administrator\\Desktop\\monitorsystem\\src\\main\\resources\\EP2FLOW.model";

    public static void main(String[] args) throws Exception {
        new Test().J48Classify();
//        PcapReader.readFile(DATASETPATH,"C:\\Users\\Administrator\\Desktop\\1",120000000L,5000000L);
    }

    public void J48Classify() throws Exception {
        ModelGenerator mg = new ModelGenerator();
        Instances dataset = mg.loadDataset(DATASETPATH);
        Filter filter = new Normalize();
//        CSVLoader loader = new CSVLoader();
//        loader.setSource(new File(DATASETPATH));
//        String [] options = new String[1];
//        options[0]="-H";
//        loader.setOptions(options);
//        Instances dataset = loader.getDataSet();
//        if (dataset.classIndex() == -1) {
//            dataset.setClassIndex(dataset.numAttributes() - 1);
//        }
        // divide dataset to train dataset 80% and test dataset 20%
        int trainSize = (int) Math.round(dataset.numInstances() * 0.8);
        int testSize = dataset.numInstances() - trainSize;

        dataset.randomize(new Debug.Random(1));// if you comment this line the accuracy of the model will be droped from 96.6% to 80%

        //Normalize dataset
        filter.setInputFormat(dataset);

//        Instances datasetnor = Filter.useFilter(dataset, filter);
        Instances datasetnor = Sampling.SMOTESample(dataset);

        Instances traindataset = new Instances(datasetnor, 0, trainSize);
        Instances testdataset = new Instances(datasetnor, trainSize, testSize);

        // build classifier with train dataset
//        MultilayerPerceptron ann = (MultilayerPerceptron) mg.buildClassifier(traindataset);
        J48 ann = new J48();
        ann.buildClassifier(traindataset);
        // Evaluate classifier with test dataset
        String evalsummary = mg.evaluateModel(ann, traindataset, testdataset);
        System.out.println("Evaluation: " + evalsummary);

        //Save model
        mg.saveModel(ann, MODElPATH);

        //classifiy a single instance
//        ModelClassifier cls = new ModelClassifier();
//        Instances test = mg.loadDataset("C:\\Users\\Administrator\\Desktop\\testnet.arff");
//        cls.classifiy(Filter.useFilter(testdataset, filter), MODElPATH);
    }
    public void Sampling(){
        ModelGenerator mg = new ModelGenerator();
        Instances dataset = mg.loadDataset(DATASETPATH);
        Instances sample = Sampling.BoostrapSample(dataset);
        System.out.println(sample.toString());
    }
    public void SMOTE(){
        ModelGenerator mg = new ModelGenerator();
        Instances dataset = mg.loadDataset(DATASETPATH);
        Instances sample = Sampling.SMOTESample(dataset);
//        Instances sample1 = Sampling.BoostrapSample(sample);
        System.out.println(sample);
    }

}
