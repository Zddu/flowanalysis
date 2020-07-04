package com.cidp.flowanalysis.ml.mlgen;

import weka.classifiers.meta.FilteredClassifier;
import weka.classifiers.trees.J48;
import weka.core.Debug;
import weka.core.Instances;
import weka.filters.Filter;
import weka.filters.unsupervised.attribute.Normalize;
import weka.filters.unsupervised.attribute.Remove;

public class Test {
    public static final String DATASETPATH = "C:\\Users\\Administrator\\Desktop\\1.arff";
    public static final String TESTDATASET = "C:\\Users\\Administrator\\Desktop\\2.arff";
    public static final String MODElPATH = "C:\\Users\\Administrator\\Desktop\\flowanalysis\\src\\main\\resources\\EP2FLOW.model";

    public static void main(String[] args) throws Exception {
        new Test().J48Classify();
//        PcapReader.readFile(DATASETPATH,"C:\\Users\\Administrator\\Desktop\\1",120000000L,5000000L);
    }

    public void J48Classify() throws Exception {
        ModelGenerator mg = new ModelGenerator();
        Instances dataset = mg.loadDataset(DATASETPATH);

        Instances test = mg.loadDataset(TESTDATASET);
        Instances data = Sampling.BoostrapSample(Sampling.SMOTESample(dataset));
        Instances testdata = Sampling.BoostrapSample(Sampling.SMOTESample(test));
        Remove rm = new Remove();
        int[] removes = {32,27,23,28,77,22,47,41,74,72,73,35,36,75,34,66,10,52,59,53,58,14,51,60,61,33};
        rm.setAttributeIndicesArray(removes);
        Filter filter = new Normalize();
        Filter filter2 = new Normalize();
        data.randomize(new Debug.Random(1));
        testdata.randomize(new Debug.Random(1));
        //Normalize dataset
        filter.setInputFormat(data);
        filter2.setInputFormat(testdata);
//        Instances data = Sampling.SMOTESample(datasetnor);
        Instances datasetnor = Filter.useFilter(data, filter);
        Instances datasetnor2 = Filter.useFilter(testdata, filter2);
//        int trainSize = (int) Math.round(data.numInstances() * 0.8);
//        int testSize = data.numInstances() - trainSize;
//        Instances traindataset = new Instances(datasetnor, 0, trainSize);
//        Instances testdataset = new Instances(datasetnor, trainSize, testSize);
//        for (int i = 0; i < datasetnor.numInstances(); i++) {
//            System.out.println(data.instance(i).toString(79));
//        }
        // build classifier with train dataset
        J48 ann = new J48();
        ann.setUnpruned(true);
        FilteredClassifier fc = new FilteredClassifier();
        fc.setFilter(rm);
        fc.setClassifier(ann);

//        Evaluation evaluation = new Evaluation(traindataset);
//        evaluation.crossValidateModel(ann,traindataset,10,new Random(1));
//        System.out.println(evaluation.toSummaryString());
        fc.buildClassifier(datasetnor);
        System.out.println(fc.graph());
        // Evaluate classifier with test dataset
//        String evalsummary = mg.evaluateModel(ann, traindataset, testdataset);
//        System.out.println("Evaluation: " + evalsummary);

        //Save model
//        mg.saveModel(ann, MODElPATH);

        //classifiy a single instance
//        ModelClassifier cls = new ModelClassifier();
//        Instances test = mg.loadDataset("C:\\Users\\Administrator\\Desktop\\testnet.arff");
//        cls.classifiy(Filter.useFilter(testdataset, filter), MODElPATH);

        double score =0;
        for (int i = 0; i < datasetnor2.numInstances(); i++) {
            if (fc.classifyInstance(datasetnor2.instance(i))==datasetnor2.instance(i).classValue()){
                score ++;
            }
        }
        System.out.println(score / datasetnor2.numInstances());
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
