package com.flow.flowanalysis.ml.mlgen;

import weka.core.Instances;
import weka.filters.Filter;
import weka.filters.supervised.instance.Resample;
import weka.filters.supervised.instance.SMOTE;

public class Sampling {
    /**
     * 有监督的简单随机采样
     * @param data
     * @return
     */
    public static Instances BoostrapSample(Instances data) {
        String[] options = {"-S","12","-Z","70","-B","1"};
        Resample convert = new Resample();
        try {
            convert.setOptions(options);
            convert.setInputFormat(data);
            data = Filter.useFilter(data, convert);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return data;
    }

    /**
     * SMOTE采样，处理多数类不均衡的数据集，使数据集平衡
     * @param data
     * @return
     */
    public static Instances SMOTESample(Instances data) {
        SMOTE convert = new SMOTE();
        int seed = (int) (Math.random() * 10);
        String[] options = {"-S", String.valueOf(seed), "-P", "90.0", "-K", "5"};
        Instances SmoteInstances = null;
        try {
            convert.setOptions(options);
            convert.setInputFormat(data);
            SmoteInstances = Filter.useFilter(data, convert);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return SmoteInstances;
    }
}
