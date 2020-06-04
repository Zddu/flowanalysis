package com.cidp.monitorsystem.model;

import lombok.Data;

@Data
public class EvaReasult {
   private double correct;//正确
   private double incorrect;//错误
   private double kappa;//Kappa 0-1之间越接近1越好
   private double meanAbsoluteError;
   private double rootMeanSquaredError;
   private double rootRelativeSquaredError;
   private double totalNumberOfInstances;
   private double avgCost;
   private double pctCorrect;
   private double pctUnclassified;
   private double relativeAbsoluteError;
   private double rootMeanPriorSquaredError;
   private double errorRate;
   private double weightedRecall;

}
