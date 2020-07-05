package com.cidp.flowanalysis.mapper;

import com.cidp.flowanalysis.model.Feature;
import com.cidp.flowanalysis.model.Pie;
import org.apache.ibatis.annotations.Param;

import java.util.List;
import java.util.Map;

public interface InstancesMapper {

    void deleteAll();

    List<Pie> getResult();

    List<Map<String,String>> getAllData();

    void insertInstances(@Param("features") List<Feature> features);
}
