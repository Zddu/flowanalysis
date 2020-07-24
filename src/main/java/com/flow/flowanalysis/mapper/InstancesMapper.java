package com.flow.flowanalysis.mapper;

import com.flow.flowanalysis.model.Feature;
import com.flow.flowanalysis.model.Pie;
import org.apache.ibatis.annotations.Param;

import java.util.List;
import java.util.Map;

public interface InstancesMapper {

    void deleteAll();

    List<Pie> getResult();

    List<Map<String,String>> getAllData();

    void insertInstances(@Param("list") List<Feature> list);
}
