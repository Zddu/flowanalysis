package com.cidp.flowanalysis.mapper;

import com.cidp.flowanalysis.model.Pie;

import java.util.List;
import java.util.Map;

public interface InstancesMapper {

    void deleteAll();

    List<Pie> getResult();

    List<Map<String,String>> getAllData();
}
