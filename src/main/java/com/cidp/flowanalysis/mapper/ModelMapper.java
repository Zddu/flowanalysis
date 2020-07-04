package com.cidp.flowanalysis.mapper;

import com.cidp.flowanalysis.model.Algorithm;
import org.apache.ibatis.annotations.Param;

import java.util.List;

public interface ModelMapper {
    void insertModeId(@Param("id") Integer id, @Param("mid") Integer mid);

    List<Algorithm> getAllModels();
}
