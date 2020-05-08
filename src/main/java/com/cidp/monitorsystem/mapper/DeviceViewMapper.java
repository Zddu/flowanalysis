package com.cidp.monitorsystem.mapper;

import com.cidp.monitorsystem.model.Cpu;
import com.cidp.monitorsystem.model.InterFlow;
import com.cidp.monitorsystem.model.Memory;
import org.apache.ibatis.annotations.Param;


import java.util.List;

/**
 * @date 2020/5/8 -- 7:54
 **/
public interface DeviceViewMapper {


    List<Memory> selectMemoryByIp(@Param("ip")String ip);

    List<InterFlow> selectInterfaceByIp(@Param("ip") String ip);

    List<InterFlow> selectInterfaceflowByInter(@Param("ip") String ip,@Param("interDescr") String interDescr);

    List<Cpu> selectCupByIp(String ip);
}
