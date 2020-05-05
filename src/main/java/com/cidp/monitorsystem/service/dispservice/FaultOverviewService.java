package com.cidp.monitorsystem.service.dispservice;


import com.cidp.monitorsystem.mapper.FaultOverviewMapper;
import com.cidp.monitorsystem.model.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * @date 2020/5/2 -- 11:14
 **/
@Service
public class FaultOverviewService {
    @Autowired
    private FaultOverviewMapper faultOverviewMapper;

    public FaultOverviewTop failuresNums(String time) {
        String start,end=null;
        FaultOverviewTop faultOverviewTop=new FaultOverviewTop();
        if ("".equals(time) || time == null){
            faultOverviewTop.setTop10IpFaults(faultOverviewMapper.selectIpFaultTop10());
            faultOverviewTop.setFaultNums(faultOverviewMapper.selectAllFaultNums());
        }else{
            String[] split = time.split(",");
            start=split[0].trim();
            end=split[1].trim()+" 59:59:59";
            faultOverviewTop.setTop10IpFaults(faultOverviewMapper.selectIpFaultTop10ByTime(start,end));
            faultOverviewTop.setFaultNums(faultOverviewMapper.selectAllFaultNumsByTime(start,end));
        }
        return faultOverviewTop;
    }






    public List<Equipment> getSelectList() {
        return faultOverviewMapper.selectAllEquipment();
    }

    public List<Pie> getPieData(String ip) {
        return faultOverviewMapper.selectSpecifiedDeviceFailuresByIp(ip);
    }
}
