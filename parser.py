#!/usr/bin/env python
#-*- coding:utf-8 -*-

"""
@author:ZCG
@file:parser.py
@time:2019/01/25
"""

import pyshark
import struct
import logging
import logging.handlers
from logging.handlers import TimedRotatingFileHandler

LOG_FILE = 'pcap.log'
handler = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes = 1024*1024, backupCount = 5)
fmt = '%(asctime)s - %(filename)s:%(lineno)s - %(name)s - %(message)s'
formatter = logging.Formatter(fmt)  # 实例化formatter
handler.setFormatter(formatter)  # 为handler添加formatter

LOG_FILE = 'c:\cap\serviceout'

#handler = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes = 1024*1024, backupCount = 5)
#fmt = '%(asctime)s - %(filename)s:%(lineno)s - %(name)s - %(message)s'
#formatter = logging.Formatter(fmt)  # 实例化formatter
#handler.setFormatter(formatter)  # 为handler添加formatter

logger = logging.getLogger('TR069')  # 获取名为TR069的logger



formatter = logging.Formatter('%(name)-12s %(asctime)s level-%(levelname)-8s thread-%(thread)-8d %(message)s')   # 每行日志的前缀设置
fileTimeHandler = TimedRotatingFileHandler("ServiceOut", "S", 1, 10)
fileTimeHandler.suffix = "%Y%m%d.log"  #设置 切分后日志文件名的时间格式 默认 filename+"." + suffix 如果需要更改需要改logging 源码
fileTimeHandler.setFormatter(formatter)
fileTimeHandler.setLevel(logging.DEBUG)
logger.addHandler(fileTimeHandler)

logger = logging.getLogger('TR069')  # 获取名为tst的logger
logger.addHandler(handler)  # 为logger添加handler
logger.setLevel(logging.DEBUG)

#定义一个StreamHandler，将INFO级别或更高的日志信息打印到标准错误，并将其添加到当前的日志处理对象#
console = logging.StreamHandler()
console.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s')
console.setFormatter(formatter)

logger.addHandler(console)



#定义事件类型
PowerOn=0x01			    #开机事件
StandBy = 0x02			 	#待机事件
Search=0x03			        #节目搜索事件
Freq=0x04					#单频点信号质量事件
ServiceIn = 0x15 			#广播节目进入事件
ServiceOut=0x05 			#广播节目退出事件
Banner=0x06 				#EPG信息条显示事件
VolumeBar=0x07		        #音量条显示事件
Menu=0x08					#本地菜单界面进出事件
Portal=0x09					#portal界面进出事件
SubLevel=0x0a				#portal界面子栏目进入事件
BroadcastData=0x0d 		    #数据广播进入事件
FloatAD=0x0e 				#如加广告事件
Error=0x0f 				    #机顶盒单向故障事件
Vod=0x10 				    #VOD播放事件
Shift=0x11					#时移节目播放事件
USB=0x12					#USB插拔事件
AppS=0x13			        #中间件应用事件
HeartBeat=0x14			    #心跳事件
Order = 0x17			    #喜爱键点击事件
Key = 0x18		            #广播频道功能键点击事件
HelpChannel = 0x19			#零频道进出事件
LinkJump = 0x1a			    #双向业务链接地址跳转事件（中间件抛送）
VodError = 0x1b			    #点播故障事件
ManualLinkJump = 0x1c	    #双向业务链接地址跳转事件（页面抛送）
NetException = 0x1d         #双向页面无法打开事件
USBPhone = 0x1e			    #USB无绳电话通信事件
MicPhone = 0x1f		        #可视通信事件
CloudComp = 0x20			#云计算Portal进出事件
MobileVideoPlay = 0x21	    #视频播放事件（预留）
CloudServInOut = 0x5f		#云业务进出事件（由云计算前端抛送）


#cap = pyshark.FileCapture("C:\cap.pcap", display_filter = 'UDP')
#cap = pyshark.FileCapture(input_file="C:\cap.pcap",display_filter = '!dcerpc and udp and !stp and !kink and !pathport')
#cap = pyshark.FileCapture(input_file="C:\cap.pcap")
#过滤出所有开机事件PowerOn udp[12]=0x01
#udp包头长度8个字节，包体第5个字节代表事件类型，偏移量从0开始计算，因此是udp[12]
 #cap = pyshark.LiveCapture(interface="WLAN",capture_filter="udp")
pyshark.LiveRingCapture

i = 0

f = open('C:\\cap\\cap.txt','w',encoding='UTF-8', newline='')

for pkt in cap:
    #if(pkt.data.data)
    logger.debug("id %d"%i)
    i = i+1

    try:
        t = pkt.data.data.binary_value
        logger.debug("包长 %d" % len(t))
    except AttributeError:
        logger.debug("AttributeError")
    head = t[0:68]
    nMsgId,EventType,RCCode,smcID,sn = struct.unpack("ii20s20s20s",head)
    RCCode = RCCode.strip(bytes('\x00','utf-8')).decode('utf-8')
    smcID = smcID.strip(bytes('\x00','utf-8')).decode('utf-8')
    sn = sn.strip(bytes('\x00','utf-8')).decode('utf-8')

    logger.info(str(nMsgId) + "|" \
                + str(EventType) + "|" \
                + RCCode + "|" \
                + smcID + "|" \
                + sn)

    if(EventType == HeartBeat):
        logger.debug("HeartBeat")
        EventName = "HeartBeat"
    elif(EventType == PowerOn):
        logger.debug("PowerOn")
        EventName = "PowerOn"
    elif(EventType == StandBy):
        logger.debug("StandBy")
        EventName = "StandBy"
    elif(EventType == Search):
        logger.debug("Search")
        EventName = "Search"
    elif(EventType == Freq):
        logger.debug("Freq")
        EventName = "Freq"
    elif(EventType == ServiceIn):
        logger.debug("ServiceIn")
        EventName = "ServiceIn"

        #进入时间
        tail = t[69:196]
        logger.debug("尾部长 %d"%len(tail))
        #节目信息
        Time,service_id,ts_id,frequency,\
        channel_name,program_name,authority,\
        signal_strength,signal_quality,sdv \
            =struct.unpack("24sHHi24s28sbiib",tail)

        Time = Time.strip(bytes('\x00', 'utf-8')).decode('utf-8')
        #ervice_id = service_id.strip(bytes('\x00', 'utf-8')).decode('utf-8')
        #ts_id = ts_id.strip(bytes('\x00', 'utf-8')).decode('utf-8')
        #frequency = frequency.strip(bytes('\x00', 'utf-8')).decode('utf-8')
        channel_name = channel_name.decode('GBK')
        program_name = program_name.decode('GBK')
        #authority = authority.strip(bytes('\x00', 'utf-8')).decode('utf-8')
        #signal_strength = signal_strength.strip(bytes('\x00', 'utf-8')).decode('utf-8')
        #signal_quality = signal_quality.strip(bytes('\x00', 'utf-8')).decode('utf-8')
        #sdv = sdv.strip(bytes('\x00', 'utf-8')).decode('utf-8')

        logger.info("Time=" + str(Time) + "|",
                    "service_id=" + str(service_id) + "|",
                    "ts_id=" + str(ts_id) + "|",
                    "frequency=" + str(frequency) + "|",
                    "channel_name=" + str(channel_name) +"|",
                    "program_name=" + str(program_name) + "|",
                    "authority=" + str(authority) + "|",
                    "signal_strength=" + str(signal_strength) + "|",
                    "signal_quality=" + str(signal_quality) + "|",
                    "sdv=" + str(sdv) + "|"
                    )


    elif(EventType == ServiceOut):
        logger.debug("ServiceOut")
        EventName = "ServiceOut"

        tail = t[68:196]
        logger.debug("尾部长 %d" % len(tail))
        # 节目信息
        ucEndTime, ucTime, service_id, ts_id, frequency, \
        channel_name, program_name, authority, \
        signal_strength, signal_quality, sdv, unContinue \
            = struct.unpack("24s24sHHi24s28sbiibL", tail)

        try:
            ucEndTime = ucEndTime.decode('GBK').strip()
            ucTime = ucTime.decode('GBK').strip()
            # ervice_id = service_id.strip(bytes('\x00', 'utf-8')).decode('utf-8')
            # ts_id = ts_id.strip(bytes('\x00', 'utf-8')).decode('utf-8')
            # frequency = frequency.strip(bytes('\x00', 'utf-8')).decode('utf-8')
            channel_name = channel_name.decode('GBK').strip()
            program_name = program_name.decode('GBK').strip()
            # authority = authority.strip(bytes('\x00', 'utf-8')).decode('utf-8')
            # signal_strength = signal_strength.strip(bytes('\x00', 'utf-8')).decode('utf-8')
            # signal_quality = signal_quality.strip(bytes('\x00', 'utf-8')).decode('utf-8')
            # sdv = sdv.strip(bytes('\x00', 'utf-8')).decode('utf-8')

            # logger.info("ucEndTime=" + str(ucEndTime) + "|",
            #             "ucTime=" + str(ucTime) + "|",
            #             "service_id=" + str(service_id) + "|",
            #             "ts_id=" + str(ts_id) + "|",
            #             "frequency=" + str(frequency) + "|",
            #             "channel_name=" + str(channel_name) + "|",
            #             "program_name=" + str(program_name) + "|",
            #             "authority=" + str(authority) + "|",
            #             "signal_strength=" + str(signal_strength) + "|",
            #             "signal_quality=" + str(signal_quality) + "|",
            #             "sdv=" + str(sdv) + "|",
            #             "unContinue=" + str(unContinue) + "|"
            #             )
        except UnicodeDecodeError:
            logger.info(UnicodeDecodeError)
        logger.info("ucEndTime=%s|ucTime=%s|service_id=%d|ts_id=%d|frequency=%d|channel_name=%s|program_name=%s|authority=%d|signal_strength=%d|signal_quality=%d|sdv=%d|unContinue=%ld"%(ucEndTime,ucTime,service_id,ts_id,frequency,channel_name,program_name,authority,signal_strength,signal_quality,sdv,unContinue)
                    )

        #print("ucEndTime=%s|ucTime=%s|ts_id=%d" % (ucEndTime,ucTime,service_id))


    elif(EventType == Banner):
        logger.debug("Banner")
        EventName = "Banner"
    elif(EventType == VolumeBar):
        logger.debug("VolumeBar")
        EventName = "VolumeBar"
    elif(EventType == Menu):
        logger.debug("Menu")
        EventName = "Menu"
    elif(EventType == Portal):
        logger.debug("Portal")
        EventName = "Portal"
    elif(EventType == SubLevel):
        logger.debug("SubLevel")
        EventName = "SubLevel"
    elif(EventType == BroadcastData):
        logger.debug("BroadcastData")
        EventName = "BroadcastData"
    elif(EventType == FloatAD):
        logger.debug("FloatAD")
        EventName = "FloatAD"
    elif(EventType == Error):
        logger.debug("Error")
        EventName = "Error"
    elif(EventType == Vod):
        logger.debug("Vod")
        EventName = "Vod"
    elif(EventType == Shift):
        logger.debug("Shift")
        EventName = "Shift"
    elif(EventType == USB):
        logger.debug("USB")
        EventName = "USB"
    elif(EventType == AppS):
        logger.debug("AppS")
        EventName = "AppS"
    elif(EventType == Order):
        logger.debug("Order")
        EventName = "Order"
    elif(EventType == Key):
        logger.debug("Key")
        EventName = "Key"
    elif(EventType == HelpChannel):
        logger.debug("HelpChannel")
        EventName = "HelpChannel"
    elif(EventType == LinkJump):
        logger.debug("LinkJump")
        EventName = "LinkJump"
    elif(EventType == VodError):
        logger.debug("VodError")
        EventName = "VodError"
    elif(EventType == ManualLinkJump):
        logger.debug("ManualLinkJump")
        EventName = "ManualLinkJump"
    elif(EventType == NetException):
        logger.debug("NetException")
        EventName = "NetException"
    elif(EventType == USBPhone):
        logger.debug("USBPhone")
        EventName = "USBPhone"
    elif(EventType == MicPhone):
        logger.debug("MicPhone")
        EventName = "MicPhone"
    elif(EventType == CloudComp):
        logger.debug("CloudComp")
        EventName = "CloudComp"
    elif(EventType == MobileVideoPlay):
        logger.debug("MobileVideoPlay")
        EventName = "MobileVideoPlay"
    elif(EventType == CloudServInOut):
        logger.debug("CloudServInOut")
        EventName = "CloudServInOut"

    #f.writelines(["nMsgId=%s" + nMsgId + "|",
    #              "EventType=" + EventName + "|",
    #              "RCCode=" + str(RCCode) + "|",
    #             "smcID=" + str(smcID) + "|",
    #              "sn=" + str(sn) + "|\r\n"])
    f.writelines(["nMsgId=" + str(nMsgId) + "|",
                  "EventType=" + EventName + "|",
                  "RCCode=" + RCCode + "|",
                  "smcID=" + smcID + "|",
                  "sn=" + sn + "|\r\n"])

cap.close()
f.close()
if __name__ == "__main__":
    pass