#!/usr/bin/env python
#-*- coding:utf-8 -*-

"""
@author:ZCG
@file:ServiceOut3.py
@time:2019/02/26
"""

import pyshark
import struct
import logging
import logging.handlers
from logging.handlers import TimedRotatingFileHandler
import sys
import getopt
import sys
import time
import logging
from watchdog.observers import Observer
from watchdog.events import LoggingEventHandler
from watchdog.events import FileSystemEventHandler
from os.path import getsize

#dumpcap的命令
#dumpcap -i "以太网 2"  -b interval:15 -b files:10 -w C:\\dumpcap\\serviceout.pcap -f "udp and ip dst net 172.31.6.0/24 and !ip src net 172.31.6.0/24 and udp[12]==0x05"




def parsePacket(pkt, logger):
    try:
        t = pkt.data.data.binary_value
        logger.debug("包长 %d" % len(t))
    except AttributeError:
        logger.debug("error packet")

    # 解析报头信息
    head = t[0:68]
    try:
        nMsgId, EventType, RCCode, smcID, sn = struct.unpack("ii20s20s20s", head)
    except struct.error:
        logger.debug("error packet head")

    try:
        RCCode = RCCode.strip(bytes('\x00', 'GBK')).decode('GBK')
        smcID = smcID.strip(bytes('\x00', 'GBK')).decode('GBK')
        sn = sn.strip(bytes('\x00', 'GBK')).decode('GBK')
    except UnicodeDecodeError:
        logger.debug("packet head decode error")

    # 解析节目信息
    tail = t[68:196]
    logger.debug("尾部长 %d" % len(tail))
    try:
        ucEndTime, ucTime, service_id, ts_id, frequency, \
        channel_name, program_name, authority, \
        signal_strength, signal_quality, sdv, unContinue \
            = struct.unpack("24s24sHHi24s28sbiibL", tail)
    except struct.error:
        logger.debug("error packet tail")

    try:
        ucEndTime = ucEndTime.strip(bytes('\x00', 'GBK')).decode('GBK')
        ucTime = ucTime.strip(bytes('\x00', 'GBK')).decode('GBK')
        channel_name = channel_name.strip(bytes('\x00', 'GBK')).decode('GBK')
        program_name = program_name.strip(bytes('\x00', 'GBK')).decode('GBK')
    except UnicodeDecodeError:
        logger.debug("packet tail decode error")

    # 写入日志
    logger.info(
        "nMsgId=%s|EventType=%d|RCCode=%s|smcID=%s|sn=%s|ucEndTime=%s|ucTime=%s|service_id=%d|ts_id=%d|frequency=%d|channel_name=%s|program_name=%s|authority=%d|signal_strength=%d|signal_quality=%d|sdv=%d|unContinue=%ld"
        % (nMsgId, EventType, RCCode, smcID, sn,
           ucEndTime, ucTime, service_id, ts_id, frequency,
           channel_name, program_name, authority, signal_strength, signal_quality,
           sdv, unContinue)
    )


# 创建日志
def logBuilder(logdir):
    logger = logging.getLogger('TR069')  # 获取名为TR069的logger
    logger.setLevel(logging.INFO)

    # 循环文件日志
    LOG_FILE = logdir + 'pcap.log'
    handler = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=1024 * 1024, backupCount=10)
    fmt = '%(asctime)s - %(filename)s:%(lineno)s - %(name)s - %(message)s'
    formatter = logging.Formatter(fmt)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # 循环时间日志
    formatter = logging.Formatter(
        '%(name)-12s %(asctime)s level-%(levelname)-8s thread-%(thread)-8d %(message)s')  # 每行日志的前缀设置
    fileTimeHandler = TimedRotatingFileHandler(logdir + "ServiceOut", when='M', interval=1, backupCount=0)
    fileTimeHandler.suffix = "%Y%m%d-%H%M.log"  # 设置 切分后日志文件名的时间格式 默认 filename+"." + suffix 如果需要更改需要改logging 源码
    fileTimeHandler.setFormatter(formatter)
    # fileTimeHandler.setLevel(logging.DEBUG)
    logger.addHandler(fileTimeHandler)

    # 控制台日志
    console = logging.StreamHandler()
    # 控制台只输出warning以上的日志
    #console.setLevel(logging.WARN)
    formatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s')
    console.setFormatter(formatter)
    logger.addHandler(console)

    return logger

class MyHandler(FileSystemEventHandler):
    def __init__(self, log):
        self.log = log

    def on_modified(self, event):
        filesize = getsize(event.src_path)
        if filesize <= 2*1024:      #监控指定文件内容、权限等变化
            log.debug("log file %s just created! size is %d" % (event.src_path, filesize))
        else:
            log.debug("log file %s just finished! size is %d" % (event.src_path, filesize))
            try:
                cap = pyshark.FileCapture(input_file=event.src_path)
                #while(pkt = cap.next()):
                for pkt in cap:
                    try:
                        parsePacket(pkt, log)
                    except:
                         log.debug("error packet")
                cap.close()
            except:
                log.debug("finish parse this cap %s" % event.src_path)



if __name__ == "__main__":


    # 存储日志的位置
    file = "C:\\cap\\"
    log = logBuilder(file)
    path = "C:\\dumpcap"

    #负责将报文解析为日志的handler
    event_handler = MyHandler(log)

    #监控采集文件
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
