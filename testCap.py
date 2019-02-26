#!/usr/bin/env python
#-*- coding:utf-8 -*-

"""
@author:ZCG
@file:testCap.py
@time:2019/02/25
"""
import pyshark
import struct
import logging
import logging.handlers
from logging.handlers import TimedRotatingFileHandler


def parsePacket(pkt,logger):
    try:
        t = pkt.data.data.binary_value
        logger.debug("包长 %d" % len(t))
    except AttributeError:
        logger.debug("AttributeError")
    head = t[0:68]
    try:
        nMsgId, EventType, RCCode, smcID, sn = struct.unpack("ii20s20s20s", head)
    except struct.error:
        logger.error(struct.error)
    try:
        RCCode = RCCode.strip(bytes('\x00', 'GBK')).decode('GBK')
        smcID = smcID.strip(bytes('\x00', 'GBK')).decode('GBK')
        sn = sn.strip(bytes('\x00', 'GBK')).decode('GBK')
    except UnicodeDecodeError:
        logger.error("id %d packet has decode error" % i)

    tail = t[68:196]
    logger.debug("尾部长 %d" % len(tail))
    # 节目信息
    ucEndTime, ucTime, service_id, ts_id, frequency, \
    channel_name, program_name, authority, \
    signal_strength, signal_quality, sdv, unContinue \
        = struct.unpack("24s24sHHi24s28sbiibL", tail)

    try:
        ucEndTime = ucEndTime.strip(bytes('\x00', 'GBK')).decode('GBK')
        ucTime = ucTime.strip(bytes('\x00', 'GBK')).decode('GBK')
        channel_name = channel_name.strip(bytes('\x00', 'GBK')).decode('GBK')
        program_name = program_name.strip(bytes('\x00', 'GBK')).decode('GBK')
    except UnicodeDecodeError:
        logger.error(UnicodeDecodeError)

    logger.info(
        "nMsgId=%s|EventType=%d|RCCode=%s|smcID=%s|sn=%s|ucEndTime=%s|ucTime=%s|service_id=%d|ts_id=%d|frequency=%d|channel_name=%s|program_name=%s|authority=%d|signal_strength=%d|signal_quality=%d|sdv=%d|unContinue=%ld"
        % (nMsgId, EventType, RCCode, smcID, sn,
           ucEndTime, ucTime, service_id, ts_id, frequency,
           channel_name, program_name, authority, signal_strength, signal_quality,
           sdv, unContinue)
        )


def logCreate(logdir):
    logger = logging.getLogger('TR069')  # 获取名为TR069的logger
    logger.setLevel(logging.DEBUG)

    # 循环文件日志
    LOG_FILE = logdir + 'pcap.log'
    handler = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=1024 * 1024, backupCount=10)
    fmt = '%(asctime)s - %(filename)s:%(lineno)s - %(name)s - %(message)s'
    formatter = logging.Formatter(fmt)  # 实例化formatter
    handler.setFormatter(formatter)  # 为handler添加formatter
    logger.addHandler(handler)  # 为logger添加handler

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
    # console.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s')
    console.setFormatter(formatter)
    logger.addHandler(console)

    return logger


if __name__ == "__main__":
    # 初始化日志信息
    file = "C:\\cap2\\"
    log = logCreate(file)
    max_packet_num = 1024

    cap = pyshark.FileCapture(input_file="C:\cap.pcap", display_filter='udp[12]==0x05')
    # while(True):
    #cap = pyshark.LiveCapture(interface='以太网 2',
    #                          bpf_filter='udp and ip dst net 172.31.6.0/24 and !ip src net 172.31.6.0/24 and udp[12]==0x05')
    i = 0
    #for pkt in cap.sniff(packet_count=max_packet_num):
    for pkt in cap:
        log.info("第%d个包", i)
        i = i + 1
        parsePacket(pkt,log)
    cap.close()