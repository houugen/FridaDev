#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ============================
# Created By  : lzm
# Created Date: 2018-11-01
# ============================

import frida
import threading
import time
import sys
import argparse
import codecs
import subprocess
import os

finished = threading.Event()

APP_JS = './js/app.js'
UI_JS = './js/ui.js'
HOOK_IOS_JS = './js/ios_hook.js'
HOOK_ANDROID_JS = './js/android_hook.js'
TRACE_IOS_JS = './js/ios_trace.js'
TRACE_ANDROID_JS = './js/android_trace.js'
ENUMERATE_IOS_JS = './js/ios_enum.js'
ENUMERATE_ANDROID_JS = './js/android_enum.js'

global session

def outWrite(text):
    sys.stdout.write(text + '\n')

# 获取USB设备
def get_usb_device():
    dManager = frida.get_device_manager()
    changed = threading.Event()
    def on_changed():
        changed.set()
    dManager.on('changed', on_changed)

    device = None
    while device is None:
        devices = [dev for dev in dManager.enumerate_devices() if dev.type == 'usb']
        if len(devices) == 0:
            print('Waiting for usb device...')
            changed.wait()
            time.sleep(2)
        else:
            device = devices[0]

    dManager.off('changed', on_changed)
    return device

# 枚举运行进程信息
def listRunningProcess(device):
    processes = device.enumerate_processes()
    processes.sort(key = lambda item : item.pid)
    outWrite('%-6s\t%s' % ('pid', 'name'))
    for process in processes:
        outWrite('%-6s\t%s' % (str(process.pid), process.name))

# 带颜色打印输出
def colorPrint(color, s):
    return "%s[31;%dm%s%s[0m" % (chr(27), color, s, chr(27))

# 处理JS中不同的信息
def deal_message(payload):
    # 基本信息输出
    if 'mes' in payload:
        print(payload['mes'])

    # 安装app信息
    if 'app' in payload:
        app = payload['app']
        lines = app.split('\n')
        outWrite('%-40s\t%-60s\t%-80s' % ('app name', 'bundle identify', 'documents path'))
        for line in lines:
            if len(line):
                arr = line.split('\t')
                if len(arr) == 3:
                    outWrite('%-40s\t%-60s\t%-80s' % (arr[0], arr[1], arr[2]))

    # 处理UI界面输出
    if 'ui' in payload:
        print(colorPrint(31, payload['ui']))

    # 处理完成事件
    if 'finished' in payload:
        finished.set()

#从JS接受信息
def on_message(message, data):
    if 'payload' in message:
        payload = message['payload']
        if isinstance(payload, dict):
            deal_message(payload)
        else:
            print(payload)

def loadJsFile(session, filename):
    source = ''
    with codecs.open(filename, 'r', 'utf-8') as f:
        source = source + f.read()
    script = session.create_script(source)
    script.on('message', on_message)
    script.load()
    return script

# 枚举安装应用程序信息
def enumerateAppInfo(device):
    global session
    try:
        session = device.attach('SpringBoard')
        script = loadJsFile(session, APP_JS)
        script.post({'cmd': 'installed'})
        finished.wait()
    except:
        apps = device.enumerate_applications()
        apps.sort(key=lambda item: item.pid)
        outWrite('%-6s\t%-40s\t%s' % ('pid', 'name', 'identifier'))
        for app in apps:
            outWrite('%-6s\t%-40s\t%s' % (str(app.pid), app.name, app.identifier))

# 判断是否为android
def isAndroid(device):
    for app in device.enumerate_processes():
        if app.name == "adbd":
            return True
    return False

# 显示界面UI
def showUI(device, appName):
    global session
    if isAndroid(device):
        print("[!] This feature is limited to ios.")
        sys.exit(0)
    session = device.attach(appName)
    script = loadJsFile(session, UI_JS)
    while True:
        line = sys.stdin.readline()
        if not line:
            break
        script.post(line[:-1])

# 获取设备进程pid
def getProcessPid(device, appName):
    for p in device.enumerate_processes():
        if p.name == appName:
            return p.pid
    return -1

# 动态hook
def dynHookProcess(device, appName):
    global session
    pid = getProcessPid(device, appName)
    if pid != -1:
        print("[+] killing {0}".format(pid))
        device.kill(pid)
        time.sleep(0.3)
    while True:
        pid = getProcessPid(device, appName)
        if pid == -1:
            print("[-] {0} is not found...".format(appName))
            time.sleep(2)
        else:
            break
    print("[+] Injecting script to {0}({1})".format(appName, pid))
    session = device.attach(pid)
    script = loadJsFile(session, HOOK_ANDROID_JS) if isAndroid(device) else loadJsFile(session, HOOK_IOS_JS)
    sys.stdin.read()

def tracer(device, identifier):
    try:
        if isAndroid(device):
            os.system('frida -U -f {} -l {} --no-pause'.format(identifier, TRACE_ANDROID_JS))
        else:
            os.system('frida -U -f {} -l {} --no-pause'.format(identifier, TRACE_IOS_JS))
    except Exception as e:
        pass

def enumerate(device, identifier):
    global session
    pid = device.spawn([identifier])
    session = device.attach(pid)
    device.resume(pid)
    script = loadJsFile(session, ENUMERATE_ANDROID_JS) if isAndroid(device) else loadJsFile(session, ENUMERATE_IOS_JS)
    sys.stdin.read()

def main():
    parser = argparse.ArgumentParser(description='frida tools')
    parser.add_argument('-l', '--list', help='list running processes', action='store_true')
    parser.add_argument('-i', '--info', help='list installed app infomation', action='store_true')
    parser.add_argument('-u', '--ui', metavar='appName', help='show UI (only for ios)')
    parser.add_argument('-d', '--dynhook', metavar='appName', help='dynamic hook')
    parser.add_argument('-t', '--trace', metavar='identifier', help='ObjC/java and Module tracer')
    parser.add_argument('-e', '--enumerate', metavar='identifier', help='Collection of functions to enumerate classes and methods')
    args = parser.parse_args()

    device = get_usb_device()
    print('[*] Device info: ' + str(device) + '\n')

    if args.list:
        listRunningProcess(device)
    elif args.info:
        enumerateAppInfo(device)
    elif args.ui:
        showUI(device, args.ui)
    elif args.dynhook:
        dynHookProcess(device, args.dynhook)
    elif args.trace:
        tracer(device, args.trace)
    elif args.enumerate:
        enumerate(device, args.enumerate)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        if session:
            session.detach()
            sys.exit()
        else:
            pass
    finally:
        pass