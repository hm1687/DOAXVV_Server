# -*- coding: utf-8 -*-
"""
clamp_offset.py — 智能时间钳制偏移计算 (19点白屏修复·自动化版)

原理:
  游戏客户端以 19:00(北京) 为"游戏日"分界, 19点后认为次日→触发跨日重做登录流程→白屏循环.
  本脚本: 真实时间 ≥19点 时, 把偏移设为"回到今天18:00"(19点前、且是过去不超前);
          <19点 时偏移=0(真实时间, 无需钳制).
  服务器启动前先运行本脚本写偏移→服务器读偏移→server_now=今天18:00(若钳制);
  frida 探针(probe_smart_clamp.js)读同一偏移→hook客户端时间API→客户端也看到今天18:00.
  ⇒ 服务器与客户端时间一致且都在19点前→客户端不触发跨日→正常进岛.

用法:
  python clamp_offset.py            # 计算+写入智能偏移 (服务器启动前调用)
  python clamp_offset.py --reset    # 复位偏移=0 (关闭服务器时调用)
"""
import os, sys, json, datetime

# __file__ 锚定 → 项目迁移到任意盘/路径都能跑 (不再写死盘符)
DIR = os.path.dirname(os.path.abspath(__file__))                    # DOAXVV_Server (本文件所在目录)
CFG = os.path.join(DIR, "local_server", "time_offset_config.json")        # 服务器+探针共用的偏移(输出)
CLAMP_CFG = os.path.join(DIR, "clamp_config.json")          # 钳制配置(可自定义)

# 默认值(配置文件缺失/出错时用)
DEF_BOUNDARY = 19   # 真实时间>=此点(整点)就触发钳制; -1=始终钳制
DEF_CLAMP_H = 18    # 钳制到今天几点
DEF_CLAMP_M = 0     # 钳制到几分
DEF_CLAMP_S = 0     # 钳制到几秒
DEF_CLAMP_END_H = -1  # 跨午夜窗口结束(次日几点停止钳制); -1=不跨午夜(旧行为)

def _parse_target_dt(s):
    """解析 target 字符串, 支持两种等价写法:
       - 紧凑14位纯数字: '20260915153345'  (= 2026-09-15 15:33:45)
       - 标准带分隔:     '2026-09-15 15:33:45'
       纯数字且恰好14位按紧凑解析; 其余按标准解析。解析失败抛 ValueError。"""
    s = s.strip()
    if len(s) == 14 and s.isdigit():
        return datetime.datetime.strptime(s, "%Y%m%d%H%M%S")
    return datetime.datetime.strptime(s, "%Y-%m-%d %H:%M:%S")

def load_clamp_cfg():
    """读 clamp_config.json; 返回 (boundary_hour, target_datetime, 模式描述). 配置无效用默认值。"""
    now = datetime.datetime.now()
    try:
        with open(CLAMP_CFG, "r", encoding="utf-8-sig") as f:
            c = json.load(f)
        b = int(c.get("boundary_hour", DEF_BOUNDARY))
        if not (b == -1 or 0 <= b <= 23):
            raise ValueError("boundary_hour 需 -1 或 0-23")
        target_str = str(c.get("target", "")).strip()
        if target_str:
            # 固定目标模式: 钳到指定年月日时分秒 (支持紧凑14位 / 标准带分隔 两种写法)
            try:
                target = _parse_target_dt(target_str)
            except ValueError:
                raise ValueError("target 格式错误(支持 '20260915153345' 或 '2026-09-15 15:33:45'): %s" % target_str)
            return b, target, "固定时刻 %s" % target.strftime("%Y-%m-%d %H:%M:%S")
        else:
            # 今天模式: 钳到今天 clamp_h:m:s (每日自动推进)
            ch = int(c.get("clamp_hour", DEF_CLAMP_H))
            cm = int(c.get("clamp_minute", DEF_CLAMP_M))
            cs = int(c.get("clamp_second", DEF_CLAMP_S))
            if not (0 <= ch <= 23 and 0 <= cm <= 59 and 0 <= cs <= 59):
                raise ValueError("clamp_hour/minute/second 范围错误(0-23/0-59/0-59)")
            # 跨午夜窗口: clamp_end_hour >= 0 时启用
            # 当天 ch:00 → 次日 clamp_end_hour:00 之间, 都钳到当天 ch:00
            ce = int(c.get("clamp_end_hour", -1))
            if ce != -1 and not (0 <= ce <= 23):
                raise ValueError("clamp_end_hour 需 -1 或 0-23")
            if ce >= 0 and now.hour < ce:
                # 午夜后、窗口结束前: target = 昨天 ch:00 (跨午夜, 保持同一目标日)
                target = (now - datetime.timedelta(days=1)).replace(hour=ch, minute=cm, second=cs, microsecond=0)
                return b, target, "昨天 %02d:%02d:%02d (跨午夜→次日%02d点)" % (ch, cm, cs, ce)
            else:
                # 午夜前(含窗口起始), 或免钳时段(ce~ch之间, target在未来→smart_offset自动跳过)
                target = now.replace(hour=ch, minute=cm, second=cs, microsecond=0)
                if ce >= 0:
                    return b, target, "今天 %02d:%02d:%02d (窗口%02d→次日%02d)" % (ch, cm, cs, ch, ce)
                return b, target, "今天 %02d:%02d:%02d" % (ch, cm, cs)
    except Exception as e:
        print("[钳制] 读配置失败(%s), 用默认 boundary=%d 今天%02d:%02d:%02d" % (e, DEF_BOUNDARY, DEF_CLAMP_H, DEF_CLAMP_M, DEF_CLAMP_S))
        target = now.replace(hour=DEF_CLAMP_H, minute=DEF_CLAMP_M, second=DEF_CLAMP_S, microsecond=0)
        return DEF_BOUNDARY, target, "今天 %02d:%02d:%02d(默认)" % (DEF_CLAMP_H, DEF_CLAMP_M, DEF_CLAMP_S)

def read_cfg():
    try:
        with open(CFG, "r", encoding="utf-8-sig") as f:
            return json.load(f)
    except Exception:
        return {"note": "智能时间钳制: 到点后自动回到今天指定时间, 避免跨日白屏. 修改后需重启服务器和探针."}

def write_cfg(days, hours, minutes, seconds):
    cfg = read_cfg()
    cfg["offset_days"] = int(days)
    cfg["offset_hours"] = int(hours)
    cfg["offset_minutes"] = int(minutes)
    cfg["offset_seconds"] = int(seconds)
    if "note" not in cfg:
        cfg["note"] = "智能时间钳制: 当天12点到次日7点都钳到当天12:00, 避免跨日白屏. 修改后需重启服务器和探针."
    with open(CFG, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)

def decompose_signed(total_sec):
    """把总秒数(可负)拆成 days/hours/minutes/seconds, 各自带符号, 和=total_sec"""
    sign = -1 if total_sec < 0 else 1
    a = abs(total_sec)
    days = sign * (a // 86400); a %= 86400
    hours = sign * (a // 3600); a %= 3600
    minutes = sign * (a // 60); a %= 60
    seconds = sign * a
    return days, hours, minutes, seconds

def reset():
    write_cfg(0, 0, 0, 0)
    print("[钳制] 已复位: offset=0 (恢复真实时间)")

def smart_offset():
    boundary_h, target, desc = load_clamp_cfg()
    now = datetime.datetime.now()
    triggered = (boundary_h == -1) or (now.hour >= boundary_h)
    if triggered:
        delta = target - now
        total_sec = int(delta.total_seconds())
        if total_sec >= 0:
            # 目标在未来(免钳时段或不慎超前), 跳过
            write_cfg(0, 0, 0, 0)
            print("[钳制] 免钳时段(目标 %s 在未来), offset=0" % target.strftime('%H:%M:%S'))
            return
        d, h, m, s = decompose_signed(total_sec)
        write_cfg(d, h, m, s)
        bdesc = "始终钳制(boundary=-1)" if boundary_h == -1 else "真实 %s >= %d点" % (now.strftime('%H:%M'), boundary_h)
        print("[钳制] %s -> 钳制到 %s (%s)" % (bdesc, target.strftime('%Y-%m-%d %H:%M:%S'), desc))
        print("       offset = %dd %dh %dm %ds  (服务器+客户端共用)" % (d, h, m, s))
        print("       游戏将看到: %s" % (now + delta).strftime('%Y-%m-%d %H:%M:%S'))
    else:
        write_cfg(0, 0, 0, 0)
        print("[钳制] 真实 %s < %d点 -> 无需钳制, offset=0" % (now.strftime('%H:%M'), boundary_h))

if __name__ == "__main__":
    if "--reset" in sys.argv:
        reset()
    else:
        smart_offset()
