/*
 * probe_smart_clamp.js — 智能时间钳制探针 (19点白屏修复, 2026-09-25 恢复)
 * 由 clamp_offset 逻辑算偏移(真实>=19点则回到今天18:00), 本探针读同一配置并 hook 客户端时间API
 *   ⇒ 客户端看到的 time = 真实 + 偏移 = 今天18:00(若钳制), 始终在19点前 → 不触发跨日 → 进岛
 * 必须与服务器 time_offset_config.json 配套(服务器 server_now 也加同一偏移)
 */
'use strict';

var TIME_OFFSET_FILE = "__TIME_OFFSET_FILE__";
var LOG_INFO = true;

var cachedOffsetMs = 0;
var lastReadTime = 0;

function getOffsetMs() {
    var now = Date.now();
    if (now - lastReadTime >= 1000) {
        lastReadTime = now;
        try {
            var f = new File(TIME_OFFSET_FILE, 'r');
            var bytes = f.readBytes();
            f.close();
            var content = bytes ? String.fromCharCode.apply(null, new Uint8Array(bytes)) : '';
            var cfg = JSON.parse(content);
            var d = parseInt(cfg.offset_days) || 0;
            var h = parseInt(cfg.offset_hours) || 0;
            var m = parseInt(cfg.offset_minutes) || 0;
            var s = parseInt(cfg.offset_seconds) || 0;
            var total_h = d * 24 + h + m / 60.0 + s / 3600.0;
            cachedOffsetMs = total_h * 3600 * 1000;
        } catch (e) { cachedOffsetMs = 0; }
    }
    return cachedOffsetMs;
}
function curOffsetH() { return Math.round(cachedOffsetMs / 3600 / 1000 * 100) / 100; }
function log(m) { console.log('[CLAMP@' + (Date.now() % 100000) + 'ms] ' + m); }

getOffsetMs();
log('智能钳制加载: 偏移=' + curOffsetH() + 'h (' + cachedOffsetMs + 'ms)');

function dateToFileTime(d) { return (d.getTime() + 11644473600000) * 10000; }
function dateToSystemTime(d) {
    return [d.getFullYear(), d.getMonth() + 1, d.getDay(), d.getDate(),
            d.getHours(), d.getMinutes(), d.getSeconds(), d.getMilliseconds()];
}

function hookFileTime() {
    var m = Process.findModuleByName('KERNELBASE.dll') || Process.findModuleByName('kernelbase.dll');
    if (!m) return;
    ['GetSystemTimeAsFileTime', 'GetSystemTimePreciseAsFileTime'].forEach(function (name) {
        try {
            var ex = m.enumerateExports().filter(function (e) { return e.name === name; })[0];
            if (!ex) return;
            Interceptor.attach(ex.address, {
                onEnter: function (args) { this.ft = args[0]; },
                onLeave: function () {
                    try {
                        var off = getOffsetMs();
                        if (off === 0) return;
                        var ft = this.ft.readU32() + this.ft.add(4).readU32() * 4294967296;
                        var orig = new Date(ft / 10000 - 11644473600000);
                        var nd = new Date(orig.getTime() + off);
                        var nft = dateToFileTime(nd);
                        this.ft.writeU32(nft % 4294967296);
                        this.ft.add(4).writeU32(Math.floor(nft / 4294967296));
                    } catch (e) {}
                }
            });
            log('hook ' + name);
        } catch (e) {}
    });
}

function hookSystemTime() {
    var m = Process.findModuleByName('KERNELBASE.dll') || Process.findModuleByName('kernelbase.dll');
    if (!m) return;
    ['GetLocalTime', 'GetSystemTime'].forEach(function (name) {
        try {
            var ex = m.enumerateExports().filter(function (e) { return e.name === name; })[0];
            if (!ex) return;
            Interceptor.attach(ex.address, {
                onEnter: function (args) { this.st = args[0]; },
                onLeave: function () {
                    try {
                        var off = getOffsetMs();
                        if (off === 0) return;
                        var arr = [];
                        for (var i = 0; i < 8; i++) arr.push(this.st.add(i * 2).readU16());
                        var d = new Date(arr[0], arr[1] - 1, arr[3], arr[4], arr[5], arr[6], arr[7]);
                        var nd = new Date(d.getTime() + off);
                        var out = dateToSystemTime(nd);
                        for (var j = 0; j < 8; j++) this.st.add(j * 2).writeU16(out[j]);
                    } catch (e) {}
                }
            });
            log('hook ' + name);
        } catch (e) {}
    });
}

function hookCrtTime() {
    ['time', '_time64'].forEach(function (name) {
        ['ucrtbase.dll', 'msvcrt.dll', 'api-ms-win-crt-time-l1-1-0.dll'].forEach(function (mod) {
            try {
                var m = Process.findModuleByName(mod);
                if (!m) return;
                var ex = m.enumerateExports().filter(function (e) { return e.name === name; })[0];
                if (!ex) return;
                Interceptor.attach(ex.address, {
                    onLeave: function (ret) {
                        var off = getOffsetMs();
                        var sec = ret.toInt32() & 0xFFFFFFFF;
                        if (off !== 0 && sec > 0x10000000) {
                            var nd = Math.floor((sec + off / 1000));
                            ret.replace(ptr(nd));
                        }
                    }
                });
                log('hook ' + mod + '!' + name);
            } catch (e) {}
        });
    });
}

hookFileTime();
hookSystemTime();
hookCrtTime();

log('智能钳制完成: 偏移=' + curOffsetH() + 'h. hosts劫持由系统hosts(hosts_switch.ps1)处理.');
