import argparse
import shlex
import sys
import threading
import time

import frida


JS = r"""
const interesting = {
  0xe2: true,
  0xe3: true,
  0xe8: true,
  0xed: true,
  0xef: true,
  0xf1: true,
  0xf8: true,
  0xf9: true,
  0xfa: true,
};

let seq = 0;
const startedAt = Date.now();

// Most recently observed physical monitor handle. SDM re-acquires this when the
// PBP topology changes, so we always replay through the freshest one we have seen.
let lastHandle = null;
// A physical monitor handle we open ourselves via GetPhysicalMonitorsFromHMONITOR.
// Preferred for replay because SDM's observed SetVCPFeature calls pass handle=0x0.
let ownHandle = null;
let setVcpFn = null;
let getVcpFn = null;

function chooseHandle() {
  return ownHandle || lastHandle;
}

// Walk every HMONITOR, open its physical monitors, and pick the one whose 0xe2
// status reads back as 0x39xx (the G95NC PBP/PIP status family).
function acquireOwnHandle() {
  if (ownHandle) { return ownHandle; }
  const enumAddr = findExportAddress("User32.dll", "EnumDisplayMonitors");
  const numAddr = findExportAddress("Dxva2.dll", "GetNumberOfPhysicalMonitorsFromHMONITOR");
  const physAddr = findExportAddress("Dxva2.dll", "GetPhysicalMonitorsFromHMONITOR");
  if (!enumAddr || !numAddr || !physAddr) {
    send({ type: "status", text: "acquire: could not resolve EnumDisplayMonitors / GetPhysicalMonitors*" });
    return null;
  }
  ensureFns();
  const EnumDisplayMonitors = new NativeFunction(enumAddr, "int", ["pointer", "pointer", "pointer", "pointer"]);
  const GetNum = new NativeFunction(numAddr, "int", ["pointer", "pointer"]);
  const GetPhys = new NativeFunction(physAddr, "int", ["pointer", "uint", "pointer"]);

  const hmonitors = [];
  const cb = new NativeCallback(function (hMon, hdc, lprc, lparam) {
    hmonitors.push(ptr(hMon.toString()));
    return 1;
  }, "int", ["pointer", "pointer", "pointer", "pointer"]);
  EnumDisplayMonitors(NULL, NULL, cb, NULL);

  const STRUCT = 8 + 128 * 2;  // PHYSICAL_MONITOR { HANDLE; WCHAR desc[128]; }
  let firstHandle = null;
  for (const hm of hmonitors) {
    const numP = Memory.alloc(4);
    if (!GetNum(hm, numP)) { continue; }
    const n = numP.readU32();
    if (n === 0) { continue; }
    const arr = Memory.alloc(STRUCT * n);
    if (!GetPhys(hm, n, arr)) { continue; }
    for (let i = 0; i < n; i++) {
      const phys = arr.add(i * STRUCT);
      const h = ptr(phys.readPointer().toString());
      const desc = phys.add(8).readUtf16String();
      if (firstHandle === null) { firstHandle = h; }
      const vct = Memory.alloc(4), cur = Memory.alloc(4), max = Memory.alloc(4);
      const ok = getVcpFn(h, 0xe2, vct, cur, max);
      const c = cur.readU32();
      send({ type: "status", text: "acquire probe handle=" + h + " desc='" + desc + "' e2ok=" + ok + " cur=0x" + c.toString(16) });
      if (ok && ((c >> 8) & 0xff) === 0x39) {
        ownHandle = h;
        send({ type: "status", text: "acquire: selected G95NC handle=" + h + " (e2=0x" + c.toString(16) + ")" });
        return ownHandle;
      }
    }
  }
  if (firstHandle !== null) {
    ownHandle = firstHandle;
    send({ type: "status", text: "acquire: no 0x39xx match; falling back to first physical monitor handle=" + firstHandle });
  } else {
    send({ type: "status", text: "acquire: no physical monitors found" });
  }
  return ownHandle;
}

function ensureFns() {
  if (setVcpFn === null) {
    // BOOL SetVCPFeature(HANDLE hMonitor, BYTE bVCPCode, DWORD dwNewValue)
    const a = findExportAddress("Dxva2.dll", "SetVCPFeature");
    if (a === null) { throw new Error("could not resolve Dxva2.dll!SetVCPFeature"); }
    setVcpFn = new NativeFunction(a, "int", ["pointer", "uint", "uint"]);
  }
  if (getVcpFn === null) {
    // BOOL GetVCPFeatureAndVCPFeatureReply(HANDLE, BYTE, LPMC_VCP_CODE_TYPE,
    //                                      LPDWORD currentValue, LPDWORD maximumValue)
    const a = findExportAddress("Dxva2.dll", "GetVCPFeatureAndVCPFeatureReply");
    if (a === null) { throw new Error("could not resolve Dxva2.dll!GetVCPFeatureAndVCPFeatureReply"); }
    getVcpFn = new NativeFunction(a, "int", ["pointer", "uint", "pointer", "pointer", "pointer"]);
  }
}

function sendHit(kind, code, value, extra) {
  if (!HOOK_ALL && !interesting[code]) {
    return;
  }
  send({
    type: "hit",
    seq: seq++,
    rel: Date.now() - startedAt,
    kind,
    code,
    value,
    extra: extra || "",
  });
}

function findExportAddress(moduleName, exportName) {
  // 1) Modern frida: module lookup is case-insensitive on Windows.
  try {
    const m = Process.findModuleByName(moduleName);
    if (m) {
      const e = m.findExportByName ? m.findExportByName(exportName) : null;
      if (e) { return e; }
    }
  } catch (e) {}
  // 2) Global export search across all modules (frida 17).
  try {
    if (typeof Module.getGlobalExportByName === "function") {
      const e = Module.getGlobalExportByName(exportName);
      if (e) { return e; }
    }
  } catch (e) {}
  // 3) Legacy ApiResolver fallback, including a wildcard-module pattern that
  //    sidesteps DLL-name casing differences (e.g. USER32.dll).
  try {
    const resolver = new ApiResolver("module");
    const patterns = [
      "exports:" + moduleName + "!" + exportName,
      "exports:*!" + exportName,
    ];
    for (const pattern of patterns) {
      const matches = resolver.enumerateMatches(pattern);
      if (matches.length > 0) {
        return matches[0].address;
      }
    }
  } catch (e) {}
  return null;
}

function findModuleBase(moduleName) {
  const lower = moduleName.toLowerCase();
  for (const module of Process.enumerateModules()) {
    if (module.name.toLowerCase() === lower) {
      return module.base;
    }
  }
  return null;
}

function hookSetVcp() {
  const addr = findExportAddress("Dxva2.dll", "SetVCPFeature");
  if (addr === null) {
    send({ type: "status", text: "missing export Dxva2.dll!SetVCPFeature" });
    return;
  }
  Interceptor.attach(addr, {
    onEnter(args) {
      lastHandle = ptr(args[0].toString());
      const code = args[1].toUInt32() & 0xff;
      const value = args[2].toUInt32() & 0xffffffff;
      sendHit("SET", code, value, "handle=" + args[0]);
    }
  });
  send({ type: "status", text: "hooked SET DXVA2!SetVCPFeature at " + addr });
}

function hookGetVcp() {
  const addr = findExportAddress("Dxva2.dll", "GetVCPFeatureAndVCPFeatureReply");
  if (addr === null) {
    send({ type: "status", text: "missing export Dxva2.dll!GetVCPFeatureAndVCPFeatureReply" });
    return;
  }
  Interceptor.attach(addr, {
    onEnter(args) {
      lastHandle = ptr(args[0].toString());
      this.code = args[1].toUInt32() & 0xff;
      this.curPtr = args[3];
    },
    onLeave(retval) {
      let cur = 0;
      try { cur = this.curPtr.readU32(); } catch (e) { cur = 0xffffffff; }
      sendHit("GET", this.code, cur, "");
    }
  });
  send({ type: "status", text: "hooked GET DXVA2!GetVCPFeatureAndVCPFeatureReply at " + addr });
}

function hookDisplayToolkitOffset(offset, label) {
  const base = findModuleBase("DisplayToolkit.dll");
  if (base === null) {
    send({ type: "status", text: "DisplayToolkit.dll not loaded" });
    return;
  }
  const addr = base.add(offset);
  Interceptor.attach(addr, {
    onEnter(args) {
      // dcc_ci::Vcp::SetVCP wrapper: RCX=this, EDX=VCP code, R8D=value.
      const code = args[1].toUInt32() & 0xff;
      const value = args[2].toUInt32() & 0xffffffff;
      sendHit(label, code, value, "this=" + args[0]);
    }
  });
  send({ type: "status", text: "hooked " + label + " at " + addr });
}

rpc.exports = {
  handle: function () {
    const h = chooseHandle();
    return { own: ownHandle ? ownHandle.toString() : null, scraped: lastHandle ? lastHandle.toString() : null, active: h ? h.toString() : null };
  },
  acquire: function () {
    const h = acquireOwnHandle();
    return h ? h.toString() : null;
  },
  setvcp: function (code, value) {
    const h = chooseHandle();
    if (!h) {
      return { ok: false, error: "no handle; run acquire (or do one SDM action)" };
    }
    ensureFns();
    const ret = setVcpFn(h, code & 0xff, value >>> 0);
    return { ok: true, ret: ret, handle: h.toString() };
  },
  getvcp: function (code) {
    const h = chooseHandle();
    if (!h) {
      return { ok: false, error: "no handle; run acquire (or do one SDM action)" };
    }
    ensureFns();
    const vct = Memory.alloc(4);
    const cur = Memory.alloc(4);
    const max = Memory.alloc(4);
    const ret = getVcpFn(h, code & 0xff, vct, cur, max);
    return {
      ok: true,
      ret: ret,
      vct: vct.readU32(),
      current: cur.readU32(),
      max: max.readU32(),
      handle: h.toString(),
    };
  }
};

if (HOOK_SETVCP) {
  hookSetVcp();
}
if (HOOK_GETVCP) {
  hookGetVcp();
}
if (HOOK_DISPLAY_TOOLKIT) {
  hookDisplayToolkitOffset(0x1a490, "DT!SetVCP");
}
"""


def on_message(message, data):
    if message["type"] == "send":
        payload = message["payload"]
        if payload.get("type") == "hit":
            ts = time.strftime("%H:%M:%S")
            code = payload["code"]
            value = payload["value"]
            print(
                f"{ts} #{payload['seq']:04d} +{payload['rel']:>6}ms {payload['kind']:>3}: "
                f"code=0x{code:02x} value=0x{value:08x} ({value}) {payload.get('extra', '')}",
                flush=True,
            )
        else:
            print("[trace] " + payload.get("text", repr(payload)), flush=True)
    elif message["type"] == "error":
        print(message.get("stack", message), file=sys.stderr, flush=True)


def find_pid(name):
    device = frida.get_local_device()
    lower = name.lower()
    matches = [p for p in device.enumerate_processes() if p.name.lower() == lower]
    if not matches:
        matches = [p for p in device.enumerate_processes() if lower in p.name.lower()]
    if not matches:
        raise SystemExit(f"process not found: {name}")
    if len(matches) > 1:
        print("multiple matches, using first:", file=sys.stderr)
        for p in matches:
            print(f"  {p.pid} {p.name}", file=sys.stderr)
    return matches[0].pid


def parse_int(token):
    return int(token, 16) if token.lower().startswith("0x") else int(token, 16)


REPLAY_HELP = """\
Replay console (commands go through a real monitor handle):
  acquire              open our own physical monitor handle (autodetect G95NC)
  set <code> <value>   e.g. 'set e2 0001'  (hex; sends DXVA2!SetVCPFeature)
  get <code>           e.g. 'get e2'        (reads current/max back)
  seq <c v> <c v> ...  e.g. 'seq e2 0001 e3 0001 e3 0101 e2 0007'
  sleep <ms>           pause between steps when scripting by hand
  handle               print own/scraped/active handles
  help                 show this
  quit                 detach and exit
All values are hex. Run 'acquire' first (or do one SDM action) for a handle.
"""


def run_command(script, line):
    """Execute one replay command line. Returns False to request exit."""
    parts = shlex.split(line)
    if not parts:
        return True
    cmd = parts[0].lower()
    try:
        if cmd in ("quit", "exit", "q"):
            return False
        elif cmd == "help":
            print(REPLAY_HELP, flush=True)
        elif cmd == "acquire":
            print("  acquire ->", script.exports_sync.acquire(), flush=True)
        elif cmd == "handle":
            print("  handle =", script.exports_sync.handle(), flush=True)
        elif cmd == "sleep" and len(parts) == 2:
            time.sleep(int(parts[1]) / 1000.0)
        elif cmd == "set" and len(parts) == 3:
            code, value = parse_int(parts[1]), parse_int(parts[2])
            r = script.exports_sync.setvcp(code, value)
            print(f"  SET 0x{code:02x}=0x{value:04x} -> {r}", flush=True)
        elif cmd == "get" and len(parts) == 2:
            code = parse_int(parts[1])
            r = script.exports_sync.getvcp(code)
            if r.get("ok"):
                print(
                    f"  GET 0x{code:02x} -> current=0x{r['current']:04x} "
                    f"max=0x{r['max']:04x} ret={r['ret']}",
                    flush=True,
                )
            else:
                print(f"  GET 0x{code:02x} -> {r}", flush=True)
        elif cmd == "seq" and len(parts) >= 3 and (len(parts) - 1) % 2 == 0:
            for i in range(1, len(parts), 2):
                code, value = parse_int(parts[i]), parse_int(parts[i + 1])
                r = script.exports_sync.setvcp(code, value)
                print(f"  SET 0x{code:02x}=0x{value:04x} -> {r}", flush=True)
                time.sleep(0.15)
        else:
            print(f"  ?  unrecognized: {line!r} (type 'help')", flush=True)
    except Exception as exc:  # keep going on a bad line
        print(f"  error on {line!r}: {exc}", flush=True)
    return True


def run_replay_console(script):
    print(REPLAY_HELP, flush=True)
    while True:
        try:
            line = input("vcp> ").strip()
        except EOFError:
            break
        if line and not run_command(script, line):
            break


def run_exec(script, exec_str):
    """Run a ';'-separated command string non-interactively, then return."""
    for line in exec_str.split(";"):
        line = line.strip()
        if not line:
            continue
        print(f"vcp> {line}", flush=True)
        if not run_command(script, line):
            break
        time.sleep(0.1)


def main():
    parser = argparse.ArgumentParser(description="Trace and replay Samsung Display Manager VCP writes.")
    parser.add_argument("--pid", type=int, help="target process id")
    parser.add_argument("--name", default="SamsungDisplayManager.exe", help="target process name")
    parser.add_argument("--all", action="store_true", help="log all VCP codes, not just the interesting set")
    parser.add_argument("--no-getvcp", action="store_true", help="do not hook GetVCPFeatureAndVCPFeatureReply readbacks")
    parser.add_argument("--no-setvcp", action="store_true", help="do not hook SetVCPFeature")
    parser.add_argument("--display-toolkit", action="store_true", help="also hook DisplayToolkit.dll + 0x1A490")
    parser.add_argument("--replay", action="store_true", help="open an interactive set/get/seq console while tracing")
    parser.add_argument("--acquire", action="store_true", help="open our own physical monitor handle on startup")
    parser.add_argument("--exec", dest="exec_str", help="run ';'-separated replay commands non-interactively, then exit")
    args = parser.parse_args()

    pid = args.pid or find_pid(args.name)
    print(f"[trace] attaching to pid {pid}", flush=True)
    session = frida.attach(pid)

    def on_detached(reason, crash):
        print(f"[trace] target detached: reason={reason} crash={crash}", flush=True)

    session.on("detached", on_detached)

    flags = (
        f"const HOOK_SETVCP = {'false' if args.no_setvcp else 'true'};\n"
        f"const HOOK_GETVCP = {'false' if args.no_getvcp else 'true'};\n"
        f"const HOOK_DISPLAY_TOOLKIT = {'true' if args.display_toolkit else 'false'};\n"
        f"const HOOK_ALL = {'true' if args.all else 'false'};\n"
    )
    script = session.create_script(flags + JS)
    script.on("message", on_message)
    script.load()

    if args.acquire or args.exec_str:
        h = script.exports_sync.acquire()
        print(f"[trace] acquired handle: {h}", flush=True)

    if args.exec_str:
        run_exec(script, args.exec_str)
        print("[trace] detaching", flush=True)
        session.detach()
        return

    if args.replay:
        print("[trace] ready; replay console enabled (run 'acquire' or do one SDM action for a handle)", flush=True)
        run_replay_console(script)
        print("\n[trace] detaching", flush=True)
        session.detach()
        return

    print("[trace] ready; perform one Samsung Display Manager action at a time", flush=True)
    try:
        while True:
            time.sleep(0.25)
    except KeyboardInterrupt:
        print("\n[trace] detaching", flush=True)
        session.detach()


if __name__ == "__main__":
    main()
