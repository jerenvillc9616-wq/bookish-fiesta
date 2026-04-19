--[[
    GATEWAY PROBE v1.2 — AUTO SAVE
    
    1. Execute script ini
    2. Execute target hub
    3. Tunggu 1-2 menit
    4. Buka file workspace/dumpcap/PROBE_REPORT.txt
    5. Kirim file itu ke Claude
    
    File auto-update tiap 15 detik. Tidak perlu ketik apapun di console.
]]

local P = {hits = {}, order = {}, start = tick()}
getgenv().PROBE = P

local DIR = "dumpcap"
pcall(function() makefolder(DIR) end)

local function hit(name, extra)
    local h = P.hits[name]
    if not h then
        h = {n = 0, samples = {}}
        P.hits[name] = h
        P.order[#P.order + 1] = name
    end
    h.n = h.n + 1
    if #h.samples < 2 and extra then
        h.samples[#h.samples + 1] = tostring(extra):sub(1, 60)
    end
end

-- Save originals
local O = {
    loadstring = loadstring, load = load,
    readfile = readfile, writefile = writefile,
    listfiles = listfiles, require = require,
    str_char = string.char, str_byte = string.byte,
    str_sub = string.sub, tbl_concat = table.concat,
    getmeta = getmetatable, setmeta = setmetatable,
    getfenv = getfenv,
    co_wrap = coroutine.wrap, co_resume = coroutine.resume,
}
if bit32 then
    O.bxor = bit32.bxor
    O.band = bit32.band
    O.rshift = bit32.rshift
end

-- Hook everything
getgenv().loadstring = function(s,...) hit("loadstring", type(s)=="string" and s:sub(1,40)); return O.loadstring(s,...) end
if O.load then getgenv().load = function(s,...) hit("load", type(s)=="string" and s:sub(1,40)); return O.load(s,...) end end
if O.require then getgenv().require = function(id,...) hit("require", id); return O.require(id,...) end end
string.char = function(...) hit("string.char"); return O.str_char(...) end
string.byte = function(s,i,j) hit("string.byte"); return O.str_byte(s,i,j) end
string.sub = function(s,i,j) hit("string.sub"); return O.str_sub(s,i,j) end
table.concat = function(t,...) hit("table.concat", t and #t.." items"); return O.tbl_concat(t,...) end
if bit32 and O.bxor then
    bit32.bxor = function(...) hit("bit32.bxor"); return O.bxor(...) end
    bit32.band = function(...) hit("bit32.band"); return O.band(...) end
    bit32.rshift = function(...) hit("bit32.rshift"); return O.rshift(...) end
end
getgenv().getmetatable = function(...) hit("getmetatable"); return O.getmeta(...) end
getgenv().setmetatable = function(...) hit("setmetatable"); return O.setmeta(...) end
if O.getfenv then getgenv().getfenv = function(...) hit("getfenv"); return O.getfenv(...) end end
coroutine.wrap = function(...) hit("coroutine.wrap"); return O.co_wrap(...) end
coroutine.resume = function(...) hit("coroutine.resume"); return O.co_resume(...) end
if O.readfile then getgenv().readfile = function(p,...) hit("readfile", p); return O.readfile(p,...) end end
if O.writefile then getgenv().writefile = function(p,...) hit("writefile", p); return O.writefile(p,...) end end
if O.listfiles then getgenv().listfiles = function(p,...) hit("listfiles", p); return O.listfiles(p,...) end end

-- Build report text
local function build_report()
    local t = tick() - P.start
    local sorted = {}
    for _, name in ipairs(P.order) do sorted[#sorted+1] = {name=name, h=P.hits[name]} end
    table.sort(sorted, function(a,b) return a.h.n > b.h.n end)

    local lines = {
        "GATEWAY PROBE REPORT",
        "Updated: " .. os.date(),
        string.format("Elapsed: %.0f seconds", t),
        string.format("Gateways detected: %d", #P.order),
        "",
        "=== HIT COUNTS ===",
    }
    for _, e in ipairs(sorted) do
        lines[#lines+1] = string.format("%-20s %8d", e.name, e.h.n)
        for _, s in ipairs(e.h.samples) do
            lines[#lines+1] = "  sample: " .. s
        end
    end

    lines[#lines+1] = ""
    lines[#lines+1] = "=== ANALYSIS ==="

    local sc = P.hits["string.char"]
    local ls = P.hits["loadstring"]
    local rf = P.hits["readfile"]
    local tc = P.hits["table.concat"]
    local bx = P.hits["bit32.bxor"]
    local sb = P.hits["string.byte"]

    if ls and ls.n > 0 then
        lines[#lines+1] = "LOADSTRING TERBUKA (" .. ls.n .. "x) — dumper v3 bisa capture lewat sini"
    end
    if rf and rf.n > 0 then
        lines[#lines+1] = "READFILE TERBUKA (" .. rf.n .. "x) — ada file cache, dumper v3 bisa capture"
    end
    if sc and sc.n > 1000 then
        lines[#lines+1] = "STRING.CHAR SANGAT TINGGI (" .. sc.n .. "x) — VM rebuild string dari byte satu-satu"
        lines[#lines+1] = "  Celah: hook string.char accumulator untuk tangkap hasil rebuild"
    end
    if sb and sb.n > 1000 then
        lines[#lines+1] = "STRING.BYTE TINGGI (" .. sb.n .. "x) — VM baca bytes dari encoded data"
    end
    if tc and tc.n > 100 then
        lines[#lines+1] = "TABLE.CONCAT TINGGI (" .. tc.n .. "x) — string assembly dari potongan"
        lines[#lines+1] = "  Celah: hook table.concat, tangkap output besar (>1KB)"
    end
    if bx and bx.n > 500 then
        lines[#lines+1] = "BIT32.BXOR TINGGI (" .. bx.n .. "x) — XOR decryption aktif di VM"
    end
    if not ls and not rf and sc and sc.n > 500 then
        lines[#lines+1] = ""
        lines[#lines+1] = "KESIMPULAN: Hub pakai CUSTOM VM (tidak lewat loadstring/readfile)"
        lines[#lines+1] = "Dumper v3 TIDAK BISA capture hub ini."
        lines[#lines+1] = "Perlu: hook string.char + table.concat accumulator (Claude bikin di sesi berikutnya)"
    end
    if ls and ls.n > 0 and (not sc or sc.n < 100) then
        lines[#lines+1] = ""
        lines[#lines+1] = "KESIMPULAN: Hub pakai loadstring klasik"
        lines[#lines+1] = "Dumper v3 BISA capture hub ini langsung."
    end
    if rf and rf.n > 0 and (not ls or ls.n == 0) then
        lines[#lines+1] = ""
        lines[#lines+1] = "KESIMPULAN: Hub load dari file cache (kemungkinan Luarmor)"
        lines[#lines+1] = "Dumper v3 BISA capture isi file lewat readfile hook."
    end

    return O.tbl_concat(lines, "\n")
end

-- Auto-save loop (setiap 15 detik)
task.spawn(function()
    while true do
        task.wait(15)
        local report = build_report()
        pcall(O.writefile, DIR .. "/PROBE_REPORT.txt", report)
    end
end)

-- Also save on game close
pcall(function()
    game:BindToClose(function()
        pcall(O.writefile, DIR .. "/PROBE_REPORT.txt", build_report())
    end)
end)

print("[PROBE] Aktif. Report otomatis save ke workspace/" .. DIR .. "/PROBE_REPORT.txt tiap 15 detik.")
print("[PROBE] Jalankan target hub sekarang, tunggu 1-2 menit, lalu buka file-nya.")
