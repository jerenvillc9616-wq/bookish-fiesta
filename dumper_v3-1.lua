--[[
    SCRIPT DUMPER v3 — LIGHTWEIGHT
    
    Cara pakai:
      1. Execute script ini
      2. Execute target hub
      3. Ketik di console: getgenv().DUMP:s()  untuk lihat hasil
      4. Ketik di console: getgenv().DUMP:e()  untuk export semua ke file
    
    Beda dari v2:
      - TANPA UI (penyebab lag/freeze)
      - TANPA polling loop (penyebab 1fps)
      - Hook minimal: loadstring + readfile saja
      - Ringan, tidak ganggu gameplay
]]

-- Output folder
local DIR = "dumpcap"
pcall(function() makefolder(DIR) end)

-- State
local D = {n = 0, list = {}, hashes = {}}
getgenv().DUMP = D

-- Hash sederhana
local function hash(s)
    if type(s) ~= "string" then return "0" end
    local h = 5381
    for i = 1, math.min(#s, 8192) do
        h = ((h * 33) + string.byte(s, i)) % 4294967296
    end
    return string.format("%08x", h)
end

-- Detect signature
local function sig(s)
    if type(s) ~= "string" then return "?" end
    if s:sub(1,4) == "\27Lua" then return "BYTECODE" end
    if s:find("LPH|", 1, true) then return "LURAPH_v11" end
    if s:find("LPH+", 1, true) then return "LURAPH_v13" end
    if s:find("luarmor", 1, true) or s:find("Luarmor", 1, true) then return "LUARMOR" end
    if s:find("superflow", 1, true) then return "LUARMOR_VM" end
    if s:find("by memcorrupt", 1, true) then return "LURAPH" end
    if #s > 50000 then return "OBFUSCATED" end
    return "PLAIN"
end

-- Save satu capture
local function save(payload, src, name)
    if type(payload) ~= "string" then return end
    if #payload < 50 then return end

    local h = hash(payload)
    if D.hashes[h] then return end
    D.hashes[h] = true

    D.n = D.n + 1
    local idx = D.n
    local s = sig(payload)
    local fname = string.format("%s/%03d_%s_%s.txt", DIR, idx, s, h)

    local header = string.format(
        "-- CAPTURE #%03d | %s | %s | %d bytes | %s\n-- Source: %s\n\n",
        idx, s, h, #payload, os.date("%H:%M:%S"), tostring(src))

    pcall(function() writefile(fname, header .. payload) end)

    local entry = {i = idx, sig = s, len = #payload, src = tostring(src):sub(1,40), file = fname}
    D.list[idx] = entry
    print(string.format("[CAP] #%03d %s %dB from %s", idx, s, #payload, entry.src))
end

-- Hook loadstring (fallback global replace)
local _ls = loadstring
getgenv().loadstring = function(src, name, ...)
    save(src, "loadstring", name)
    return _ls(src, name, ...)
end

-- Hook load
local _ld = load
if _ld then
    getgenv().load = function(src, name, ...)
        if type(src) == "string" then
            save(src, "load", name)
        end
        return _ld(src, name, ...)
    end
end

-- Hook readfile (untuk Luarmor cache)
if readfile then
    local _rf = readfile
    getgenv().readfile = function(path, ...)
        local ok, result = pcall(_rf, path, ...)
        if ok and type(result) == "string" and #result > 100 then
            save(result, "readfile:" .. tostring(path):sub(1,50))
        end
        if ok then return result end
        error(result, 2)
    end
end

-- Status command
function D:s()
    print(string.format("[DUMP] %d captures", self.n))
    for _, m in ipairs(self.list) do
        print(string.format("  #%03d %-12s %7dB  %s", m.i, m.sig, m.len, m.src))
    end
end

-- Export summary
function D:e()
    local lines = {"DUMP SUMMARY — " .. os.date(), "Captures: " .. self.n, ""}
    for _, m in ipairs(self.list) do
        table.insert(lines, string.format("#%03d %-12s %7dB  %s  → %s", m.i, m.sig, m.len, m.src, m.file))
    end
    pcall(function() writefile(DIR .. "/_SUMMARY.txt", table.concat(lines, "\n")) end)
    print("[DUMP] Summary saved to " .. DIR .. "/_SUMMARY.txt")
end

print("[DUMP] Ready. " .. D.n .. " captures. Execute target hub sekarang.")
print("[DUMP] Commands: getgenv().DUMP:s()  getgenv().DUMP:e()")
