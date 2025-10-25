-- ============================================
--
--
--          Avresi Event Shield Protection
--
--
-- Description: Automatically encrypts and protects all events
-- Version: 1.0.0
-- Developer: Avresi Development
-- Discord: https://discord.gg/EmkbQFPc8G
--
--
-- ============================================

local DEFAULT_SECRET = "change_me_setr_avresi_eventshield_secret"
local SECRET_KEY = GetConvar("avresi_eventshield_secret", DEFAULT_SECRET)

local eventCache = {}
local rateLimits = {}
local playerFingerprints = {}

local tablePack = table.pack or function(...)
    return { n = select("#", ...), ... }
end

local tableUnpack = table.unpack or unpack

if SECRET_KEY == DEFAULT_SECRET and IsDuplicityVersion() then
    print("^3[Avresi PROTECTION] Warning: Add `setr avresi_eventshield_secret <random_password>` to your server.cfg file.^7")
end

local function hashString(value)
    local hash = 0
    for i = 1, #value do
        hash = ((hash * 131) + string.byte(value, i)) % 4294967295
    end
    return string.format("%08X", hash)
end

local function buildSecureName(eventName)
    return string.format("__avresi_%s_%s", hashString(eventName), hashString(SECRET_KEY))
end

local function encryptEvent(eventName, timestamp, source)
    local payload = string.format("%s|%s|%s|%s", eventName, tostring(timestamp), tostring(source or 0), SECRET_KEY)
    return hashString(payload)
end

local function signEvent(eventName, source)
    local timestamp = os.time()
    local signature = encryptEvent(eventName, timestamp, source)
    return signature, timestamp
end

local function verifySignature(eventName, signature, timestamp, source)
    if type(signature) ~= "string" or not timestamp then
        return false
    end

    local diff = os.time() - timestamp
    if diff < 0 or diff > 30 then
        return false
    end

    return signature == encryptEvent(eventName, timestamp, source)
end

local function checkRateLimit(source, eventName)
    local key = source .. "_" .. eventName
    local currentTime = os.time()

    if not rateLimits[key] then
        rateLimits[key] = { count = 1, resetTime = currentTime + 60 }
        return true
    end

    if currentTime > rateLimits[key].resetTime then
        rateLimits[key] = { count = 1, resetTime = currentTime + 60 }
        return true
    end

    if rateLimits[key].count >= 100 then
        return false
    end

    rateLimits[key].count = rateLimits[key].count + 1
    return true
end

local blacklistedEvents = {
    "playerEnteredScope", "playerLeftScope", "entityRemoved", "entityCreating",
    "entityCreated", "ptfxEvent", "clearPedTasksEvent", "giveWeaponEvent",
    "removeWeaponEvent", "ptFxEvent", "explosionEvent", "startProjectileEvent",
    "onServerResourceStop", "onResourceListRefresh", "onResourceStart",
    "onServerResourceStart", "onResourceStarting", "onResourceStop",
    "playerConnecting", "playerDropped", "rconCommand", "playerJoining",
    "__cfx_internal:commandFallback", "commandLoggerDiscord:commandWasExecuted"
}

local function isSystemEvent(eventName)
    return eventName:match("^__cfx") or
        eventName:match("^txAdmin") or
        eventName:match("^txsv") or
        eventName:match("^_cfx") or
        eventName:match("^onNet") or
        eventName:match("^onClient") or
        eventName:match("^chat:") or
        eventName:match("^mumble") or
        eventName:match("^avresi%-eventshield:")
end

local function isBlacklisted(eventName)
    local cleanName = eventName:lower():gsub("[^%w]", "")
    for _, blocked in ipairs(blacklistedEvents) do
        if cleanName:find(blocked:lower():gsub("[^%w]", "")) then
            return true
        end
    end
    return false
end

local function getSecureEventName(eventName)
    if eventCache[eventName] then
        return eventCache[eventName]
    end

    local secureName = buildSecureName(eventName)
    eventCache[eventName] = secureName

    return secureName
end

local function validateParams(...)
    local args = { ... }
    for _, arg in ipairs(args) do
        local argType = type(arg)

        if argType == "function" then
            return false
        end

        if argType == "table" then
            local count = 0
            for _ in pairs(arg) do
                count = count + 1
                if count > 1000 then
                    return false
                end
            end
        end

        if argType == "string" and #arg > 10000 then
            return false
        end
    end

    return true
end

local function banPlayer(source, reason)
    if IsDuplicityVersion() then
        local playerName = GetPlayerName(source) or "Unknown"

        print(string.format("^1[Avresi PROTECTION] Player banned: %s^7", playerName))
        print(string.format("^1Reason: %s^7", reason))

        pcall(function()
            if exports and exports["avresi-base"] and exports["avresi-base"].BanPlayer then
                exports["avresi-base"]:BanPlayer(source, reason, "trigger")
            end
        end)

        DropPlayer(source, reason)
    end
end

local function toSourceId(value)
    local num = tonumber(value)
    if not num or num <= 0 then
        return nil
    end
    return num
end

local nativeTriggerEvent = TriggerEvent
local nativeTriggerServerEvent = TriggerServerEvent
local nativeTriggerClientEvent = TriggerClientEvent
local nativeRegisterNetEvent = RegisterNetEvent
local nativeRegisterServerEvent = RegisterServerEvent
local nativeAddEventHandler = AddEventHandler

if IsDuplicityVersion() then
    local violationLimits = {
        rate = 3,
        signature = 3,
        params = 1,
        unsecured = 1
    }

    local function ensureFingerprint(src)
        if not playerFingerprints[src] then
            playerFingerprints[src] = {
                firstSeen = os.time(),
                counts = {}
            }
        end
        return playerFingerprints[src]
    end

    local function flagViolation(src, kind, reason)
        src = toSourceId(src)
        if not src then
            return
        end

        local fingerprint = ensureFingerprint(src)
        local counts = fingerprint.counts
        counts[kind] = (counts[kind] or 0) + 1

        if counts[kind] >= (violationLimits[kind] or 1) then
            banPlayer(src, reason)
            counts[kind] = 0
        end
    end

    AddEventHandler("playerConnecting", function()
        ensureFingerprint(source)
    end)

    AddEventHandler("playerDropped", function()
        local src = toSourceId(source)
        if not src then
            return
        end

        playerFingerprints[src] = nil

        for key in pairs(rateLimits) do
            if key:match("^" .. src .. "_") then
                rateLimits[key] = nil
            end
        end
    end)

    local function secured_TriggerEvent(eventName, ...)
        if not validateParams(...) then
            return
        end

        if isSystemEvent(eventName) then
            nativeTriggerEvent(eventName, ...)
            return
        end

        if isBlacklisted(eventName) then
            return
        end

        local secureEvent = getSecureEventName(eventName)
        nativeTriggerEvent(secureEvent, ...)
    end

    local function collectTargets(target)
        if target == nil or target == -1 then
            local players = {}
            for _, id in ipairs(GetPlayers()) do
                local numericId = toSourceId(id)
                if numericId then
                    players[#players + 1] = numericId
                end
            end
            return players
        end

        if type(target) == "table" then
            local players = {}
            for _, id in ipairs(target) do
                local numericId = toSourceId(id)
                if numericId then
                    players[#players + 1] = numericId
                end
            end
            return players
        end

        local numericId = toSourceId(target)
        if numericId then
            return { numericId }
        end

        return {}
    end

    local function secured_TriggerClientEvent(eventName, target, ...)
        if not nativeTriggerClientEvent then
            return
        end

        if not validateParams(...) then
            return
        end

        if isSystemEvent(eventName) then
            nativeTriggerClientEvent(eventName, target, ...)
            return
        end

        if isBlacklisted(eventName) then
            return
        end

        local payload = tablePack(...)
        local targets = collectTargets(target)
        local secureEvent = getSecureEventName(eventName)

        for _, playerId in ipairs(targets) do
            local signature, timestamp = signEvent(eventName, playerId)
            nativeTriggerClientEvent(secureEvent, playerId, signature, timestamp, tableUnpack(payload, 1, payload.n))
        end
    end

    local function secured_RegisterServerEvent(eventName, callback)
        if isSystemEvent(eventName) then
            if nativeRegisterServerEvent then
                nativeRegisterServerEvent(eventName, callback)
            elseif nativeRegisterNetEvent then
                nativeRegisterNetEvent(eventName, callback)
            end
            return
        end

        if isBlacklisted(eventName) then
            return
        end

        local secureEvent = getSecureEventName(eventName)

        nativeRegisterNetEvent(secureEvent, function(signature, timestamp, ...)
            local src = toSourceId(source)
            if not src then
                return
            end

            if GetPlayerPed(src) <= 0 then
                return
            end

            if not checkRateLimit(src, eventName) then
                flagViolation(src, "rate", "Event spam detected: " .. eventName)
                return
            end

            if not verifySignature(eventName, signature, timestamp, src) then
                flagViolation(src, "signature", "Invalid event signature: " .. eventName)
                return
            end

            if not validateParams(...) then
                flagViolation(src, "params", "Invalid parameters: " .. eventName)
                return
            end

            if callback and type(callback) == "function" then
                callback(...)
            end
        end)

        nativeRegisterNetEvent(eventName, function(...)
            local src = toSourceId(source)
            if src then
                flagViolation(src, "unsecured", "Unencrypted event usage: " .. eventName)
            end
        end)
    end

    local function secured_RegisterNetEvent(eventName, callback)
        secured_RegisterServerEvent(eventName, callback)
    end

    local function secured_AddEventHandler(eventName, callback)
        if isSystemEvent(eventName) then
            nativeAddEventHandler(eventName, callback)
            return
        end

        if isBlacklisted(eventName) then
            return
        end

        local secureEvent = getSecureEventName(eventName)

        nativeAddEventHandler(secureEvent, function(signature, timestamp, ...)
            local src = toSourceId(source)

            if src then
                if not checkRateLimit(src, eventName) then
                    flagViolation(src, "rate", "Event handler spam: " .. eventName)
                    return
                end

                if not verifySignature(eventName, signature, timestamp, src) then
                    flagViolation(src, "signature", "Invalid signature for event handler: " .. eventName)
                    return
                end
            end

            if not validateParams(...) then
                flagViolation(src or 0, "params", "Event handler parameter violation: " .. eventName)
                return
            end

            if callback and type(callback) == "function" then
                callback(...)
            end
        end)

        nativeAddEventHandler(eventName, function(...)
            local src = toSourceId(source)
            if src then
                flagViolation(src, "unsecured", "Unencrypted event handler: " .. eventName)
            end
        end)
    end

    TriggerEvent = secured_TriggerEvent
    TriggerClientEvent = secured_TriggerClientEvent
    RegisterServerEvent = secured_RegisterServerEvent
    RegisterNetEvent = secured_RegisterNetEvent
    AddEventHandler = secured_AddEventHandler
else
    local function getPlayerServerId()
        return GetPlayerServerId(PlayerId())
    end

    local function secured_TriggerServerEvent(eventName, ...)
        if not validateParams(...) then
            return
        end

        if isSystemEvent(eventName) then
            nativeTriggerServerEvent(eventName, ...)
            return
        end

        if isBlacklisted(eventName) then
            return
        end

        local secureEvent = getSecureEventName(eventName)
        local signature, timestamp = signEvent(eventName, getPlayerServerId())

        nativeTriggerServerEvent(secureEvent, signature, timestamp, ...)
    end

    local function secured_TriggerEvent(eventName, ...)
        if not validateParams(...) then
            return
        end

        if isSystemEvent(eventName) then
            nativeTriggerEvent(eventName, ...)
            return
        end

        if isBlacklisted(eventName) then
            return
        end

        local secureEvent = getSecureEventName(eventName)
        nativeTriggerEvent(secureEvent, ...)
    end

    local function secured_RegisterNetEvent(eventName, callback)
        if isSystemEvent(eventName) then
            nativeRegisterNetEvent(eventName, callback)
            return
        end

        if isBlacklisted(eventName) then
            return
        end

        local secureEvent = getSecureEventName(eventName)

        nativeRegisterNetEvent(secureEvent, function(signature, timestamp, ...)
            if not verifySignature(eventName, signature, timestamp, getPlayerServerId()) then
                return
            end

            if not validateParams(...) then
                return
            end

            if callback and type(callback) == "function" then
                callback(...)
            end
        end)
    end

    local function secured_AddEventHandler(eventName, callback)
        if isSystemEvent(eventName) then
            nativeAddEventHandler(eventName, callback)
            return
        end

        if isBlacklisted(eventName) then
            return
        end

        local secureEvent = getSecureEventName(eventName)

        nativeAddEventHandler(secureEvent, function(...)
            if not validateParams(...) then
                return
            end

            if callback and type(callback) == "function" then
                callback(...)
            end
        end)
    end

    TriggerServerEvent = secured_TriggerServerEvent
    TriggerEvent = secured_TriggerEvent
    RegisterNetEvent = secured_RegisterNetEvent
    AddEventHandler = secured_AddEventHandler
end

local function protectDebug()
    if debug then
        debug.getinfo = function()
            return {}
        end
        debug.getlocal = function()
            return nil
        end
        debug.getupvalue = function()
            return nil
        end
        debug.setupvalue = function()
            return nil
        end
        debug.setlocal = function()
            return nil
        end
        debug.traceback = function()
            return ""
        end
    end
end

protectDebug()

print("^2[Avresi PROTECTION] Event protection system active!^7")
print("^2[Avresi PROTECTION] All events encrypted and secured.^7")
