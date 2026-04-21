-- smart_filter.lua - SharkBot v1.7.2 Wireshark launcher with packet-context handoff
--
-- Receiver config:
-- Edit RECEIVER_BASE below to point at your receiver.
-- Example: "http://192.168.1.50:8765"
-- Do not use 0.0.0.0 here; that is only valid as a server bind address.
-- Environment variable SMART_FILTER_RECEIVER still overrides this if set.

if not gui_enabled() then
    return
end

local RECEIVER_BASE = os.getenv("SMART_FILTER_RECEIVER") or "http://127.0.0.1:8765"
local LAST_SESSION_ID = ""

local function json_escape(s)
    s = tostring(s or "")
    s = s:gsub("\\", "\\\\")
    s = s:gsub('"', '\\"')
    s = s:gsub("\n", "\\n")
    s = s:gsub("\r", "")
    return s
end

local function shell_quote_single(s)
    return "'" .. tostring(s):gsub("'", "'\\''") .. "'"
end

local function detect_open_command(url)
    if package.config:sub(1,1) == "\\" then
        return 'start "" "' .. url .. '"'
    end
    return 'open "' .. url .. '" >/dev/null 2>&1 &'
end

local function extract_web_url(body)
    local web_url = body:match('"web_url"%s*:%s*"([^"]+)"')
    if web_url then
        web_url = web_url:gsub('\\/', '/')
    end
    return web_url
end

local function extract_session_id(body)
    return body:match('"session_id"%s*:%s*"([^"]+)"')
end

local function extract_message(body)
    return body:match('"message"%s*:%s*"([^"]+)"')
end

local function trim(s)
    return tostring(s or ""):gsub("^%s+", ""):gsub("%s+$", "")
end

local function browser_url_looks_unusable(url)
    if not url or url == "" then
        return true
    end
    return url:match("://127%.0%.0%.1[:/]") or url:match("://0%.0%.0%.0[:/]")
end

local function build_browser_url(body)
    local web_url = extract_web_url(body)
    if web_url and not browser_url_looks_unusable(web_url) then
        return web_url
    end

    local session_id = extract_session_id(body)
    if session_id then
        return RECEIVER_BASE:gsub("/+$", "") .. "/session/" .. session_id
    end
    return web_url
end

local function receiver_post(path, payload)
    local cmd = "curl -sS -X POST " .. shell_quote_single(RECEIVER_BASE .. path) ..
        " -H 'Content-Type: application/json' --data-binary " .. shell_quote_single(payload) ..
        " -w " .. shell_quote_single("\n__STATUS__:%{http_code}") .. " 2>&1"

    local pipe = io.popen(cmd)
    if not pipe then
        return nil, nil, "Unable to call curl."
    end

    local raw = pipe:read("*a") or ""
    pipe:close()

    local status = raw:match("\n__STATUS__:(%d%d%d)%s*$")
    if not status then
        return nil, nil, trim(raw) ~= "" and trim(raw) or "Receiver did not return a valid HTTP response."
    end
    local body = raw:gsub("\n__STATUS__:%d%d%d%s*$", "")
    return body, tonumber(status), nil
end

local function remember_session_id(body)
    local session_id = extract_session_id(body)
    if session_id and session_id ~= "" then
        LAST_SESSION_ID = session_id
    end
    return session_id
end

local function open_investigation_from_body(body)
    local web_url = build_browser_url(body)
    if not web_url then
        new_dialog("SharkBot Error", function() end, "Receiver did not return a browser URL. Make sure the receiver is running.")
        return
    end
    remember_session_id(body)
    os.execute(detect_open_command(web_url))
end

local function maybe_get_filter()
    local ok, value = pcall(get_filter)
    if ok and value then
        return tostring(value)
    end
    return ""
end

local function field_value_to_string(fi)
    if fi == nil then
        return nil
    end

    local ok, value = pcall(function() return tostring(fi) end)
    if ok and value and value ~= "" then
        return value
    end

    ok, value = pcall(function() return tostring(fi.display) end)
    if ok and value and value ~= "" then
        return value
    end

    ok, value = pcall(function() return tostring(fi.label) end)
    if ok and value and value ~= "" then
        return value
    end

    ok, value = pcall(function() return tostring(fi.value) end)
    if ok and value and value ~= "" then
        return value
    end

    return nil
end

local function build_context_json(ctx)
    return '{' ..
        '"context":{' ..
            '"launch_source":"' .. json_escape(ctx.launch_source or "") .. '",' ..
            '"frame_number":"' .. json_escape(ctx.frame_number or "") .. '",' ..
            '"current_filter":"' .. json_escape(ctx.current_filter or "") .. '",' ..
            '"selected_ip":"' .. json_escape(ctx.selected_ip or "") .. '",' ..
            '"selected_ipv6":"' .. json_escape(ctx.selected_ipv6 or "") .. '",' ..
            '"selected_mac":"' .. json_escape(ctx.selected_mac or "") .. '",' ..
            '"eth_src":"' .. json_escape(ctx.eth_src or "") .. '",' ..
            '"eth_dst":"' .. json_escape(ctx.eth_dst or "") .. '",' ..
            '"ip_src":"' .. json_escape(ctx.ip_src or "") .. '",' ..
            '"ip_dst":"' .. json_escape(ctx.ip_dst or "") .. '",' ..
            '"ipv6_src":"' .. json_escape(ctx.ipv6_src or "") .. '",' ..
            '"ipv6_dst":"' .. json_escape(ctx.ipv6_dst or "") .. '",' ..
            '"tcp_srcport":"' .. json_escape(ctx.tcp_srcport or "") .. '",' ..
            '"tcp_dstport":"' .. json_escape(ctx.tcp_dstport or "") .. '",' ..
            '"udp_srcport":"' .. json_escape(ctx.udp_srcport or "") .. '",' ..
            '"udp_dstport":"' .. json_escape(ctx.udp_dstport or "") .. '",' ..
            '"http_host":"' .. json_escape(ctx.http_host or "") .. '",' ..
            '"dns_name":"' .. json_escape(ctx.dns_name or "") .. '",' ..
            '"protocol_hint":"' .. json_escape(ctx.protocol_hint or "") .. '"' ..
        '}' ..
    '}'
end

local function launch_new_investigation(ctx)
    local payload = build_context_json(ctx)
    local body, status, err = receiver_post("/api/session", payload)
    if err then
        new_dialog("SharkBot Error", function() end, err)
        return
    end
    if not status or status < 200 or status >= 300 then
        local message = extract_message(body) or "Receiver rejected the new investigation request."
        new_dialog("SharkBot Error", function() end, message)
        return
    end
    open_investigation_from_body(body)
end

local function continue_investigation(session_id, ctx)
    local clean_session_id = trim(session_id)
    if clean_session_id == "" then
        new_dialog("SharkBot Error", function() end, "A session ID is required to continue an investigation.")
        return
    end
    local payload = build_context_json(ctx)
    local body, status, err = receiver_post("/api/session/" .. clean_session_id .. "/context", payload)
    if err then
        new_dialog("SharkBot Error", function() end, err)
        return
    end
    if not status or status < 200 or status >= 300 then
        local message = extract_message(body) or "That investigation session was not found on the receiver."
        new_dialog("SharkBot Error", function() end, message)
        return
    end
    LAST_SESSION_ID = clean_session_id
    open_investigation_from_body(body)
end

local function prompt_for_session_id_and_continue(ctx)
    new_dialog("Continue SharkBot Investigation", function(session_id)
        session_id = trim(session_id)
        if session_id == "" then
            return
        end
        continue_investigation(session_id, ctx)
    end, "Session ID")
end

local interested_fields = {
    ["frame.number"] = "frame_number",
    ["eth.src"] = "eth_src",
    ["eth.dst"] = "eth_dst",
    ["eth.addr"] = "selected_mac",
    ["wlan.sa"] = "eth_src",
    ["wlan.da"] = "eth_dst",
    ["wlan.addr"] = "selected_mac",
    ["ip.src"] = "ip_src",
    ["ip.dst"] = "ip_dst",
    ["ip.addr"] = "selected_ip",
    ["ipv6.src"] = "ipv6_src",
    ["ipv6.dst"] = "ipv6_dst",
    ["ipv6.addr"] = "selected_ipv6",
    ["tcp.srcport"] = "tcp_srcport",
    ["tcp.dstport"] = "tcp_dstport",
    ["udp.srcport"] = "udp_srcport",
    ["udp.dstport"] = "udp_dstport",
    ["http.host"] = "http_host",
    ["dns.qry.name"] = "dns_name",
    ["btcommon.addr"] = "selected_mac",
}

local function base_context(launch_source)
    return {
        launch_source = launch_source,
        current_filter = maybe_get_filter(),
    }
end

local function launch_from_tools_menu()
    launch_new_investigation(base_context("tools_menu"))
end

local function continue_from_tools_menu()
    local ctx = base_context("tools_menu_continue")
    if LAST_SESSION_ID ~= "" then
        continue_investigation(LAST_SESSION_ID, ctx)
        return
    end
    prompt_for_session_id_and_continue(ctx)
end

local function continue_from_tools_menu_by_id()
    prompt_for_session_id_and_continue(base_context("tools_menu_continue"))
end

local function collect_packet_context(...)
    local ctx = {
        launch_source = "packet_menu",
        current_filter = maybe_get_filter(),
    }

    for _, fi in ipairs({...}) do
        local ok_name, field_name = pcall(function() return fi.name end)
        if ok_name and field_name and interested_fields[field_name] then
            local key = interested_fields[field_name]
            if not ctx[key] or ctx[key] == "" then
                local value = field_value_to_string(fi)
                if value and value ~= "" then
                    ctx[key] = value
                end
            end
        end
    end

    if ctx.ip_src ~= "" and not ctx.selected_ip then
        ctx.selected_ip = ctx.ip_src
    end
    if ctx.ipv6_src ~= "" and not ctx.selected_ipv6 then
        ctx.selected_ipv6 = ctx.ipv6_src
    end
    if ctx.eth_src ~= "" and not ctx.selected_mac then
        ctx.selected_mac = ctx.eth_src
    end

    if ctx.ip_src or ctx.ip_dst then
        ctx.protocol_hint = "ip"
    elseif ctx.ipv6_src or ctx.ipv6_dst then
        ctx.protocol_hint = "ipv6"
    elseif ctx.eth_src or ctx.eth_dst then
        ctx.protocol_hint = "ethernet"
    end

    return ctx
end

local function packet_menu_new_callback(...)
    launch_new_investigation(collect_packet_context(...))
end

local function packet_menu_continue_callback(...)
    local ctx = collect_packet_context(...)
    ctx.launch_source = "packet_menu_continue"
    if LAST_SESSION_ID ~= "" then
        continue_investigation(LAST_SESSION_ID, ctx)
        return
    end
    prompt_for_session_id_and_continue(ctx)
end

local function packet_menu_continue_by_id_callback(...)
    local ctx = collect_packet_context(...)
    ctx.launch_source = "packet_menu_continue"
    prompt_for_session_id_and_continue(ctx)
end

register_menu("Tools/SharkBot/New Investigation", launch_from_tools_menu, MENU_TOOLS_UNSORTED)
register_menu("Tools/SharkBot/Continue Current Investigation", continue_from_tools_menu, MENU_TOOLS_UNSORTED)
register_menu("Tools/SharkBot/Continue Investigation by ID", continue_from_tools_menu_by_id, MENU_TOOLS_UNSORTED)
register_packet_menu("SharkBot: New Investigation", packet_menu_new_callback)
register_packet_menu("SharkBot: Continue Current Investigation", packet_menu_continue_callback)
register_packet_menu("SharkBot: Continue Investigation by ID", packet_menu_continue_by_id_callback)
