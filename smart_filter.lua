-- smart_filter.lua - SharkBot v1.5.0 Wireshark launcher with packet-context handoff
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

local function launch_with_context(ctx)
    local payload = build_context_json(ctx)
    local cmd = "curl -s -X POST " .. shell_quote_single(RECEIVER_BASE .. "/api/session") ..
        " -H 'Content-Type: application/json' --data-binary " .. shell_quote_single(payload)

    local pipe = io.popen(cmd)
    if not pipe then
        new_dialog("Smart Filter Error", function() end, "Unable to call curl.")
        return
    end

    local body = pipe:read("*a") or ""
    pipe:close()

    local web_url = build_browser_url(body)
    if not web_url then
        new_dialog("Smart Filter Error", function() end, "Receiver did not return web_url. Make sure the receiver is running.")
        return
    end

    os.execute(detect_open_command(web_url))
end

local function launch_from_tools_menu()
    launch_with_context({
        launch_source = "tools_menu",
        current_filter = maybe_get_filter(),
    })
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

local function packet_menu_callback(...)
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

    launch_with_context(ctx)
end

register_menu("Tools/Smart Filter Assistant", launch_from_tools_menu, MENU_TOOLS_UNSORTED)
register_packet_menu("Smart Filter Assistant", packet_menu_callback)
