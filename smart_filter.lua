-- smart_filter.lua - SharkBot v1.8 Wireshark launcher with packet-context handoff
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

local function json_encode(value)
    local value_type = type(value)
    if value_type == "table" then
        local parts = {}
        for key, item in pairs(value) do
            parts[#parts + 1] = '"' .. json_escape(key) .. '":' .. json_encode(item)
        end
        return "{" .. table.concat(parts, ",") .. "}"
    end
    if value_type == "boolean" then
        return value and "true" or "false"
    end
    return '"' .. json_escape(value) .. '"'
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
    local payload = {
        context = {
            payload_version = "1.8.0",
            context_schema = "protocol_native_v1",
            launch_source = ctx.launch_source or "",
            frame_number = ctx.frame_number or "",
            current_filter = ctx.current_filter or "",
            frame_protocols = ctx.frame_protocols or "",
            protocol_hint = ctx.protocol_hint or "",
            protocol_identity = ctx.protocol_identity or "",
            highest_protocol = ctx.highest_protocol or "",
            selected_ip = ctx.selected_ip or "",
            selected_ipv6 = ctx.selected_ipv6 or "",
            selected_mac = ctx.selected_mac or "",
            eth_src = ctx.eth_src or "",
            eth_dst = ctx.eth_dst or "",
            ip_src = ctx.ip_src or "",
            ip_dst = ctx.ip_dst or "",
            ipv6_src = ctx.ipv6_src or "",
            ipv6_dst = ctx.ipv6_dst or "",
            tcp_srcport = ctx.tcp_srcport or "",
            tcp_dstport = ctx.tcp_dstport or "",
            udp_srcport = ctx.udp_srcport or "",
            udp_dstport = ctx.udp_dstport or "",
            tcp_stream = ctx.tcp_stream or "",
            tcp_flags = ctx.tcp_flags or "",
            tcp_expert = ctx.tcp_expert or "",
            dns_name = ctx.dns_name or "",
            dns_query_type = ctx.dns_query_type or "",
            dns_response_code = ctx.dns_response_code or "",
            dns_answer_count = ctx.dns_answer_count or "",
            http_host = ctx.http_host or "",
            http_method = ctx.http_method or "",
            http_request_uri = ctx.http_request_uri or "",
            http_response_code = ctx.http_response_code or "",
            tls_sni = ctx.tls_sni or "",
            tls_handshake_type = ctx.tls_handshake_type or "",
            tls_record_version = ctx.tls_record_version or "",
            icmp_type = ctx.icmp_type or "",
            icmp_code = ctx.icmp_code or "",
            arp_opcode = ctx.arp_opcode or "",
            arp_src_proto_ipv4 = ctx.arp_src_proto_ipv4 or "",
            arp_dst_proto_ipv4 = ctx.arp_dst_proto_ipv4 or "",
            arp_src_hw_mac = ctx.arp_src_hw_mac or "",
            arp_dst_hw_mac = ctx.arp_dst_hw_mac or "",
            wlan_sa = ctx.wlan_sa or "",
            wlan_da = ctx.wlan_da or "",
            wlan_ra = ctx.wlan_ra or "",
            wlan_ta = ctx.wlan_ta or "",
	            wlan_bssid = ctx.wlan_bssid or "",
	            wlan_ssid = ctx.wlan_ssid or "",
	            wlan_type_subtype = ctx.wlan_type_subtype or "",
	            wlan_channel = ctx.wlan_channel or "",
	            wlan_signal_dbm = ctx.wlan_signal_dbm or "",
	            wlan_data_rate = ctx.wlan_data_rate or "",
	            btcommon_addr = ctx.btcommon_addr or "",
            btatt_opcode = ctx.btatt_opcode or "",
            btatt_handle = ctx.btatt_handle or "",
            btl2cap_cid = ctx.btl2cap_cid or "",
            protocol_details = {
                tcp = {
                    srcport = ctx.tcp_srcport or "",
                    dstport = ctx.tcp_dstport or "",
                    stream = ctx.tcp_stream or "",
                    flags = ctx.tcp_flags or "",
                    expert = ctx.tcp_expert or "",
                },
                udp = {
                    srcport = ctx.udp_srcport or "",
                    dstport = ctx.udp_dstport or "",
                },
                dns = {
                    query_name = ctx.dns_name or "",
                    query_type = ctx.dns_query_type or "",
                    response_code = ctx.dns_response_code or "",
                    answer_count = ctx.dns_answer_count or "",
                },
                http = {
                    host = ctx.http_host or "",
                    method = ctx.http_method or "",
                    request_uri = ctx.http_request_uri or "",
                    response_code = ctx.http_response_code or "",
                },
                tls = {
                    server_name = ctx.tls_sni or "",
                    handshake_type = ctx.tls_handshake_type or "",
                    record_version = ctx.tls_record_version or "",
                },
                icmp = {
                    type = ctx.icmp_type or "",
                    code = ctx.icmp_code or "",
                },
                arp = {
                    opcode = ctx.arp_opcode or "",
                    src_proto_ipv4 = ctx.arp_src_proto_ipv4 or "",
                    dst_proto_ipv4 = ctx.arp_dst_proto_ipv4 or "",
                    src_hw_mac = ctx.arp_src_hw_mac or "",
                    dst_hw_mac = ctx.arp_dst_hw_mac or "",
                },
                wlan = {
                    sa = ctx.wlan_sa or "",
                    da = ctx.wlan_da or "",
                    ra = ctx.wlan_ra or "",
                    ta = ctx.wlan_ta or "",
	                    bssid = ctx.wlan_bssid or "",
	                    ssid = ctx.wlan_ssid or "",
	                    type_subtype = ctx.wlan_type_subtype or "",
	                    channel = ctx.wlan_channel or "",
	                    signal_dbm = ctx.wlan_signal_dbm or "",
	                    data_rate = ctx.wlan_data_rate or "",
	                },
                btle = {
                    address = ctx.btcommon_addr or "",
                    att_opcode = ctx.btatt_opcode or "",
                    att_handle = ctx.btatt_handle or "",
                    l2cap_cid = ctx.btl2cap_cid or "",
                },
            },
        },
    }
    return json_encode(payload)
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
    ["frame.protocols"] = "frame_protocols",
    ["eth.src"] = "eth_src",
    ["eth.dst"] = "eth_dst",
    ["eth.addr"] = "selected_mac",
    ["wlan.sa"] = "wlan_sa",
    ["wlan.da"] = "wlan_da",
    ["wlan.ra"] = "wlan_ra",
    ["wlan.ta"] = "wlan_ta",
    ["wlan.bssid"] = "wlan_bssid",
    ["wlan.ssid"] = "wlan_ssid",
    ["wlan.fc.type_subtype"] = "wlan_type_subtype",
    ["wlan_radio.channel"] = "wlan_channel",
    ["wlan_radio.signal_dbm"] = "wlan_signal_dbm",
    ["wlan_radio.data_rate"] = "wlan_data_rate",
    ["wlan.addr"] = "selected_mac",
    ["ip.src"] = "ip_src",
    ["ip.dst"] = "ip_dst",
    ["ip.addr"] = "selected_ip",
    ["ipv6.src"] = "ipv6_src",
    ["ipv6.dst"] = "ipv6_dst",
    ["ipv6.addr"] = "selected_ipv6",
    ["tcp.srcport"] = "tcp_srcport",
    ["tcp.dstport"] = "tcp_dstport",
    ["tcp.stream"] = "tcp_stream",
    ["tcp.flags.str"] = "tcp_flags",
    ["_ws.expert.message"] = "tcp_expert",
    ["udp.srcport"] = "udp_srcport",
    ["udp.dstport"] = "udp_dstport",
    ["http.host"] = "http_host",
    ["http.request.method"] = "http_method",
    ["http.request.uri"] = "http_request_uri",
    ["http.response.code"] = "http_response_code",
    ["dns.qry.name"] = "dns_name",
    ["dns.qry.type"] = "dns_query_type",
    ["dns.flags.rcode"] = "dns_response_code",
    ["dns.count.answers"] = "dns_answer_count",
    ["tls.handshake.extensions_server_name"] = "tls_sni",
    ["tls.handshake.type"] = "tls_handshake_type",
    ["tls.record.version"] = "tls_record_version",
    ["icmp.type"] = "icmp_type",
    ["icmp.code"] = "icmp_code",
    ["arp.opcode"] = "arp_opcode",
    ["arp.src.proto_ipv4"] = "arp_src_proto_ipv4",
    ["arp.dst.proto_ipv4"] = "arp_dst_proto_ipv4",
    ["arp.src.hw_mac"] = "arp_src_hw_mac",
    ["arp.dst.hw_mac"] = "arp_dst_hw_mac",
    ["btcommon.addr"] = "btcommon_addr",
    ["btatt.opcode"] = "btatt_opcode",
    ["btatt.handle"] = "btatt_handle",
    ["btl2cap.cid"] = "btl2cap_cid",
}

local function infer_protocol_identity(ctx)
    local frame_protocols = tostring(ctx.frame_protocols or ""):lower()
    if ctx.dns_name or ctx.dns_query_type or frame_protocols:match("dns") then
        return "dns"
    end
    if ctx.http_host or ctx.http_method or ctx.http_request_uri or ctx.http_response_code or frame_protocols:match("http") then
        return "http"
    end
    if ctx.tls_sni or ctx.tls_handshake_type or ctx.tls_record_version or frame_protocols:match("tls") then
        return "tls"
    end
    if ctx.wlan_sa or ctx.wlan_da or ctx.wlan_bssid or ctx.wlan_ssid or frame_protocols:match("wlan") or frame_protocols:match("802%.11") then
        return "wlan"
    end
    if ctx.btcommon_addr or ctx.btatt_opcode or ctx.btl2cap_cid or frame_protocols:match("bt") then
        return "btle"
    end
    if ctx.arp_opcode or ctx.arp_src_proto_ipv4 or ctx.arp_dst_proto_ipv4 or frame_protocols:match("arp") then
        return "arp"
    end
    if ctx.icmp_type or ctx.icmp_code or frame_protocols:match("icmp") then
        return "icmp"
    end
    if ctx.tcp_srcport or ctx.tcp_dstport or ctx.tcp_stream or frame_protocols:match("tcp") then
        return "tcp"
    end
    if ctx.udp_srcport or ctx.udp_dstport or frame_protocols:match("udp") then
        return "udp"
    end
    if ctx.ipv6_src or ctx.ipv6_dst or frame_protocols:match("ipv6") then
        return "ipv6"
    end
    if ctx.ip_src or ctx.ip_dst or frame_protocols:match("ip") then
        return "ip"
    end
    if ctx.eth_src or ctx.eth_dst then
        return "ethernet"
    end
    return ctx.protocol_hint or ""
end

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
    if ctx.wlan_sa ~= "" and not ctx.selected_mac then
        ctx.selected_mac = ctx.wlan_sa
    end
    if ctx.wlan_ta ~= "" and not ctx.selected_mac then
        ctx.selected_mac = ctx.wlan_ta
    end
    if ctx.btcommon_addr ~= "" and not ctx.selected_mac then
        ctx.selected_mac = ctx.btcommon_addr
    end
    if ctx.eth_src ~= "" and not ctx.selected_mac then
        ctx.selected_mac = ctx.eth_src
    end

    if ctx.wlan_sa or ctx.wlan_da or ctx.wlan_ra or ctx.wlan_ta or ctx.wlan_bssid then
        ctx.eth_src = ctx.eth_src or ctx.wlan_sa or ctx.wlan_ta or ""
        ctx.eth_dst = ctx.eth_dst or ctx.wlan_da or ctx.wlan_ra or ""
        ctx.protocol_hint = "wlan"
    elseif ctx.btcommon_addr then
        ctx.protocol_hint = "btle"
    elseif ctx.ip_src or ctx.ip_dst then
        ctx.protocol_hint = "ip"
    elseif ctx.ipv6_src or ctx.ipv6_dst then
        ctx.protocol_hint = "ipv6"
    elseif ctx.eth_src or ctx.eth_dst then
        ctx.protocol_hint = "ethernet"
    end
    ctx.protocol_identity = infer_protocol_identity(ctx)
    ctx.highest_protocol = ctx.protocol_identity

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
