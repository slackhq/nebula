local nebula = Proto("nebula", "nebula")

local default_settings = {
    port      = 4242,
    all_ports = false,
}

nebula.prefs.port  = Pref.uint("Port number", default_settings.port, "The UDP port number for Nebula")
nebula.prefs.all_ports  = Pref.bool("All ports", default_settings.all_ports, "Assume nebula packets on any port, useful when dealing with hole punching")

local pf_version  = ProtoField.new("version", "nebula.version", ftypes.UINT8, nil, base.DEC, 0xF0)
local pf_type     = ProtoField.new("type", "nebula.type", ftypes.UINT8, {
    [0] = "handshake",
    [1] = "message",
    [2] = "recvError",
    [3] = "lightHouse",
    [4] = "test",
    [5] = "closeTunnel",
}, base.DEC, 0x0F)

local pf_subtype = ProtoField.new("subtype", "nebula.subtype", ftypes.UINT8, nil, base.DEC)
local pf_subtype_test = ProtoField.new("subtype", "nebula.subtype", ftypes.UINT8, {
    [0] = "request",
    [1] = "reply",
}, base.DEC)

local pf_subtype_handshake = ProtoField.new("subtype", "nebula.subtype", ftypes.UINT8, {
    [0] = "ix_psk0",
}, base.DEC)

local pf_reserved        = ProtoField.new("reserved",     "nebula.reserved",     ftypes.UINT16, nil, base.HEX)
local pf_remote_index    = ProtoField.new("remote index", "nebula.remote_index", ftypes.UINT32, nil, base.DEC)
local pf_message_counter = ProtoField.new("counter",      "nebula.counter",      ftypes.UINT64, nil, base.DEC)
local pf_payload         = ProtoField.new("payload",      "nebula.payload",      ftypes.BYTES,  nil, base.NONE)

nebula.fields = { pf_version, pf_type, pf_subtype, pf_subtype_handshake, pf_subtype_test, pf_reserved, pf_remote_index, pf_message_counter, pf_payload }

local ef_holepunch = ProtoExpert.new("nebula.holepunch.expert", "Nebula hole punch packet", expert.group.PROTOCOL, expert.severity.NOTE)
local ef_punchy = ProtoExpert.new("nebula.punchy.expert", "Nebula punchy keepalive packet", expert.group.PROTOCOL, expert.severity.NOTE)

nebula.experts = { ef_holepunch, ef_punchy }
local type_field = Field.new("nebula.type")
local subtype_field = Field.new("nebula.subtype")

function nebula.dissector(tvbuf, pktinfo, root)
    -- set the protocol column to show our protocol name
    pktinfo.cols.protocol:set("NEBULA")

    local pktlen = tvbuf:reported_length_remaining()
    local tree = root:add(nebula, tvbuf:range(0,pktlen))

    if pktlen == 0 then
        tree:add_proto_expert_info(ef_holepunch)
        pktinfo.cols.info:append(" (holepunch)")
        return
    elseif pktlen == 1 then
        tree:add_proto_expert_info(ef_punchy)
        pktinfo.cols.info:append(" (punchy)")
        return
    end

    tree:add(pf_version, tvbuf:range(0,1))
    local type = tree:add(pf_type,    tvbuf:range(0,1))

    local nebula_type = bit32.band(tvbuf:range(0,1):uint(), 0x0F)
    if nebula_type == 0 then
        local stage = tvbuf(8,8):uint64()
        tree:add(pf_subtype_handshake, tvbuf:range(1,1))
        type:append_text(" stage " .. stage)
        pktinfo.cols.info:append(" (" .. type_field().display .. ", stage " .. stage .. ", " .. subtype_field().display .. ")")
    elseif nebula_type == 4 then
        tree:add(pf_subtype_test, tvbuf:range(1,1))
        pktinfo.cols.info:append(" (" .. type_field().display .. ", " .. subtype_field().display .. ")")
    else
        tree:add(pf_subtype, tvbuf:range(1,1))
        pktinfo.cols.info:append(" (" .. type_field().display .. ")")
    end

    tree:add(pf_reserved,        tvbuf:range(2,2))
    tree:add(pf_remote_index,    tvbuf:range(4,4))
    tree:add(pf_message_counter, tvbuf:range(8,8))
    tree:add(pf_payload,         tvbuf:range(16,tvbuf:len() - 16))
end

function nebula.prefs_changed()
    if default_settings.all_ports == nebula.prefs.all_ports and default_settings.port == nebula.prefs.port then
        -- Nothing changed, bail
        return
    end

    -- Remove our old dissector
    DissectorTable.get("udp.port"):remove_all(nebula)

    if nebula.prefs.all_ports and default_settings.all_ports ~= nebula.prefs.all_ports then
        default_settings.all_port = nebula.prefs.all_ports

        for i=0, 65535 do
            DissectorTable.get("udp.port"):add(i, nebula)
        end

        -- no need to establish again on specific ports
        return
    end


    if default_settings.all_ports ~= nebula.prefs.all_ports then
        -- Add our new port dissector
        default_settings.port = nebula.prefs.port
        DissectorTable.get("udp.port"):add(default_settings.port, nebula)
    end
end

DissectorTable.get("udp.port"):add(default_settings.port, nebula)
