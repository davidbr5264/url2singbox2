
// Simplified app.js for Config Forge
document.addEventListener('DOMContentLoaded', () => {
    const btnGenerate = document.getElementById('btnGenerate');
    const btnCopy = document.getElementById('btnCopy');
    const vlessUri = document.getElementById('vlessUri');
    const outputSection = document.getElementById('outputSection');
    const configOutput = document.getElementById('configOutput');

    btnGenerate.addEventListener('click', () => {
        const uri = vlessUri.value.trim();
        if (!uri.startsWith('vless://')) {
            alert('Please enter a valid vless:// URI');
            return;
        }

        try {
            const config = generateConfig(uri);
            configOutput.value = JSON.stringify(config, null, 2);
            outputSection.style.display = 'flex';
        } catch (e) {
            alert('Error parsing URI: ' + e.message);
        }
    });

    btnCopy.addEventListener('click', () => {
        configOutput.select();
        document.execCommand('copy');
        
        const originalText = btnCopy.textContent;
        btnCopy.textContent = 'Copied!';
        setTimeout(() => {
            btnCopy.textContent = originalText;
        }, 2000);
    });
});

function parseVless(uri) {
    // Basic parser for vless://uuid@server:port?params#name
    const parsed = new URL(uri);
    const uuid = parsed.username;
    const server = parsed.hostname;
    const port = parseInt(parsed.port);
    const name = decodeURIComponent(parsed.hash.substring(1));
    
    const params = {};
    for (const [key, value] of parsed.searchParams.entries()) {
        params[key] = value;
    }
    
    return { uuid, server, port, name, params };
}

function generateConfig(uri) {
    const vless = parseVless(uri);
    
    const blockQuic = document.getElementById('optBlockQuic').checked;
    const strictRoute = document.getElementById('optStrictRoute').checked;
    const blockIpv6 = document.getElementById('optBlockIpv6').checked;

    // Build the outbounds
    const vlessOutbound = {
        type: "vless",
        tag: "proxy",
        server: vless.server,
        server_port: vless.port,
        uuid: vless.uuid,
        packet_encoding: vless.params.packetEncoding || "xudp"
    };

    // Add transport
    if (vless.params.type) {
        vlessOutbound.transport = { type: vless.params.type };
        if (vless.params.type === 'ws') {
            vlessOutbound.transport.path = vless.params.path || "/";
            if (vless.params.host) {
                vlessOutbound.transport.headers = { Host: vless.params.host };
            }
        }
        if (vless.params.type === 'grpc') {
            vlessOutbound.transport.service_name = vless.params.serviceName || "";
        }
    }

    // Add TLS
    if (vless.params.security === 'tls' || vless.params.security === 'reality') {
        vlessOutbound.tls = {
            enabled: true,
            server_name: vless.params.sni || vless.server
        };
        if (vless.params.security === 'reality') {
            vlessOutbound.tls.reality = {
                enabled: true,
                public_key: vless.params.pbk,
                short_id: vless.params.sid || ""
            };
            if (vless.params.fp) {
                vlessOutbound.tls.utls = {
                    enabled: true,
                    fingerprint: vless.params.fp
                };
            }
        } else if (vless.params.fp) {
             vlessOutbound.tls.utls = {
                enabled: true,
                fingerprint: vless.params.fp
            };
        }
    }

    const outbounds = [
        vlessOutbound,
        { type: "direct", tag: "direct" },
        { type: "block", tag: "block" },
        { type: "dns", tag: "dns-out" }
    ];

    // Build routes
    const rules = [
        { protocol: "dns", outbound: "dns-out" }
    ];

    if (blockIpv6) {
         rules.push({ ip_version: 6, outbound: "block" });
    }
    
    if (blockQuic) {
        rules.push({ network: "udp", port: 443, outbound: "block" });
    }
    
    // Default bypass rules
    rules.push({
        ip_is_private: true,
        outbound: "direct"
    });
    
    // Core config structure
    const config = {
        log: {
            level: "info",
            timestamp: true
        },
        dns: {
            servers: [
                {
                    tag: "remote",
                    address: "https://1.1.1.1/dns-query",
                    detour: "proxy"
                },
                {
                    tag: "local",
                    address: "local",
                    detour: "direct"
                }
            ],
            rules: [
                { outbound: "any", server: "local" },
                { rule_set: "geosite-cn", server: "local" },
            ],
            final: "remote",
            independent_cache: true
        },
        inbounds: [
            {
                type: "tun",
                tag: "tun-in",
                interface_name: "singbox_tun",
                inet4_address: "172.18.0.1/30",
                mtu: 9000,
                auto_route: true,
                strict_route: strictRoute,
                stack: "system",
                sniff: true
            },
            {
                type: "mixed",
                tag: "mixed-in",
                listen: "127.0.0.1",
                listen_port: 10808
            }
        ],
        outbounds: outbounds,
        route: {
            rules: rules,
            auto_detect_interface: true,
            final: "proxy"
        },
        experimental: {
            clash_api: {
                external_controller: "127.0.0.1:9090",
                external_ui: "dashboard"
            }
        }
    };

    return config;
}
