package com.selfishnet.companion.model

import android.net.Uri

data class PairingConfig(
    val host: String,
    val port: Int = 8443,
    val token: String,
    val name: String = "MyNet Filter",
) {
    val baseUrl: String get() = "http://$host:$port"

    companion object {
        fun fromUri(raw: String): PairingConfig? {
            val uri = Uri.parse(raw.trim())
            if (uri.scheme != "selfishnet" || uri.host != "pair") return null
            val host = uri.getQueryParameter("host")?.takeIf { it.isNotBlank() } ?: return null
            val token = uri.getQueryParameter("token")?.takeIf { it.isNotBlank() } ?: return null
            val port = uri.getQueryParameter("port")?.toIntOrNull() ?: 8443
            val name = uri.getQueryParameter("name") ?: "MyNet Filter"
            return PairingConfig(host = host, port = port, token = token, name = name)
        }
    }
}

data class NetworkDevice(
    val ip: String,
    val mac: String,
    val vendor: String,
    val alias: String,
    val kbit: Double,
    val upKbit: Double,
    val downKbit: Double,
    val packets: Int,
    val ageSec: Double,
    val isSafe: Boolean,
    val mode: String?,          // null, "pause", "limit"
    val limitRateKbit: Int?,
    val remainingSec: Int?,
) {
    val displayName: String
        get() = when {
            alias.isNotBlank() -> alias
            vendor.isNotBlank() -> vendor
            else -> ip
        }
}

data class StatusSnapshot(
    val iface: String,
    val myIp: String,
    val gateway: String,
    val totalKbit: Double,
    val ipv6Active: Boolean,
    val devices: List<NetworkDevice>,
    val errors: List<String>,
)
