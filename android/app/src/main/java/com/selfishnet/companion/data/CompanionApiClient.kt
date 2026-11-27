package com.selfishnet.companion.data

import com.selfishnet.companion.model.NetworkDevice
import com.selfishnet.companion.model.PairingConfig
import com.selfishnet.companion.model.StatusSnapshot
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL

class CompanionApiClient(private val config: PairingConfig) {

    private suspend fun request(method: String, path: String, body: JSONObject? = null): JSONObject =
        withContext(Dispatchers.IO) {
            val conn = (URL("${config.baseUrl}$path").openConnection() as HttpURLConnection).apply {
                requestMethod = method
                connectTimeout = 5000
                readTimeout = 8000
                setRequestProperty("Authorization", "Bearer ${config.token}")
                setRequestProperty("Accept", "application/json")
                if (body != null) {
                    doOutput = true
                    setRequestProperty("Content-Type", "application/json; charset=utf-8")
                }
            }
            try {
                if (body != null) {
                    OutputStreamWriter(conn.outputStream, Charsets.UTF_8).use { writer ->
                        writer.write(body.toString())
                    }
                }
                val stream = if (conn.responseCode in 200..299) conn.inputStream else conn.errorStream
                val text = stream?.use { s ->
                    BufferedReader(InputStreamReader(s, Charsets.UTF_8)).readText()
                } ?: "{}"
                val json = JSONObject(text)
                if (conn.responseCode !in 200..299) {
                    throw IllegalStateException(json.optString("error", "HTTP ${conn.responseCode}"))
                }
                json
            } finally {
                conn.disconnect()
            }
        }

    suspend fun fetchStatus(): StatusSnapshot {
        val json = request("GET", "/api/v1/status")
        val targetMap = mutableMapOf<String, JSONObject>()
        val targetsArr = json.optJSONArray("targets")
        if (targetsArr != null) {
            for (i in 0 until targetsArr.length()) {
                val t = targetsArr.getJSONObject(i)
                targetMap[t.optString("ip")] = t
            }
        }

        val devices = mutableListOf<NetworkDevice>()
        val devArr = json.optJSONArray("devices")
        if (devArr != null) {
            for (i in 0 until devArr.length()) {
                val d = devArr.getJSONObject(i)
                val ip = d.optString("ip")
                val t = targetMap[ip]
                devices.add(
                    NetworkDevice(
                        ip = ip,
                        mac = d.optString("mac", "?"),
                        vendor = d.optString("vendor", ""),
                        alias = d.optString("alias", ""),
                        kbit = d.optDouble("kbit", 0.0),
                        upKbit = d.optDouble("up_kbit", 0.0),
                        downKbit = d.optDouble("down_kbit", 0.0),
                        packets = d.optInt("pkts", d.optInt("packets", 0)),
                        ageSec = d.optDouble("age", 0.0),
                        isSafe = d.optBoolean("is_safe", false),
                        mode = t?.optString("mode")?.takeIf { it.isNotBlank() },
                        limitRateKbit = if (t != null && !t.isNull("rate")) t.optInt("rate") else null,
                        remainingSec = if (t != null && !t.isNull("remaining_sec")) t.optInt("remaining_sec") else null,
                    )
                )
            }
        }

        val errors = mutableListOf<String>()
        val errArr = json.optJSONArray("errors")
        if (errArr != null) {
            for (i in 0 until errArr.length()) {
                errors.add(errArr.optString(i))
            }
        }

        return StatusSnapshot(
            iface = json.optString("iface", ""),
            myIp = json.optString("my_ip", ""),
            gateway = json.optString("gateway", ""),
            totalKbit = json.optDouble("total_kbit", 0.0),
            ipv6Active = json.optBoolean("ipv6_active", false),
            devices = devices,
            errors = errors,
        )
    }

    suspend fun rescan() = request("POST", "/api/v1/rescan", JSONObject())

    suspend fun freeAll() = request("POST", "/api/v1/free_all", JSONObject())

    suspend fun setMode(targets: String, mode: String, rateKbit: Int? = null, durationSec: Int? = null) {
        val body = JSONObject().apply {
            put("targets", targets)
            put("mode", mode)
            if (rateKbit != null) put("rate", rateKbit)
            if (durationSec != null && durationSec > 0) put("duration", durationSec)
        }
        request("POST", "/api/v1/set", body)
    }

    suspend fun safeAdd(target: String) =
        request("POST", "/api/v1/safe/add", JSONObject().put("target", target))

    suspend fun safeRemove(target: String) =
        request("POST", "/api/v1/safe/remove", JSONObject().put("target", target))

    suspend fun setAlias(target: String, name: String) =
        request("POST", "/api/v1/aliases/set", JSONObject().put("target", target).put("name", name))
}
