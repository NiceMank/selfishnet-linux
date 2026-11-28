package com.mynetfilter.companion.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.mynetfilter.companion.data.CompanionApiClient
import com.mynetfilter.companion.model.NetworkDevice
import com.mynetfilter.companion.model.PairingConfig
import com.mynetfilter.companion.model.StatusSnapshot
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

private val BgDark = Color(0xFF0D1117)
private val SurfaceDark = Color(0xFF161B22)
private val AccentBlue = Color(0xFF2F81F7)
private val GreenOk = Color(0xFF3FB950)
private val YellowWarn = Color(0xFFD29922)
private val RedDanger = Color(0xFFF85149)
private val MutedText = Color(0xFF8B949E)

private val DarkPalette = darkColorScheme(
    primary = AccentBlue,
    background = BgDark,
    surface = SurfaceDark,
    onBackground = Color(0xFFE6EDF3),
    onSurface = Color(0xFFE6EDF3),
)

@Composable
fun MyNetFilterApp(initialPairingUri: String? = null) {
    MaterialTheme(colorScheme = DarkPalette) {
        var config by remember { mutableStateOf(initialPairingUri?.let { PairingConfig.fromUri(it) }) }

        Surface(modifier = Modifier.fillMaxSize(), color = BgDark) {
            if (config == null) {
                PairingScreen(
                    initialUri = initialPairingUri.orEmpty(),
                    onPaired = { config = it }
                )
            } else {
                DashboardScreen(
                    config = config!!,
                    onDisconnect = { config = null }
                )
            }
        }
    }
}

@Composable
private fun PairingScreen(initialUri: String, onPaired: (PairingConfig) -> Unit) {
    var uriText by remember { mutableStateOf(initialUri) }
    var errorMsg by remember { mutableStateOf<String?>(null) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        verticalArrangement = Arrangement.Center,
    ) {
        Text("MyNet Filter", fontSize = 26.sp, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(6.dp))
        Text(
            "Connectez ce téléphone à votre PC Linux ou Windows lançant MyNet Filter (--api-port 8443).",
            color = MutedText,
            fontSize = 14.sp,
        )
        Spacer(Modifier.height(20.dp))
        OutlinedTextField(
            value = uriText,
            onValueChange = { uriText = it; errorMsg = null },
            label = { Text("URI d'appairage (mynetfilter://pair?...)") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = false,
            maxLines = 4,
        )
        if (errorMsg != null) {
            Spacer(Modifier.height(8.dp))
            Text(errorMsg!!, color = RedDanger, fontSize = 13.sp)
        }
        Spacer(Modifier.height(16.dp))
        Button(
            onClick = {
                val parsed = PairingConfig.fromUri(uriText)
                if (parsed == null) {
                    errorMsg = "URI invalide. Exemple : mynetfilter://pair?host=192.168.1.10&port=8443&token=..."
                } else {
                    onPaired(parsed)
                }
            },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Se connecter au serveur")
        }
    }
}

@Composable
private fun DashboardScreen(config: PairingConfig, onDisconnect: () -> Unit) {
    val client = remember(config) { CompanionApiClient(config) }
    val scope = rememberCoroutineScope()
    var snapshot by remember { mutableStateOf<StatusSnapshot?>(null) }
    var statusBanner by remember { mutableStateOf("Connexion à ${config.host}:${config.port}...") }
    var filter by remember { mutableStateOf("all") }

    LaunchedEffect(config) {
        while (true) {
            try {
                snapshot = client.fetchStatus()
                statusBanner = "${config.name} · ${snapshot?.iface ?: ""}"
            } catch (exc: Exception) {
                statusBanner = "Erreur : ${exc.message}"
            }
            delay(2000)
        }
    }

    val devices = snapshot?.devices.orEmpty().filter { dev ->
        when (filter) {
            "restricted" -> dev.mode != null
            "safe" -> dev.isSafe
            "active" -> dev.kbit >= 1.0
            else -> true
        }
    }

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column {
                Text("MyNet Filter", fontSize = 20.sp, fontWeight = FontWeight.Bold)
                Text(statusBanner, fontSize = 12.sp, color = MutedText)
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { scope.launch { runCatching { client.rescan() } } }) {
                    Text("Scan")
                }
                TextButton(onClick = onDisconnect) {
                    Text("Déconnecter", color = MutedText)
                }
            }
        }

        Spacer(Modifier.height(12.dp))

        // Cartes KPI
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            KpiCard("Appareils", "${snapshot?.devices?.size ?: 0}", Modifier.weight(1f))
            KpiCard("Débit", formatRate(snapshot?.totalKbit ?: 0.0), Modifier.weight(1f), AccentBlue)
            val restrictedCount = snapshot?.devices?.count { it.mode != null } ?: 0
            KpiCard("Restreints", "$restrictedCount", Modifier.weight(1f), YellowWarn)
        }

        Spacer(Modifier.height(10.dp))

        // Actions globales rapides
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = { scope.launch { runCatching { client.setMode("local", "limit", 250) } } },
                modifier = Modifier.weight(1f),
            ) {
                Text("Mode Focus")
            }
            OutlinedButton(
                onClick = { scope.launch { runCatching { client.freeAll() } } },
                modifier = Modifier.weight(1f),
            ) {
                Text("Tout libérer", color = GreenOk)
            }
        }

        Spacer(Modifier.height(10.dp))

        // Filtres rapides
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            listOf("all" to "Tous", "active" to "Actifs", "restricted" to "Restreints", "safe" to "Protégés").forEach { (key, label) ->
                FilterChip(
                    selected = filter == key,
                    onClick = { filter = key },
                    label = { Text(label) },
                )
            }
        }

        Spacer(Modifier.height(8.dp))

        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            items(devices, key = { it.ip }) { dev ->
                DeviceCard(
                    device = dev,
                    onPause = { scope.launch { runCatching { client.setMode(dev.ip, "pause") } } },
                    onLimit = { scope.launch { runCatching { client.setMode(dev.ip, "limit", 500) } } },
                    onFree = { scope.launch { runCatching { client.setMode(dev.ip, "free") } } },
                    onToggleSafe = {
                        scope.launch {
                            runCatching {
                                if (dev.isSafe) client.safeRemove(dev.ip) else client.safeAdd(dev.ip)
                            }
                        }
                    },
                )
            }
        }
    }
}

@Composable
private fun KpiCard(title: String, value: String, modifier: Modifier = Modifier, valueColor: Color = Color(0xFFE6EDF3)) {
    Card(
        modifier = modifier,
        shape = RoundedCornerShape(10.dp),
        colors = CardDefaults.cardColors(containerColor = SurfaceDark),
    ) {
        Column(modifier = Modifier.padding(10.dp)) {
            Text(title, fontSize = 11.sp, color = MutedText)
            Text(value, fontSize = 17.sp, fontWeight = FontWeight.Bold, color = valueColor)
        }
    }
}

@Composable
private fun DeviceCard(
    device: NetworkDevice,
    onPause: () -> Unit,
    onLimit: () -> Unit,
    onFree: () -> Unit,
    onToggleSafe: () -> Unit,
) {
    val badgeColor = when {
        device.mode == "pause" -> RedDanger
        device.mode == "limit" -> YellowWarn
        device.isSafe -> GreenOk
        else -> MutedText
    }
    val statusText = when {
        device.mode == "pause" -> "Pause"
        device.mode == "limit" -> "Limité (${device.limitRateKbit ?: 500}k)"
        device.isSafe -> "Protégé"
        else -> "Normal"
    }

    Card(
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = SurfaceDark),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(device.displayName, fontWeight = FontWeight.SemiBold, fontSize = 15.sp)
                    Text("${device.ip} · ${device.mac}", fontSize = 12.sp, color = MutedText)
                }
                Column(horizontalAlignment = Alignment.End) {
                    Text(statusText, color = badgeColor, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                    Text(formatRate(device.kbit), fontSize = 12.sp, color = AccentBlue)
                }
            }
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                if (!device.isSafe) {
                    OutlinedButton(onClick = onPause, contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp)) {
                        Text("Pause", color = RedDanger, fontSize = 12.sp)
                    }
                    OutlinedButton(onClick = onLimit, contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp)) {
                        Text("500k", color = YellowWarn, fontSize = 12.sp)
                    }
                    if (device.mode != null) {
                        OutlinedButton(onClick = onFree, contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp)) {
                            Text("Libérer", color = GreenOk, fontSize = 12.sp)
                        }
                    }
                }
                Spacer(Modifier.weight(1f))
                TextButton(onClick = onToggleSafe) {
                    Text(if (device.isSafe) "Retirer Safe" else "Safe", fontSize = 12.sp, color = GreenOk)
                }
            }
        }
    }
}

private fun formatRate(kbit: Double): String =
    if (kbit >= 1000.0) String.format("%.1f Mb/s", kbit / 1000.0) else String.format("%.0f kb/s", kbit)
