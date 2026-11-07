package com.andrerinas.openheadunit.connection.wifi.modes.nativeaa

import android.content.Context
import com.andrerinas.openheadunit.utils.InterfaceMacReader
import com.andrerinas.openheadunit.utils.NetworkAddresses
import com.andrerinas.openheadunit.utils.SoftApStateReader
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.NetworkInterface

/**
 * Read-only, on-screen diagnostics for dual-hotspot Zeekr head units.
 * Some OEM access points are invisible to ordinary Android applications.
 * No passwords, remote requests, or privileged system modifications.
 */
internal object ZeekrHotspotInterfaceDiagnostics {
    private const val PHONE_SSID = "ZEEKR-2211"
    private const val PHONE_BSSID = "56:C3:A2:9B:52:7D"
    private const val OTHER_AP_BSSID = "7A:75:99:03:CA:64"
    private const val PHONE_GATEWAY = "192.168.1.1"

    data class InterfaceRow(
        val name: String,
        val isUp: Boolean,
        val isLoopback: Boolean,
        val isVirtual: Boolean,
        val ipv4: List<String>,
        val ipv6: List<String>,
        val hardwareMac: String?,
        val sysfsMac: String?,
        val privateIpv4: String?
    ) {
        val selectable: Boolean get() = isUp && !isLoopback && privateIpv4 != null
    }

    data class Snapshot(val text: String, val interfaces: List<InterfaceRow>)

    fun collect(context: Context, selectedInterface: String, configuredSsid: String): Snapshot {
        val errors = mutableListOf<String>()
        val interfaces = try {
            (NetworkInterface.getNetworkInterfaces()?.toList() ?: emptyList()).map { iface ->
                val ipv4 = try {
                    iface.inetAddresses.toList().filterIsInstance<Inet4Address>()
                        .mapNotNull { it.hostAddress }.distinct()
                } catch (e: Exception) {
                    errors += "IPv4 ${iface.name}: ${e.javaClass.simpleName}"
                    emptyList()
                }
                val ipv6 = try {
                    iface.inetAddresses.toList().filterIsInstance<Inet6Address>()
                        .filter { it.isLinkLocalAddress }
                        .mapNotNull { it.hostAddress?.substringBefore('%') }.distinct()
                } catch (_: Exception) { emptyList() }
                val mac = try {
                    iface.hardwareAddress?.let { address ->
                        if (address.size != 6) null
                        else address.joinToString(":") { "%02X".format(it.toInt() and 0xff) }
                    }
                } catch (_: Exception) { null }
                InterfaceRow(
                    name = iface.name.orEmpty(),
                    isUp = try { iface.isUp } catch (_: Exception) { false },
                    isLoopback = try { iface.isLoopback } catch (_: Exception) { false },
                    isVirtual = try { iface.isVirtual } catch (_: Exception) { false },
                    ipv4 = ipv4, ipv6 = ipv6,
                    hardwareMac = mac,
                    sysfsMac = InterfaceMacReader.fromSysfs(iface.name),
                    privateIpv4 = ipv4.firstOrNull { ip ->
                        try { java.net.InetAddress.getByName(ip).isSiteLocalAddress }
                        catch (_: Exception) { false }
                    }
                )
            }.sortedBy { it.name }
        } catch (e: Exception) {
            errors += "Interface scan: ${e.javaClass.simpleName}"
            emptyList()
        }

        val stationIp = try { NetworkAddresses.stationIpv4(context) } catch (_: Exception) { null }
        val candidates = interfaces.map {
            ApInterfaceCandidate(it.name, it.isLoopback, it.isUp, it.privateIpv4)
        }
        val plausible = SoftApNetworkPolicy.eligible(candidates, stationIp)
        val automatic = SoftApNetworkPolicy.pickApInterface(candidates, stationIp)?.name
        val apState = try { SoftApStateReader.read(context).name } catch (_: Exception) { "UNKNOWN" }

        val report = buildString {
            appendLine("ZEEKR 007 GT - HOTSPOT DIAGNOSIS")
            appendLine("Read-only. No Wi-Fi password shown.")
            appendLine()
            appendLine("Phone log SSID: $PHONE_SSID")
            appendLine("Phone log BSSID: $PHONE_BSSID")
            appendLine("Other Zeekr AP / advertised BSSID: $OTHER_AP_BSSID")
            appendLine("Phone log car gateway: $PHONE_GATEWAY")
            appendLine("(These are historical log values, not measured again.)")
            appendLine()
            appendLine("Configured SSID: ${configuredSsid.ifBlank { "(automatic)" }}")
            appendLine("Manual interface: ${selectedInterface.ifBlank { "(automatic)" }}")
            appendLine("Android Soft AP state: $apState")
            appendLine("Station IPv4: ${stationIp ?: "(unavailable)"}")
            appendLine("Auto-picked interface: ${automatic ?: "(none)"}")
            appendLine("Possible APs: ${plausible.joinToString { it.name }.ifBlank { "(none)" }}")
            appendLine()
            if (interfaces.isEmpty()) appendLine("No interfaces visible to this app.")
            interfaces.forEach { row ->
                appendLine("--- ${row.name} ---")
                appendLine("  ${if (row.isUp) "UP" else "DOWN"}, loopback=${row.isLoopback}, virtual=${row.isVirtual}")
                appendLine("  IPv4: ${row.ipv4.joinToString().ifBlank { "(none)" }}")
                appendLine("  IPv6 link-local: ${row.ipv6.joinToString().ifBlank { "(none)" }}")
                appendLine("  MAC Java: ${row.hardwareMac ?: "(unavailable)"}")
                appendLine("  MAC sysfs: ${row.sysfsMac ?: "(unavailable)"}")
                if (row.name == automatic) appendLine("  [AUTO-PICKED]")
                if (row.name.equals(selectedInterface, true)) appendLine("  [MANUAL SETTING]")
                if (row.ipv4.contains(PHONE_GATEWAY)) appendLine("  [MATCHES CAR GATEWAY IP]")
                if (listOf(row.hardwareMac, row.sysfsMac).any { it.equals(PHONE_BSSID, true) })
                    appendLine("  [MAC MATCHES PHONE'S AP]")
                if (listOf(row.hardwareMac, row.sysfsMac).any { it.equals(OTHER_AP_BSSID, true) })
                    appendLine("  [MAC MATCHES OTHER ZEEKR AP]")
            }
            if (errors.isNotEmpty()) {
                appendLine("Read errors: ${errors.joinToString()}")
            }
            appendLine()
            appendLine("A virtual access point's BSSID can differ from the hardware MAC.")
            appendLine("Some OEM interfaces can be hidden. IP matches are clues, not proof.")
            appendLine("After selecting an interface, SAVE settings before reconnecting.")
        }
        return Snapshot(report, interfaces)
    }
}
