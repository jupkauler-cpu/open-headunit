package com.andrerinas.openheadunit.connection.wifi.modes.nativeaa

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import java.net.ConnectException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NoRouteToHostException
import java.net.Socket
import java.net.SocketTimeoutException

/**
 * Read-only reachability and route diagnostics for the Zeekr hotspot gateway.
 *
 * A hotspot may be hosted in a separate Linux network namespace or modem service
 * and hence be invisible to the app's NetworkInterface enumeration.
 * This probe checks routes visible through Android's public ConnectivityManager API
 * and attempts a short TCP connection; a closed port is NOT a failed routing test.
 *
 * Does not retrieve credentials, change network settings or start any server.
 * Caller must run on Dispatchers.IO.
 */
internal object ZeekrGatewayRouteDiagnostics {
    fun inspect(context: Context, gateway: String): String {
        val target = try { InetAddress.getByName(gateway) } catch (e: Exception) {
            return "Gateway route diagnostics: invalid address ($gateway)"
        }
        return buildString {
            appendLine("=== GATEWAY ROUTE DIAGNOSTICS ===")
            appendLine("Test IP from current phone screenshot: $gateway")
            appendLine("No local interface with this IP was visible above.")
            appendLine("Route matching does NOT prove the phone can reach this app.")
            val cm = try {
                context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            } catch (e: Exception) {
                appendLine("ConnectivityManager unavailable: ${e.javaClass.simpleName}")
                return@buildString
            }
            try {
                val active = cm.activeNetwork
                appendLine("Default Android network: ${active ?: "(none)"}")
                val networks = cm.allNetworks.toList().sortedBy { it.toString() }
                appendLine("Android network objects visible: ${networks.size}")
                if (networks.isEmpty()) appendLine("(No Android networks exposed to app.)")
                for (network in networks) {
                    appendLine("--- Android network $network ---")
                    try {
                        val caps = cm.getNetworkCapabilities(network)
                        if (caps != null) {
                            val types = listOf(
                                NetworkCapabilities.TRANSPORT_WIFI to "WIFI",
                                NetworkCapabilities.TRANSPORT_CELLULAR to "CELLULAR",
                                NetworkCapabilities.TRANSPORT_ETHERNET to "ETHERNET",
                                NetworkCapabilities.TRANSPORT_VPN to "VPN",
                                NetworkCapabilities.TRANSPORT_BLUETOOTH to "BLUETOOTH"
                            ).filter { caps.hasTransport(it.first) }.map { it.second }
                            appendLine("  Transport: ${types.joinToString().ifBlank { "(other)" }}")
                        }
                        val lp = cm.getLinkProperties(network)
                        if (lp == null) {
                            appendLine("  LinkProperties: unavailable")
                        } else {
                            appendLine("  Interface: ${lp.interfaceName ?: "(unknown)"}")
                            appendLine("  IPs: ${lp.linkAddresses.joinToString().ifBlank { "(none)" }}")
                            if (lp.routes.isEmpty()) appendLine("  Routes: (none)")
                            for (route in lp.routes) {
                                val matches = try { route.destination.contains(target) } catch (_: Exception) { false }
                                appendLine("  ${if (matches) "[MATCH GATEWAY] " else ""}" +
                                    "Route ${route.destination} via ${route.gateway?.hostAddress ?: "-"} " +
                                    "(${route})")
                            }
                        }
                    } catch (e: Exception) {
                        appendLine("  Network details unavailable: ${e.javaClass.simpleName}")
                    }
                }
                appendLine("TCP route probes (closed ports are inconclusive):")
                appendLine("  System default -> $gateway:80 = ${probe(gateway, 80, null)}")
                appendLine("  System default -> $gateway:443 = ${probe(gateway, 443, null)}")
                // Check only Wi-Fi and ethernet networks to discover non-default routes.
                for (network in networks) {
                    val caps = try { cm.getNetworkCapabilities(network) } catch (_: Exception) { null }
                    if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true ||
                        caps?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true) {
                        appendLine("  Android $network -> $gateway:80 = ${probe(gateway, 80, network)}")
                    }
                }
            } catch (e: Exception) {
                appendLine("Route inspection failed: ${e.javaClass.simpleName}: ${e.message.orEmpty().take(90)}")
            }
            appendLine("Interpretation: a missing 192.168.225.x interface + no matching route")
            appendLine("suggests a separate Zeekr hotspot service/network namespace.")
            appendLine("Even a reachable gateway would not automatically make the")
            appendLine("head unit app reachable from the phone (incoming WPP/TCP).")
        }
    }

    private fun probe(host: String, port: Int, network: Network?): String {
        return try {
            val sock: Socket = network?.socketFactory?.createSocket() ?: Socket()
            sock.use { it.connect(InetSocketAddress(host, port), 650) }
            "CONNECTED (TCP port open)"
        } catch (e: NoRouteToHostException) {
            "NO ROUTE (${e.message.orEmpty().take(45)})"
        } catch (e: SocketTimeoutException) {
            "TIMEOUT (inconclusive)"
        } catch (e: ConnectException) {
            "REFUSED/UNREACHABLE (${e.message.orEmpty().take(45)}); routing inconclusive"
        } catch (e: SecurityException) {
            "PERMISSION DENIED"
        } catch (e: Exception) {
            "${e.javaClass.simpleName} (${e.message.orEmpty().take(45)})"
        }
    }
}
