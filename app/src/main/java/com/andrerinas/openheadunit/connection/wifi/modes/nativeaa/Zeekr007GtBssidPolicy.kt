package com.andrerinas.openheadunit.connection.wifi.modes.nativeaa

/**
 * Narrow diagnostic test for Zeekr 007 GT with the SSID observed in the phone log.
 * Not a permanent solution: Wi-Fi hotspot MAC addresses can change after reboot.
 */
internal object Zeekr007GtBssidPolicy {
    private const val TARGET_SSID = "ZEEKR-2211"
    private const val OBSERVED_PHONE_AP_BSSID = "56:C3:A2:9B:52:7D"

    fun selectForPhone(ssid: String, reportedBssid: String): String =
        if (ssid.equals(TARGET_SSID, ignoreCase = true)) {
            OBSERVED_PHONE_AP_BSSID
        } else {
            reportedBssid
        }
}
