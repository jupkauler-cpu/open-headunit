package com.andrerinas.openheadunit.connection.wifi.modes.nativeaa

import org.junit.Assert.assertEquals
import org.junit.Test

class Zeekr007GtBssidPolicyTest {
    @Test fun replacesObservedZeekrHotspot() {
        assertEquals("56:C3:A2:9B:52:7D",
            Zeekr007GtBssidPolicy.selectForPhone("ZEEKR-2211", "7A:75:99:03:CA:64"))
    }

    @Test fun preservesOtherNetworks() {
        assertEquals("12:34:56:78:9A:BC",
            Zeekr007GtBssidPolicy.selectForPhone("Home-WiFi", "12:34:56:78:9A:BC"))
    }

    @Test fun toleratesSsidCase() {
        assertEquals("56:C3:A2:9B:52:7D",
            Zeekr007GtBssidPolicy.selectForPhone("zeekr-2211", "7A:75:99:03:CA:64"))
    }
}
