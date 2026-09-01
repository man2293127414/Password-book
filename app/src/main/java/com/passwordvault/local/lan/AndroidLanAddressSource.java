package com.passwordvault.local.lan;

import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;

/** Resolves non-cellular IPv4 interfaces that a nearby browser can actually reach. */
final class AndroidLanAddressSource implements LanAddressGuard.CurrentAddresses {
    private final ConnectivityManager connectivityManager;

    AndroidLanAddressSource(ConnectivityManager connectivityManager) {
        if (connectivityManager == null) {
            throw new IllegalArgumentException("connectivityManager must not be null");
        }
        this.connectivityManager = connectivityManager;
    }

    @Override
    public Set<String> current() {
        Set<String> excludedInterfaces = excludedTransportInterfaces();
        Set<String> addresses = new TreeSet<String>();
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            if (interfaces == null) return Collections.emptySet();
            while (interfaces.hasMoreElements()) {
                NetworkInterface networkInterface = interfaces.nextElement();
                if (!isCandidateInterface(networkInterface, excludedInterfaces)) continue;
                Enumeration<InetAddress> interfaceAddresses = networkInterface.getInetAddresses();
                while (interfaceAddresses.hasMoreElements()) {
                    InetAddress address = interfaceAddresses.nextElement();
                    if (isReachableIpv4(address)) {
                        addresses.add(networkInterface.getName() + "/" + address.getHostAddress());
                    }
                }
            }
        } catch (SocketException | RuntimeException exception) {
            return Collections.emptySet();
        }
        return Collections.unmodifiableSet(addresses);
    }

    private Set<String> excludedTransportInterfaces() {
        Set<String> excluded = new HashSet<String>();
        try {
            for (Network network : connectivityManager.getAllNetworks()) {
                NetworkCapabilities capabilities = connectivityManager.getNetworkCapabilities(network);
                if (capabilities == null
                        || (!capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
                        && !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN))) {
                    continue;
                }
                LinkProperties properties = connectivityManager.getLinkProperties(network);
                if (properties != null && properties.getInterfaceName() != null) {
                    excluded.add(properties.getInterfaceName());
                }
            }
        } catch (RuntimeException ignored) {
            // Interface-name filtering below remains as a conservative fallback.
        }
        return excluded;
    }

    private static boolean isCandidateInterface(
            NetworkInterface networkInterface,
            Set<String> excludedInterfaces
    ) throws SocketException {
        String name = networkInterface.getName();
        return networkInterface.isUp()
                && !networkInterface.isLoopback()
                && name != null
                && !excludedInterfaces.contains(name)
                && !hasNonLanPrefix(name.toLowerCase(Locale.ROOT));
    }

    private static boolean hasNonLanPrefix(String name) {
        return name.startsWith("rmnet")
                || name.startsWith("ccmni")
                || name.startsWith("pdp")
                || name.startsWith("wwan")
                || name.startsWith("rev_rmnet")
                || name.startsWith("r_rmnet")
                || name.startsWith("v4-rmnet")
                || name.startsWith("clat")
                || name.startsWith("dummy")
                || name.startsWith("tun")
                || name.startsWith("tap");
    }

    private static boolean isReachableIpv4(InetAddress address) {
        return address instanceof Inet4Address
                && !address.isAnyLocalAddress()
                && !address.isLoopbackAddress()
                && !address.isLinkLocalAddress()
                && !address.isMulticastAddress();
    }
}
