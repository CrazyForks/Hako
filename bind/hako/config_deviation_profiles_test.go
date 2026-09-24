package hako

var registryProfiles = []struct {
	name                  string
	profile               runtimeProfile
	underNetworkExtension bool
}{
	{RuntimeProfileIOSPacketTunnel, runtimeProfileIOSPacketTunnel, true},
	{RuntimeProfileMacOSPacketTunnel, runtimeProfileMacOSPacketTunnel, true},
	{RuntimeProfileTVOSPacketTunnel, runtimeProfileTVOSPacketTunnel, true},
	{RuntimeProfileMacOSApplication, runtimeProfileMacOSApplication, false},
}
