// ABOUTME: This file maps TLS profile strings to bogdanfinn/tls-client profiles
// ABOUTME: It provides a clean abstraction for profile selection via CLI

package tlsprofile

import (
	"fmt"
	"strings"

	"github.com/bogdanfinn/tls-client/profiles"
)

var ProfileMap = map[string]profiles.ClientProfile{
	// Chrome profiles
	"chrome_103":        profiles.Chrome_103,
	"chrome_104":        profiles.Chrome_104,
	"chrome_105":        profiles.Chrome_105,
	"chrome_106":        profiles.Chrome_106,
	"chrome_107":        profiles.Chrome_107,
	"chrome_108":        profiles.Chrome_108,
	"chrome_109":        profiles.Chrome_109,
	"chrome_110":        profiles.Chrome_110,
	"chrome_111":        profiles.Chrome_111,
	"chrome_112":        profiles.Chrome_112,
	"chrome_117":        profiles.Chrome_117,
	"chrome_120":        profiles.Chrome_120,
	"chrome_124":        profiles.Chrome_124,
	"chrome_131":        profiles.Chrome_131,
	"chrome_133":        profiles.Chrome_133,
	// Firefox profiles
	"firefox_102":       profiles.Firefox_102,
	"firefox_104":       profiles.Firefox_104,
	"firefox_105":       profiles.Firefox_105,
	"firefox_106":       profiles.Firefox_106,
	"firefox_108":       profiles.Firefox_108,
	"firefox_110":       profiles.Firefox_110,
	"firefox_117":       profiles.Firefox_117,
	"firefox_120":       profiles.Firefox_120,
	"firefox_123":       profiles.Firefox_123,
	"firefox_132":       profiles.Firefox_132,
	"firefox_133":       profiles.Firefox_133,
	"firefox_135":       profiles.Firefox_135,
	// Safari profiles
	"safari_15_6_1":     profiles.Safari_15_6_1,
	"safari_16_0":       profiles.Safari_16_0,
	"safari_ipad_15_6":  profiles.Safari_Ipad_15_6,
	"safari_ios_15_5":   profiles.Safari_IOS_15_5,
	"safari_ios_15_6":   profiles.Safari_IOS_15_6,
	"safari_ios_16_0":   profiles.Safari_IOS_16_0,
	"safari_ios_17_0":   profiles.Safari_IOS_17_0,
	"safari_ios_18_0":   profiles.Safari_IOS_18_0,
	"safari_ios_18_5":   profiles.Safari_IOS_18_5,
	// Opera profiles
	"opera_89":          profiles.Opera_89,
	"opera_90":          profiles.Opera_90,
	"opera_91":          profiles.Opera_91,
	// Mobile app profiles
	"zalando_android":   profiles.ZalandoAndroidMobile,
	"zalando_ios":       profiles.ZalandoIosMobile,
	"nike_ios":          profiles.NikeIosMobile,
	"nike_android":      profiles.NikeAndroidMobile,
	"mms_ios":           profiles.MMSIos,
	"mesh_ios":          profiles.MeshIos,
	"mesh_ios2":         profiles.MeshIos2,
	"mesh_android":      profiles.MeshAndroid,
	"mesh_android2":     profiles.MeshAndroid2,
	"confirmed_ios":     profiles.ConfirmedIos,
	"confirmed_android": profiles.ConfirmedAndroid,
	// OkHttp profiles
	"okhttp_android_7":  profiles.Okhttp4Android7,
	"okhttp_android_8":  profiles.Okhttp4Android8,
	"okhttp_android_9":  profiles.Okhttp4Android9,
	"okhttp_android_10": profiles.Okhttp4Android10,
	"okhttp_android_11": profiles.Okhttp4Android11,
	"okhttp_android_12": profiles.Okhttp4Android12,
	"okhttp_android_13": profiles.Okhttp4Android13,
}

// GetProfile returns a ClientProfile by name, case-insensitive
func GetProfile(name string) (profiles.ClientProfile, error) {
	name = strings.ToLower(name)
	profile, exists := ProfileMap[name]
	if !exists {
		return profiles.DefaultClientProfile, fmt.Errorf("unknown TLS profile: %s", name)
	}
	return profile, nil
}

// ListProfiles returns all available profile names sorted alphabetically
func ListProfiles() []string {
	names := make([]string, 0, len(ProfileMap))
	for name := range ProfileMap {
		names = append(names, name)
	}
	return names
}
