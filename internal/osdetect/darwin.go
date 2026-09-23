package osdetect

import (
	"bytes"
	"encoding/xml"
	"strings"
)

// systemVersionPlist is where macOS records its product version. It is read
// rather than obtained from sw_vers because reading a file cannot fail the way
// forking can on a system that is being audited precisely because something is
// wrong with it.
const systemVersionPlist = "/System/Library/CoreServices/SystemVersion.plist"

func detectDarwin(e env, info *Info) {
	if b, err := e.readFile(systemVersionPlist); err == nil {
		kv := parsePlistDict(b)
		if v := kv["ProductVersion"]; v != "" {
			info.Distro = kv["ProductName"]
			info.Version = v
			info.Pretty = strings.TrimSpace(kv["ProductName"] + " " + v)
			if build := kv["ProductBuildVersion"]; build != "" {
				info.Pretty += " (" + build + ")"
			}
			info.Source = systemVersionPlist
			return
		}
	}

	if out, err := e.run("sw_vers", "-productVersion"); err == nil && out != "" {
		info.Distro = "macos"
		info.Version = out
		info.Pretty = "macOS " + out
		info.Source = "sw_vers -productVersion"
	}
}

// parsePlistDict reads the flat <key>/<string> pairs of a property list. Only
// string values are of interest here, and a plist osfp cannot parse simply
// yields no keys, which sends detection to the sw_vers fallback.
func parsePlistDict(b []byte) map[string]string {
	dec := xml.NewDecoder(bytes.NewReader(b))
	dec.Strict = false
	kv := make(map[string]string)

	var elem, key string
	var value strings.Builder
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			elem = t.Name.Local
			value.Reset()
		case xml.CharData:
			// Character data can be delivered in several pieces, so it is
			// accumulated until the element ends.
			if elem == "key" || elem == "string" {
				value.Write(t)
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "key":
				key = strings.TrimSpace(value.String())
			case "string":
				if key != "" {
					kv[key] = strings.TrimSpace(value.String())
					key = ""
				}
			}
			elem = ""
			value.Reset()
		}
	}
	return kv
}
