// XL-001 / GO-DESERIALIZE-001 negative fixture.
// Unmarshalling a constant literal config blob, not an untrusted body.
package config

func Defaults() Cfg {
	var cfg Cfg
	yaml.Unmarshal([]byte("retries: 3\n"), &cfg)
	return cfg
}
