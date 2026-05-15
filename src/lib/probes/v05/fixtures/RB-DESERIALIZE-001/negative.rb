# XL-001 / RB-DESERIALIZE-001 negative fixture.
# YAML.safe_load with permitted classes; no Marshal.
def config
  YAML.safe_load(File.read("config.yml"), permitted_classes: [Symbol])
end
