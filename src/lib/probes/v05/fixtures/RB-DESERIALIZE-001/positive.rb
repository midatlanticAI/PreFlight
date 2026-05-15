# XL-001 / RB-DESERIALIZE-001 positive fixture.
# Marshal.load on untrusted bytes: arbitrary object instantiation.
def restore(blob)
  Marshal.load(blob)
end
