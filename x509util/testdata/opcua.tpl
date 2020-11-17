{
      "subject": {{ toJson .Subject }},
      "sans": {{ toJson .SANs }},
      "basicConstraints": {
            "isCA": false
      },
      "keyUsage": ["digitalSignature", "keyEncipherment", "keyAgreement", "certSign"],
      "extKeyUsage": ["serverAuth", "clientAuth"]
}
