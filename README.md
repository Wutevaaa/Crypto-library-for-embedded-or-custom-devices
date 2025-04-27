# Crypto-library for embedded or custom devices



## Getting started
```
cd existing_repo
git remote add origin https://gitlab.cs.pub.ro/etti/dcae-public/arh/research/beia/isolde/crypto-library-for-embedded-or-custom-devices.git
git branch -M main
git push -uf origin main
```

## Integrate with your tools

- [ ] [Set up project integrations](https://gitlab.cs.pub.ro/etti/dcae-public/arh/research/beia/isolde/crypto-library-for-embedded-or-custom-devices/-/settings/integrations)

***
## Name
Yet another cryptolibrary for embedded, custom devices and general-purpose computers.

## Description
Let people know what your project can do specifically. Provide context and add a link to any reference visitors might be unfamiliar with. A list of Features or a Background subsection can also be added here. If there are alternatives to your project, this is a good place to list differentiating factors.

## Usage
Use examples liberally, and show the expected output if you can. It's helpful to have inline the smallest example of usage that you can demonstrate, while providing links to more sophisticated examples if they are too long to reasonably include in the README.

## Authors and acknowledgment
## License
## Benchmarks (on ROG-Flow X13 with Ryzen 5900HS CPU):

AES-256 ECB NIST testing AES-tiny PASSED
AES-256 CTR NIST testing AES-tiny PASSED
AES-tiny CTR encryption throughput: 0.081547 GB/s
AES-tiny CTR decryption throughput: 0.082882 GB/s

AES-256 ECB NIST testing AES-small PASSED
AES-256 CTR NIST testing AES-small PASSED
AES-small CTR encryption throughput: 0.082837 GB/s
AES-small CTR decryption throughput: 0.08639 GB/s

AES-256 ECB NIST testing AES-NI PASSED
AES-256 CTR NIST testing AES-NI PASSED
AES-NI CTR encryption throughput: 1.47492 GB/s
AES-NI CTR decryption throughput: 1.74592 GB/s

AES-256 ECB NIST testing AES-NI-SSE PASSED
AES-256 CTR NIST testing AES-NI-SSE PASSED
AES-NI-SSE CTR encryption throughput: 0.958698 GB/s
AES-NI-SSE CTR decryption throughput: 1.04045 GB/s

AES-256 ECB NIST testing AES-NI-AVX2 PASSED
AES-256 CTR NIST testing AES-NI-AVX2 PASSED
AES-NI-AVX2 CTR encryption throughput: 0.966464 GB/s
AES-NI-AVX2 CTR decryption throughput: 1.04146 GB/s

AES-256 ECB NIST testing AES-NI-OMP PASSED
AES-256 CTR NIST testing AES-NI-OMP PASSED
AES-NI-OMP CTR encryption throughput: 10.5269 GB/s
AES-NI-OMP CTR decryption throughput: 6.42959 GB/s
