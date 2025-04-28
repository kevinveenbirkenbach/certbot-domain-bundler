# 📦 Certbot Domain Bundler

**Certbot Domain Bundler** automates the creation of Let's Encrypt certificates for multiple domains using SANs (Subject Alternative Names).  
It intelligently groups domains and supports both DNS and webroot challenges.

---

## 🚀 Installation

You can install **Certbot Domain Bundler** easily using [Kevin's Package Manager (pkgmgr)](https://github.com/kevinveenbirkenbach/package-manager):

```bash
pkgmgr install certbundle
```

After installation, usage instructions are available via:

```bash
certbundle --help
```

---

## 🛠 Features

- Group multiple domains into a single SAN certificate
- Supports DNS-01 and HTTP-01 (webroot) ACME challenges
- Control DNS propagation wait time
- Wildcard domain support
- Test mode for Let's Encrypt staging environment
- Fully customizable via CLI parameters

---

## 📜 License

This project is licensed under the **MIT License**.

---

## 👤 Author

Developed by **Kevin Veen-Birkenbach**  
🌐 [https://www.veen.world](https://www.veen.world)
