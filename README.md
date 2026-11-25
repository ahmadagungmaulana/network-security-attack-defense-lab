# Lab Network Attack — UTS Keamanan Jaringan (Pertemuan 1–7)

```

'##::: ##:'########:'########:::::'######::'########::'######::
 ###:: ##: ##.....::... ##..:::::'##... ##: ##.....::'##... ##:
 ####: ##: ##:::::::::: ##::::::: ##:::..:: ##::::::: ##:::..::
 ## ## ##: ######:::::: ##:::::::. ######:: ######::: ##:::::::
 ##. ####: ##...::::::: ##::::::::..... ##: ##...:::: ##:::::::
 ##:. ###: ##:::::::::: ##:::::::'##::: ##: ##::::::: ##::: ##:
 ##::. ##: ########:::: ##:::::::. ######:: ########:. ######::
..::::..::........:::::..:::::::::......:::........:::......:::

                  N E T W O R K   S E C U R I T Y
                  AHMAD AGUNG MAULANA
                  TIF24E CNS
```

Repo ini berisi bukti pengerjaan UTS Praktik Keamanan Jaringan: jawaban lengkap
**Kasus 8 (`k8`)**, screenshot setiap langkah, dan source lab Docker untuk mengulang
seluruh serangan. **Semua serangan hanya boleh dijalankan di lingkungan lab lokal.**
Jangan memindai atau menyerang host di luar lab.

## Isi repo

```
uts-network-lab/
├── README.md                              ← file ini (penjelasan umum)
├── jawaban.md                             ← jawaban UTS Kasus 8: hitungan kasus,
│                                            7 tugas, command, bukti, penjelasan
├── Sreenshoot/                            ← 20 screenshot bukti (tugas 1–7)
│   ├── Tugas 1/  (6 file)
│   ├── Tugas 2/  (2 file)
│   ├── Tugas 3/  (3 file)
│   ├── Tugas 4/  (kosong — capture tidak valid, lihat catatan)
│   ├── Tugas 5/  (2 file)
│   ├── Tugas 6/  (4 file)
│   └── Tugas 7/  (3 file)
├── b/                                     ← source compose per tugas
│   ├── b1-compose/docker-compose.yml      ← Tugas 1: jaringan internal (target + attacker)
│   ├── b3-syn-flood/docker-compose.yml    ← Tugas 6: SYN flood
│   └── b4-dns-exfil/docker-compose.yml    ← Tugas 7: DNS exfiltration
├── kasus-8/docker-compose.yml             ← compose kasus k8 (volume vol-k8 + target-k8)
├── kasus/                                 ← skrip bantu dari lembar praktikum
│   ├── k5-scapy/kirim_icmp.py             ← skrip ICMP dengan Scapy (Tugas 5)
│   └── k9-dns-detect/analisis_dns.py      ← skrip deteksi DNS exfiltration (Tugas 7)
├── images/                                ← Dockerfile tiga image lab
│   ├── uts-openssl/Dockerfile             ← image untuk Pertemuan 2 (OpenSSL)
│   ├── uts-kali-tools/Dockerfile          ← image untuk Pertemuan 3–7 (arpspoof,
│   │                                         hping3, tcpdump, scapy, aircrack-ng)
│   └── uts-dnsmasq/Dockerfile             ← image untuk Pertemuan 7 (resolver DNS lab)
└── artefak hasil Tugas 2 & 7:
    laporan-k8.txt, laporan-k8.enc, hasil-k8.txt,
    key-k8.pem, cert-k8.pem, dns-k8.log
```

Nama folder `kasus/k5-scapy` dan `kasus/k9-dns-detect` adalah **penanda modul** dari
lembar praktikum, bukan nomor kasus jawaban ini. Di `jawaban.md`, skrip detektor DNS
dicari otomatis dengan `Get-ChildItem` supaya tidak bergantung pada nama foldernya.

**Yang sengaja tidak ikut repo:**

- `handshake-k8.cap` dan `wordlist-k8.txt` — file contoh **disediakan penguji** dan
  masuk `.gitignore`, jadi hasil clone tidak bisa menjalankan Tugas 4 tanpa kedua
  file itu. Pada pengerjaan ini capture yang dipakai ternyata bukan 802.11 valid
  (`No networks found`), sehingga `Sreenshoot/Tugas 4` kosong dan transkrip
  `KEY FOUND` di `jawaban.md` ditandai jelas sebagai **simulasi**.
- `02-dokumen/` (lembar soal & rubrik) — berkas ujian, tidak dipublikasikan.

`key-k8.pem` yang ikut repo adalah kunci privat sertifikat **self-signed lab**, bukan
kredensial produksi; file ini hanya untuk membuktikan langkah Tugas 2.

## Urutan pemakaian

1. **Baca** `jawaban.md` — berisi kasus (NIM → jumlah digit → mod 10), urutan
   langkah, command siap pakai, screenshot bukti, dan penjelasan tiap tugas.
2. **Buka PowerShell** di folder repo (semua perintah di repo ini sintaks PowerShell,
   bukan bash):

   ```powershell
   cd C:\Keamananjaringan\uts-network-lab
   ```

3. **Siapkan image** dari `images/`. Semua lab memakai jaringan `internal: true`
   (tanpa akses internet), sehingga paket harus sudah ada di image sebelum lab
   dijalankan:

   ```powershell
   docker build -t uts-openssl images/uts-openssl
   docker build -t uts-kali-tools images/uts-kali-tools
   docker build -t uts-dnsmasq images/uts-dnsmasq
   docker pull alpine:3.20
   docker pull nginx:alpine
   ```

4. **Tentukan kasus** dari NIM: jumlahkan seluruh digit, ambil sisa bagi 10, dan
   sisa 0 berarti Kasus 10. Contoh NIM `19552011024`: jumlah digit 30, sisa 0, maka
   Kasus 10. (Jawaban di repo ini = **Kasus 8**, NIM `24552011350` → 28 → 8.)
5. **Kerjakan kasus** mengikuti lembar perintah per kasus yang diedarkan dosen.
   Setiap kasus mencakup tujuh tugas (Pertemuan 1 sampai 7) dengan bobot sama.
6. **Lampirkan** jawaban, output terminal, dan bukti setiap tugas dalam satu berkas
   `jawaban.md`, di awal ditulis jumlah digit NIM, sisa bagi, dan nomor kasus.

## Parameter kasus `k8`

| Item | Nilai |
|---|---|
| NIM | `24552011350` |
| Perhitungan | 2+4+5+5+2+0+1+1+3+5+0 = 28 → 28 mod 10 = **8** |
| Volume | `vol-k8` |
| File kerja | `laporan-k8.txt`, `laporan-k8.enc`, `hasil-k8.txt` |
| Kunci & sertifikat | `key-k8.pem`, `cert-k8.pem` (`CN=k8.uts.local`) |
| Kata sandi enkripsi | `kunci-k8-2026` |
| Domain | `k8.exfil.lab` / `k8.uts.local` |
| Container Tugas 3 & 5 | `korban-k8`, `gateway-k8`, `penyerang-k8` |
| Network Tugas 3 & 5 | `lab-arp-k8` |
| Project compose | `-p k8` |

## Hasil ringkas tiap tugas

| Tugas | Bukti utama |
|---|---|
| T1 — Docker & Volume | `vol-k8` tetap ada setelah `docker rm w-k8`; container baru membaca `24552011350`; attacker → target nginx sukses |
| T2 — Kriptografi | Dua hash SHA-256 identik (`e26ef77c…a4264f7`); sertifikat self-signed RSA 2048, Subject = Issuer = `CN=k8.uts.local` |
| T3 — ARP Spoofing | MAC gateway `8e:07:96:68:99:68` → `26:fe:12:7a:10:e4` saat diserang; pulih dengan `Flags 0x6` setelah static ARP |
| T4 — WPA2 | Capture bukan 802.11 valid → `No networks found`; analisis 4-way handshake + simulasi `KEY FOUND` (berlabel) |
| T5 — ICMP | Echo reply `TTL 64`, `type 0` dari `172.18.0.2` |
| T6 — SYN Flood | `SYN_RECV` 0 → **158**; tcpdump menangkap `[S] → [S.] → [.]` |
| T7 — DNS Exfiltration | NIM → hex `3234353532303131333530` (22 karakter) tercatat di log dnsmasq; detektor `exfil.lab: 1`, label tidak ditandai karena < 30 |

## Catatan di mesin ini (Windows PowerShell)

- Pakai **`docker compose`** (pakai spasi, bukan `docker-compose`). Project name
  dipatok `-p k8` supaya nama network/container tidak bertabrakan dengan lab lain.
- Path volume memakai **`"${PWD}:/work"`** — PowerShell meng-expand `${PWD}` menjadi
  path Windows yang bisa dibaca Docker Desktop dengan aman.
- Nama network `lab-arp-k8` mengandung tanda hubung, sehingga
  `{{.NetworkSettings.Networks.lab-arp-k8.IPAddress}}` gagal
  (`bad character U+002D '-'`). Pakai `{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}`
  lalu `.Trim()`.
- Di dalam `uts-kali-tools` tidak tersedia `ping`, `arp`, `ip`, dan `netstat`:
  trafik L2 dipicu lewat socket UDP `python3`, tabel ARP dibaca dari
  `/proc/net/arp`, static ARP disuntik lewat `ioctl(SIOCSARP)` di Python, dan
  `SYN_RECV` dihitung dengan `awk` pada `/proc/net/tcp` + `/proc/net/tcp6`.
- Encoding hex memakai `.NET` (`[System.Text.Encoding]::UTF8.GetBytes(...)`), decode
  memakai `UTF8.GetString`, dan query DNS dikirim sebagai paket UDP mentah lewat
  `python3` — tidak bergantung pada `xxd`/`dig`.
- Log dnsmasq disimpan dengan `--no-log-prefix` + `Set-Content -Encoding Ascii`
  supaya tidak ada BOM atau prefiks `dns-1 |`.
- **Tugas 3 jangan di-`down`** sebelum Tugas 5 selesai — T5 memakai `korban-k8` di
  network `lab-arp-k8` yang sama.
- **Screenshot dulu, baru `down -v`** — output hilang kalau container sudah dihapus.
- SYN flood hanya menumpuk `SYN_RECV` bila source di-spoof ke IP **satu subnet**
  (`--spoof 172.19.0.99`); tanpa spoof, kernel attacker langsung membalas `RST`.

## Pembersihan setelah selesai

```powershell
docker compose -p k8 -f b/b4-dns-exfil/docker-compose.yml down -v
docker compose -p k8 -f b/b3-syn-flood/docker-compose.yml down -v
docker rm -f korban-k8 gateway-k8 penyerang-k8
docker network rm lab-arp-k8
docker ps
```

Jalankan pembersihan di atas sebelum mematikan laptop, lalu **Quit Docker Desktop**
dari system tray agar tidak ada container atau network virtual yang tertinggal.
