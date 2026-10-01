# VeloraGames Backend v9 — Cloudflare Worker + D1

Firebase tidak dipakai. Backend ini menyediakan auth, marketplace, transaksi, group chat, delivery akun, dan withdrawal.

## Sekali setup
1. Buat akun Cloudflare.
2. Install Node.js/Termux di HP atau gunakan GitHub Actions.
3. `cd backend && npm install`
4. `npx wrangler login`
5. `npx wrangler d1 create velora`
6. Salin `database_id` hasil command ke `wrangler.toml`.
7. `npx wrangler d1 execute velora --remote --file=schema.sql`
8. `npx wrangler deploy`
9. Copy URL Worker, misalnya `https://velora-backend.namaakun.workers.dev`.
10. Masukkan URL itu ke `Api.kt` di APK.

D1 adalah database online; semua HP mengakses backend yang sama. Tidak ada Firebase dan tidak perlu payment gateway untuk flow pembayaran manual.

## Keamanan
Password akun login di-hash. Kredensial akun game pada contoh API dienkripsi sebelum disimpan. Untuk produksi, gunakan secret server dan jangan pernah mengirim API key OpenAI ke APK.
