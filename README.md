# Optical Lab Device Protocol

OLDP は Optical Lab Device Protocol の略である。Optical Lab Demo Protocol と読んでもかまわない。

OLDP は、[vca-hub](https://github.com/NrivYuki/vca-hub) に通信方式を加える拡張の用例として作った、デモ用の規格の一例である。

眼鏡レンズの加工機器(トレーサー・加工機など)とホストの間でジョブをやり取りするための通信規格で、マイコンで動く機器を前提とする。現在の版は第 1.0 版である。規格の本文は [docs/spec.md](docs/spec.md) にある。

このリポジトリには、規格だけを置く。実装は、ここにある定義とテストベクタを全て通すことで、規格どおりであることを示す。

## ファイル

| ファイル | 中身 |
|---|---|
| `docs/spec.md` | 規格の本文 |
| `spec/labels.json` | 項目の辞書(名前・型・左右の有無・単位・取れる値・ほかの項目との条件) |
| `spec/messages.json` | フレームの種類・操作の番号・フラグ・状態の番号・待ち時間 |
| `spec/vectors/protocol.json` | フレームとセッションのバイト列のテストベクタ。`tools/gen-vectors.py` が規格の本文から作る |
| `spec/vectors/records.json` | 項目の扱いのテストベクタ(手で定めたもの) |
| `spec/vectors/noise_xx_25519_chachapoly_sha256.json` | Noise XX の公開のテストベクタ(cacophony から写したもの) |
| `tools/gen-vectors.py` | `protocol.json` を作るプログラム。実装を使わず、Python の標準ライブラリと、プログラムの中に書いた小さな暗号の実装だけで組み立てる |
| `third_party/noise-vectors/` | Noise のテストベクタの元のファイル(cacophony) |

規格の正本は `spec/` の定義であり、本文は説明である。両者が食い違うときは、定義を正とする(規格の 1 章)。

## テストベクタの作り直し

```
python3 tools/gen-vectors.py
```

このプログラムは、テストベクタを作る前に、中の暗号の部品を RFC 7748・RFC 8439 の例と Noise の公開のテストベクタで確かめる。外部のパッケージは使わず、Python 3 だけで動く。

## 関連するリポジトリ

| リポジトリ | 中身 |
|---|---|
| [optical-lab-device-protocol-reference](https://github.com/NrivYuki/optical-lab-device-protocol-reference) | OLDP の参照実装。機器の側の C(H8/3069F の基板のファームウェアを含む)と、ホストの側の JavaScript。このリポジトリの `spec/` を写して取り込み、テストベクタを通す |
| [vca-hub-extension](https://github.com/NrivYuki/vca-hub-extension) | vca-hub の拡張。参照実装の JavaScript を使って、OLDP の機器を vca-hub につなぐ |
| [vca-hub](https://github.com/NrivYuki/vca-hub) | VCA(DCS)のデータを受け取り、保存し、中継する常駐プログラム。上の拡張を入れると、OLDP の機器とつながる |

## ライセンス

| 対象 | ライセンス |
|---|---|
| 規格の文書(`docs/`) | CC BY 4.0(`docs/LICENSE`) |
| 規格の定義とテストベクタ(`spec/`)、`tools/` | MIT(`LICENSE`) |
| `third_party/` と、そこから写した `spec/vectors/noise_xx_25519_chachapoly_sha256.json` | cacophony のテストベクタ: Unlicense |

`spec/` を MIT にしたのは、実装が項目の辞書やテストベクタをそのまま取り込めるようにするためである。
