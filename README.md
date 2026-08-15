# NN-Extensions

Burp Suite 用の拡張ローダーです。中身は独立して完成した**2つの拡張**をまとめて1回のロードで有効化するだけの薄いコンポジションルート（[nn_extensions.py](nn_extensions.py)）で、各拡張のロジック・UI・挙動には一切手を加えていません。ロードすると、Burpの **Extensions** 一覧には **NN-Extensions** という1エントリだけが表示され、その中に両方の拡張のSuiteタブ・右クリックメニューがこれまで通り追加されます。

詳しい使い方・仕組みは [docs/manual.html](docs/manual.html) を参照してください（ブラウザで開けます）。

## 同梱している拡張

| 拡張 | Suiteタブ | 概要 | 詳細 |
|---|---|---|---|
| **CSV List Input** | `CSV List Input` | Repeaterで送るリクエストの複数項目（URL/Cookie/ヘッダー/JSON・XML本文、入れ子構造も再帰的に展開）に、CSVで用意したテストデータを送信のたびに自動で差し込む。加えて Match & Replace・Decode・Target & Replace with Decode & Encode 機能も持つ | [burp-list-input/README.md](burp-list-input/README.md) / [burp-list-input/docs/manual.html](burp-list-input/docs/manual.html) |
| **SF Aura Helper** | `SF Helper` | Salesforce(Aura/Experience Cloud) 診断支援。HTTP historyへの採番、繰り返し通信のAura集約判別、CSVワードリスト照合、Aura診断（能動送信・要認可）を提供 | [burp-sf-aura/README.md](burp-sf-aura/README.md) / [burp-sf-aura/sf_aura_burp_helper_マニュアル.html](burp-sf-aura/sf_aura_burp_helper_マニュアル.html) |

各拡張は元々別々に配布されていたものをそのまま同梱しているため、機能や制限事項の詳細は上表右列の元ドキュメントを参照してください。このREADMEとdocs/manual.htmlは、あくまで「NN-Extensionsとして1つにロードする」ことについての説明に限定しています。

## 必要環境

- Burp Suite（Community / Professional）
- [jython-standalone.jar](https://www.jython.org/download)（バージョン 2.7.x を推奨。両拡張ともJython/Python 2向け）

## インストール

1. Burp Suiteの **Extender/Extensions > Options > Python Environment** で `jython-standalone.jar` を指定する
2. **Extender/Extensions > Extensions > Add** で Extension type を `Python` にし、このリポジトリ直下の [`nn_extensions.py`](nn_extensions.py) を選択する
   - `burp-list-input/` と `burp-sf-aura/` フォルダは `nn_extensions.py` と**同じ場所（このリポジトリのルート直下）に置いたまま**にしてください。`nn_extensions.py` はこの2フォルダを実行時にimportするため、単体では動作しません
3. 読み込みに成功すると、Extensions一覧に **NN-Extensions** という1エントリと **MyTools** タブが追加されます。SF Helperは既定で非表示です。

## SF Helperの表示切替

`nn_extensions.py` 上部の `ENABLE_SF_HELPER` は既定で `False` です。`True` に変更して拡張をReloadすると、従来の **SF Helper** タブとその右クリックメニューも読み込みます。`False` のままではSF Helperを読み込まないため、MyToolsのみが表示されます。

## リポジトリ構成

```
Burp-NN-Extensions/
├── nn_extensions.py          # Burpが直接ロードするエントリポイント（コンポジションルート）
├── README.md                 # このファイル
├── docs/manual.html          # NN-Extensionsとしての導入・仕組みの説明
├── burp-list-input/          # CSV List Input（独立した拡張。ロジック未変更）
│   ├── csv_list_input.py
│   ├── csvlistinput/
│   ├── docs/manual.html
│   └── README.md
└── burp-sf-aura/             # SF Aura Helper（独立した拡張。ロジック未変更）
    ├── sf_aura_burp_helper.py
    ├── sf_aura_burp_helper_マニュアル.html
    └── README.md
```

## 仕組み（要約）

`nn_extensions.py` はBurpの`IBurpExtender`を実装する薄いラッパーで、`registerExtenderCallbacks()` の中で `csv_list_input.py` と `sf_aura_burp_helper.py` を通常のPythonモジュールとしてimportし、それぞれの `BurpExtender` インスタンスを生成して同じ `callbacks` オブジェクトに対して `registerExtenderCallbacks()` を呼び出すだけです。両拡張は元のコードのまま、それぞれ独立してタブ追加・HTTPリスナー登録・コンテキストメニュー登録を行います。詳細は [docs/manual.html](docs/manual.html) を参照してください。

## 単体でのロードについて

各拡張は従来通り単体でロードすることも可能です（`burp-list-input/csv_list_input.py` または `burp-sf-aura/sf_aura_burp_helper.py` を直接選択）。その場合はExtensionsタブに個別の名前（`CSV List Input` / `SF Aura Helper`）で2エントリ表示されます。
